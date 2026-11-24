"""Room presence continues while receiving work is slow, without requiring a game or compiler."""

import json
import subprocess
import threading
import time
from types import SimpleNamespace

import httpx
import pytest

from decompnet.app import collab
from decompnet.network import NetworkError


@pytest.fixture
def connection(monkeypatch):
    monkeypatch.setattr(collab, "HEARTBEAT_EVERY", 0.01)
    clients, links = [], []

    def make(handler, fork=False):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        clients.append(client)
        net = SimpleNamespace(project_row=lambda _: {"config": "{}"}, fork_slug=lambda _: fork)
        link = collab.Link(net, "connection-test", "https://host.example", "room", "secret", "guest", client)
        links.append(link)
        return link

    yield make
    for link in links:
        link.stop()
    for thread in threading.enumerate():
        if thread.name in ("link-connection-test", "room-heartbeat-connection-test"):
            thread.join(timeout=2)
            assert not thread.is_alive()
    for client in clients:
        client.close()


@pytest.mark.parametrize("fork", [False, True])
def test_presence_continues_during_slow_sync(connection, fork):
    applying, release, alive = threading.Event(), threading.Event(), threading.Event()
    requests = []

    def host(request):
        assert request.url.path == "/collab/whoami"
        assert request.url.params["room"] == "room"
        assert request.headers["authorization"] == "Bearer secret"
        assert request.extensions["timeout"]["read"] == collab.HEARTBEAT_TIMEOUT
        requests.append(1)
        if applying.is_set() and len(requests) > 1:
            alive.set()
        return httpx.Response(200, json={"name": "guest", "room": "room"})

    link = connection(host, fork)
    link.last_ok = time.time() - 60
    link.synced = True

    def slow_sync():
        applying.set()
        release.wait(2)

    link.sync = slow_sync
    try:
        link.run()
        assert applying.wait(1)
        assert alive.wait(1)  # the heartbeat reaches the host while sync is still blocked
        assert link.status()["state"] == "connected"
        link.refused, link.error = True, collab.WAITING
        assert link.status()["state"] == "waiting"
        assert link.error == collab.WAITING
        link.refused, link.synced, link.error = False, False, ""
        assert link.status()["state"] == "syncing"  # a heartbeat doesn't mean the work has arrived
        link.error = "git reset failed: unable to unlink old 'src/a.c'"
        assert link.status()["state"] == "stuck"  # the host answers, but following it fails here: not "In a room"
    finally:
        link.stop()
        release.set()


def test_sync_retries_and_logs_recovery(connection, caplog):
    recovered = threading.Event()
    link = connection(lambda _: httpx.Response(200, json={}))
    calls = []

    def sync():
        calls.append(1)
        if len(calls) < 3:
            raise NetworkError("can't reach the host (ReadTimeout)")
        link.stop()
        recovered.set()

    link.sync = sync
    with caplog.at_level("INFO", logger="decompdecomp"):
        link.run(every=0.01)
        assert recovered.wait(1)
        for thread in threading.enumerate():
            if thread.name == "link-connection-test":
                thread.join(timeout=1)
    # Repeated failures don't bury useful diagnostics in a line every two seconds.
    assert sum("sync failed" in r.message for r in caplog.records) == 1
    assert any("sync recovered" in r.message for r in caplog.records)
    assert "secret" not in caplog.text


def test_failed_heartbeat_does_not_keep_room_online(connection, caplog):
    failed = threading.Event()

    def host(request):
        failed.set()
        raise httpx.ConnectError("unreachable", request=request)

    link = connection(host)
    link.last_ok = time.time() - 60
    link.error = "local sync error"
    link.sync = lambda: None
    with caplog.at_level("WARNING", logger="decompdecomp"):
        link.run()
        assert failed.wait(1)
        link.stop()
    assert link.status()["state"] == "offline"
    assert link.last_contact == 0
    assert link.error == "local sync error"


def test_join_shares_only_stronger_saved_rom_progress():
    class RoomLink:
        cursor = {}

        def __init__(self):
            self.attempts = []
            self.reports = []
            self.synced = False

        def _req(self, method, route, params):
            assert method == "GET" and route == "/collab/state" and params["fresh"] == 1
            assert params["m"] == "" and params["l"] == "" and params["a"] == 0  # (all of it, whatever this copy has)
            return {
                "matched_set": {"digest": "d", "items": [["already_matched", "0123456789abcdef"]]},
                "layout": {"digest": "l", "symbols": [], "functions": [
                    {"vram": 0x1000, "size": 4, "name": "already_matched"},
                    {"vram": 0x2000, "size": 4, "name": "saved_match"},
                    {"vram": 0x3000, "size": 4, "name": "better_attempt"},
                    {"vram": 0x4000, "size": 4, "name": "worse_attempt"},
                ]},
                "best": [{"name": "worse_attempt", "score": 3, "source": "host's"}],
            }

        def attempt(self, agent, function, source):
            self.attempts.append((function, source))
            return {"matched": True}

        def call(self, route, agent, **data):
            self.reports.append((route, data))

        def sync(self):
            self.synced = True

    class Net:
        def local_agent(self, name):
            assert name == "saved-progress"
            return SimpleNamespace(name=name), None

    candidates = [
        {"name": "already_matched", "vram": 0x1000, "size": 4, "status": "matched",
         "matched_source": "already"},
        {"name": "saved_match", "vram": 0x2000, "size": 4, "status": "matched",
         "matched_source": "match"},
        {"name": "better_attempt", "vram": 0x3000, "size": 4, "status": "open",
         "best_score": 2, "best_source": "better"},
        {"name": "worse_attempt", "vram": 0x4000, "size": 4, "status": "open",
         "best_score": 4, "best_source": "worse"},
    ]
    room = RoomLink()
    log = []

    collab._share_saved_progress(Net(), "project", room, candidates, fork=False,
                                 best_comparable=True, log=log.append)

    assert room.attempts == [("saved_match", "match")]
    assert room.reports == [("/collab/best", {"function": "better_attempt", "source": "better", "score": 2})]
    assert room.synced
    assert any("host confirmed 1 saved match" in message for message in log)


def test_a_rom_guest_can_wait_for_approval_after_joining(monkeypatch):
    hello = {"kind": "rom", "room": "game", "sha1": "same", "title": "Game", "game_code": "ABCD",
             "region": "USA", "functions": 1, "matched": 0,
             "compiler": {"toolchain": "gcc", "flags": ""}}
    monkeypatch.setattr(collab, "_hello", lambda *args: ("https://host.example", "invite", hello))
    monkeypatch.setattr("decompnet.consoles.identify", lambda _: SimpleNamespace(
        read_game=lambda *_: SimpleNamespace(info={"sha1": "same"})))
    monkeypatch.setattr(collab, "_saved_progress", lambda *args, **kwargs: [])
    requests = []

    def host(request):
        requests.append(request.url.path)
        if request.url.path == "/collab/join":
            return httpx.Response(200, json={"token": "secret", "name": "guest", "waiting": True})
        return httpx.Response(400)

    class Net:
        store = SimpleNamespace(all=lambda *_: [])

        def import_rom(self, *args, **kwargs):
            return "game"

        def project_row(self, slug):
            assert slug == "game"
            return {"config": json.dumps({"compiler": hello["compiler"]})}

        def link_project(self, *args, **kwargs):
            return SimpleNamespace(run=lambda: None)

    with httpx.Client(transport=httpx.MockTransport(host)) as client:
        slug = collab.join_room(Net(), "https://host.example/join/invite", "guest", b"rom",
                                log=lambda *_: None, client=client, start=False)

    assert slug == "game"
    assert requests == ["/collab/join"]


def test_heartbeat_recovers_without_rejoining(connection, caplog):
    recovered = threading.Event()
    requests = []

    def host(request):
        requests.append(request.url.path)
        if len(requests) == 1:
            raise httpx.ReadTimeout("slow host", request=request)
        if len(requests) == 3:
            recovered.set()  # the previous heartbeat has already updated last_contact and logged recovery
        return httpx.Response(200, json={"name": "guest", "room": "room"})

    link = connection(host)
    link.synced = True
    link.last_ok = time.time() - 60
    link.sync = lambda: None
    with caplog.at_level("INFO", logger="decompdecomp"):
        link.run()
        assert recovered.wait(1)
        link.stop()
    assert link.status()["state"] == "connected"
    assert set(requests) == {"/collab/whoami"}
    assert any("heartbeat recovered" in r.message for r in caplog.records)


@pytest.mark.parametrize("status", [400, 502])
def test_rejected_heartbeat_does_not_count_as_contact(connection, status):
    answered = threading.Event()

    def host(request):
        answered.set()
        return httpx.Response(status, json={"error": "not available"})

    link = connection(host)
    link.last_ok = time.time() - 60
    link.sync = lambda: None
    link.run()
    assert answered.wait(1)
    link.stop()
    assert link.last_contact == 0
    assert link.status()["state"] == "offline"


@pytest.mark.parametrize("fork", [False, True])
def test_a_guest_with_nothing_to_claim_says_what_the_host_says(connection, fork, monkeypatch):
    """The host says why nothing is left (Network.nothing_to_claim); a ROM room's and a project room's guest pass it
    on, and an older host that doesn't say still gets the bare "nothing left"."""
    from decompnet.app.engine import judging
    from decompnet.app.forkengine import ForkEngine

    why = {"why": "1 you said no C makes: f. Stop working on this project."}
    link = connection(lambda request: httpx.Response(200, json={"function": None, "vram": None, **why}), fork)
    agent = SimpleNamespace(name="claude-1")
    assert link.claim(agent, None, "easiest") == (None, why["why"])
    if fork:
        engine = ForkEngine.__new__(ForkEngine)
        engine.net = SimpleNamespace(selection=lambda slug, name: {})
        said = engine._claim_in_room(link, agent, "game", None, "easiest")
    else:
        net = SimpleNamespace(fork_slug=lambda _: None, _link=lambda _: link, selection=lambda slug, name: {},
                              _project=lambda slug: {"slug": slug})
        said = judging.JudgeMixin.claim(net, agent, "game", None, "easiest")
    assert said == why["why"]
    why = {}  # (an older host)
    assert link.claim(agent, None, "easiest") == (None, "")



def test_a_guest_gets_the_data_job_the_host_hands_out(connection):
    """The host hands a room member's agent a file's data to finish (/collab/claim's "job"): its brief is what the
    agent hears, as the host's own agents do. A GameCube room's guests found "nothing left" while files waited."""
    from decompnet.app.forkengine import ForkEngine

    job = "DATA JOB (claimed): src/input.c\n\nEvery function in src/input.c matches."
    link = connection(lambda request: httpx.Response(200, json={"function": None, "vram": None, "job": job}), True)
    agent = SimpleNamespace(name="claude-1")
    engine = ForkEngine.__new__(ForkEngine)
    engine.net = SimpleNamespace(selection=lambda slug, name: {})
    assert engine._claim_in_room(link, agent, "game", None, "finish") == job

def test_the_host_answers_a_heartbeat_while_its_threads_are_busy():
    """A GameCube room went "waiting for the host" whenever its guest's polishing helpers ran, and came back when they
    stopped: their requests and the host's own helpers' tool calls, all waiting for the project's rebuild, held every
    one of the host's shared threads, so the guest's heartbeat (whoami) found none within its 10 seconds."""
    import anyio
    from starlette.testclient import TestClient

    gate = threading.Event()

    class Busy:
        slug = "room"

        def member(self, request, counted=True):
            return SimpleNamespace(name="alex")

        def state(self, *args):  # a request that waits for the host's rebuild
            gate.wait(30)
            return {}

    with TestClient(collab.host_app(SimpleNamespace(), {"room": Busy()}), base_url="https://host.example") as client:
        waiting = [threading.Thread(target=client.get, args=("/collab/state?room=room",)) for _ in range(60)]
        try:
            for _ in range(60):  # the host's own helpers' tool calls, on the shared threads
                client.portal.start_task_soon(anyio.to_thread.run_sync, gate.wait, 30)
            for t in waiting:  # and the guest's helpers' requests
                t.start()
            time.sleep(0.5)
            answered = []
            beat = threading.Thread(target=lambda: answered.append(client.get("/collab/whoami?room=room")))
            beat.start()
            beat.join(collab.HEARTBEAT_TIMEOUT)
            assert answered and answered[0].json()["name"] == "alex" and answered[0].json()["room"] == "room"
        finally:
            gate.set()
            for t in waiting:
                t.join(timeout=30)


def test_a_busy_member_is_told_to_slow_down_but_still_sees_the_host():
    """A member over the room's 900 requests a minute is told "slow down"; their heartbeat isn't, or the host would
    look gone to them while it was only refusing their helpers' flood."""
    from collections import defaultdict, deque

    room = collab.Room.__new__(collab.Room)
    room.slug, room._hits, room.versions = "o", defaultdict(lambda: deque(maxlen=900)), {}
    room.net = SimpleNamespace(authenticate=lambda token: SimpleNamespace(id=1, name="alex"),
                               store=SimpleNamespace(one=lambda *a: {"origin": "collab:o", "owner": None}))
    request = SimpleNamespace(headers={collab.VERSION_HEADER: collab.__version__,
                                       collab.COMMIT_HEADER: collab.own_commit() or "", "authorization": "Bearer t"})
    for _ in range(899):
        room.member(request)
    with pytest.raises(NetworkError, match="slow down"):
        room.member(request)
    assert room.member(request, counted=False).name == "alex"


def test_a_file_held_open_while_following_the_host_keeps_the_members_work(tmp_path, monkeypatch):
    """A Windows member's "git stash failed: unable to unlink old 'src/...c': Device or resource busy": the stash had
    reset the other files already, their work only in a stash entry the next try never popped. Now the work is
    saved without touching the files, and a reset that stops part way puts it back for the next try."""
    from decompnet.app import forkroom

    def _git(root, *args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True).stdout.strip()

    host, member = tmp_path / "host", tmp_path / "member"
    host.mkdir()
    _git(host, "init", "-q", "-b", "main")
    for name in ("a.c", "b.c", "c.c"):
        (host / name).write_text(f"int {name[0]};\n")
    _git(host, "add", ".")
    _git(host, "-c", "user.name=h", "-c", "user.email=h@example.com", "commit", "-q", "-m", "start")
    subprocess.run(["git", "clone", "-q", str(host), str(member)], check=True)
    (host / "c.c").write_text("int c = 1;\n")  # the host's next commit
    _git(host, "-c", "user.name=h", "-c", "user.email=h@example.com", "commit", "-q", "-am", "host's")
    (member / "a.c").write_text("int a = 2; /* an agent's attempt */\n")
    (member / "b.c").write_text("int b = 3; /* another's, in a file held open */\n")
    before = _git(member, "rev-parse", "HEAD")

    real = forkroom._git

    def held(root, *args, **kwargs):
        if args[:2] == ("reset", "-q"):  # git resets a.c, then can't remove b.c
            real(root, "checkout", "HEAD", "--", "a.c")
            raise NetworkError("git reset failed: error: unable to unlink old 'b.c': Device or resource busy")
        return real(root, *args, **kwargs)
    monkeypatch.setattr(forkroom, "_git", held)
    data = forkroom.bundle(host)
    with pytest.raises(NetworkError, match="unable to unlink"):
        forkroom.pull(member, data, "main")
    assert (member / "a.c").read_text() == "int a = 2; /* an agent's attempt */\n"  # put back
    assert _git(member, "rev-parse", "HEAD") == before and not _git(member, "stash", "list")
    monkeypatch.setattr(forkroom, "_git", real)  # the file let go: the next try follows the host, work kept
    tip = forkroom.pull(member, data, "main")
    assert tip == _git(host, "rev-parse", "HEAD") and (member / "c.c").read_text() == "int c = 1;\n"
    assert "agent's attempt" in (member / "a.c").read_text() and "held open" in (member / "b.c").read_text()
    assert not _git(member, "stash", "list")
