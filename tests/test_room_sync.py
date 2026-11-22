"""Rooms without a game: a host and a guest with the same hand-made ROM project (rows only), so what travels between
them is checked on every computer, CI too (the demo ROM's room tests need gcc-2.7.2-kmc and ld.lld)."""

import json
import time

import httpx
import pytest
from starlette.testclient import TestClient

from decompnet.app import collab
from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError, model_of

FUNCTIONS = [("func_80000400", 0x80000400, 16), ("func_80000410", 0x80000410, 32), ("func_80000430", 0x80000430, 8)]


def _project(net: RomNetwork, root) -> str:
    cfg = {"kind": "rom", "rom": {"sha1": "same"}, "compiler": {"toolchain": "gcc-2.7.2-kmc", "flags": ["-O2"]}}
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                         ("game", "Game", "", "mips", 1, str(root), json.dumps(cfg))).lastrowid
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at) "
                   "VALUES(?,?,?,?,?,?)", (pid, 1, "typedef int s32;\n", None, "import", time.time()))
        for name, vram, size in FUNCTIONS:
            db.execute("INSERT INTO functions(project_id,name,vram,size,n_insns,status,unit) VALUES(?,?,?,?,?,?,?)",
                       (pid, name, vram, size, size // 4, "open", "a"))
    return "game"


@pytest.fixture
def pair(tmp_path):
    host = RomNetwork(tmp_path / "h.db", tmp_path / "h")
    slug = _project(host, tmp_path / "h")
    room = collab.Room(host, slug)
    host.rooms[slug] = room
    client = TestClient(collab.host_app(host, host.rooms), base_url="http://192.168.1.20:6481",
                        headers={collab.VERSION_HEADER: collab.__version__})
    guest = RomNetwork(tmp_path / "g.db", tmp_path / "g")
    gslug = _project(guest, tmp_path / "g")
    token, member = room.join("rio", "same")
    guest.link_project(gslug, {"url": "http://192.168.1.20:6481", "room": slug, "token": token, "member": member},
                       client=client, start=False)
    link = guest.links[gslug]
    link.sync()
    return host, slug, guest, gslug, link, client


def _set(net, fn_name, **cols):
    with net.store.tx() as db:
        db.execute(f"UPDATE functions SET {', '.join(f'{k}=?' for k in cols)} WHERE name=?", (*cols.values(), fn_name))


def _fn(net, name):
    return net.store.one("SELECT * FROM functions WHERE name=?", name)


def test_matches_follow_the_hosts_set_whatever_the_feed_said(pair):
    """A guest followed the host's feed of events: a match it missed (a page it skipped, renamed before it caught
    up), one the host opened again, or its C tidied afterwards never reached it, and its count drifted from the
    host's (91.8% against 98.9%). Now the host sends its set of matches whenever the guest's differs."""
    host, slug, guest, gslug, link, _ = pair
    _set(host, "func_80000400", status="matched", matched_source="int a(void) { return 1; }")
    link.sync()
    mine = _fn(guest, "func_80000400")
    assert mine["status"] == "matched" and "return 1" in mine["matched_source"]
    # tidied on the host: the guest's C follows
    _set(host, "func_80000400", matched_source="/* one */\nint a(void) { return 1; }")
    link.sync()
    assert "/* one */" in _fn(guest, "func_80000400")["matched_source"]
    # opened again on the host: open here too, its C kept as the best attempt
    _set(host, "func_80000400", status="open", matched_source=None)
    link.sync()
    mine = _fn(guest, "func_80000400")
    assert mine["status"] == "open" and mine["matched_source"] is None and "/* one */" in mine["best_source"]
    # a match this copy has and the host doesn't (never confirmed there) opens again
    _set(guest, "func_80000410", status="matched", matched_source="int b(void) { return 2; }")
    link.sync()
    assert _fn(guest, "func_80000410")["status"] == "open"
    # nothing differs: the host sends no list
    assert "matched_set" not in link._req("GET", "/collab/state", link.cursor | {
        "m": collab._digest(collab.matched_items(guest.store, guest.project_row(gslug)["id"]))})


def test_notes_and_names_reach_a_guest_after_its_first_sync(pair):
    """Notes travelled only with a guest's first state; the host's layout as events the guest might miss."""
    host, slug, guest, gslug, link, _ = pair
    agent, _ = host.local_agent("codex-1")
    host.add_note(agent, slug, "returns the entity's hit points", "func_80000410")
    assert host.rename_symbol(agent, slug, "func_80000430", "get_hp").startswith("✅")
    link.sync()
    assert any("hit points" in n["text"] for n in guest.store.all("SELECT text FROM notes"))
    assert _fn(guest, "get_hp") is not None and _fn(guest, "func_80000430") is None
    assert link.cursor["n"] and link.cursor["l"]
    link.sync()  # (nothing new: neither comes again)
    assert len(guest.store.all("SELECT text FROM notes WHERE text LIKE '%hit points%'")) == 1


def test_a_hosts_failure_is_not_a_refusal(pair):
    """A tunnel's 502, the host's own 500, "slow down" or one side updated first covered the project with "You're not
    in this room" and dropped the saved work being sent. Only the host's own no is a refusal."""
    *_, link, _ = pair
    def answer(status, body=None):
        link.client = httpx.Client(transport=httpx.MockTransport(
            lambda _r: httpx.Response(status, json=body) if body is not None else httpx.Response(status, text="<html>")))
    for status, body in [(502, None), (500, {"error": "boom"}), (400, {"error": "slow down"}),
                         (400, {"error": f"{collab.SAME_VERSION}. Update"})]:
        answer(status, body)
        with pytest.raises(NetworkError) as e:
            link._req("GET", "/collab/state", {})
        assert not isinstance(e.value, collab.Refused), (status, body)
    answer(400, {"error": collab.NOT_MEMBER})
    with pytest.raises(collab.Refused) as e:
        link._req("GET", "/collab/state", {})
    assert e.value.room_wide
    answer(400, {"error": "func_80000400 is claimed by bo.claude-1"})
    with pytest.raises(collab.Refused) as e:
        link._req("GET", "/collab/state", {})
    assert not e.value.room_wide


def test_bad_requests_are_refused_not_500s(pair):
    host, slug, guest, gslug, link, client = pair
    auth = {"authorization": f"Bearer {link.token}"}
    r = client.get(f"/collab/state?room={slug}&e=many", headers=auth)
    assert r.status_code == 400 and "isn't a number" in r.json()["error"]
    r = client.post(f"/collab/matched?room={slug}", headers=auth, json={"names": "func_80000400"})
    assert r.status_code == 400
    r = client.post(f"/collab/matched?room={slug}", headers=auth | {"content-type": "application/json"},
                    content=b'{"names": ["' + b"x" * (collab.MAX_BODY + 1) + b'"]}')
    assert r.status_code in (400, 413)


def test_a_match_the_host_cant_take_now_waits_and_survives_a_restart(pair):
    """A guest's match while the host was away for a moment stayed on the guest alone: the room's function stayed
    open, and another member's agent did it again."""
    host, slug, guest, gslug, link, _ = pair
    link.keep_for_later("func_80000410", "int b(void) { return 2; }")
    rows = guest.store.all("SELECT name, kind, source FROM saved_progress")
    assert [(r["name"], r["kind"]) for r in rows] == [("func_80000410", "match")]
    # the room at a new address: the queue goes with it
    info = json.loads(guest.project_row(gslug)["config"])["link"]
    guest.link_project(gslug, info | {"url": "http://192.168.1.21:6481"}, client=link.client, start=False, moved=True)
    assert guest.store.one("SELECT url FROM saved_progress")["url"] == "http://192.168.1.21:6481"


def test_removing_a_linked_project_stops_its_link(pair):
    host, slug, guest, gslug, link, _ = pair
    guest.remove_project(gslug)
    assert gslug not in guest.links and link._stop.is_set()
    host.remove_project(slug)
    assert slug not in host.rooms


def test_follow_says_when_this_copy_follows_later(pair):
    *_, link, _ = pair
    assert link.follow() == ""
    link.client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(502, text="<html>")))
    assert "next sync" in link.follow()


def test_one_model_in_a_room_is_one_model():
    """A member's claude-sonnet-5-5-1 is alex.claude-sonnet-5-5-1 on the host: as another model than the host's own
    agents, two of one model set a function aside as no C makes it (NOT_C_MODELS)."""
    assert model_of("alex.claude-sonnet-5-5-1") == model_of("claude-sonnet-5-5-2") == "claude-sonnet-5-5"
    assert model_of("bo.opencode-minimax-m3.1-flash-free-1") == model_of("opencode-minimax-m3.1-flash-free--1")
    assert collab.member_label("opencode-minimax-m3.1-flash-free-1") == "opencode-minimax-m3.1-flash-free-1"


def test_a_guest_whose_following_fails_says_so():
    link = collab.Link.__new__(collab.Link)
    link.refused, link.error, link.last_ok, link.last_contact = False, "git reset failed", time.time(), time.time()
    link.synced, link.behind, link.received, link.members = True, 0, 0, []
    assert link.status()["state"] == "stuck"


def test_work_that_takes_longer_than_a_request_is_answered_when_it_ends(pair, monkeypatch, caplog):
    """A GameCube room's member: every make_readable and edit_file said "the room's host isn't reachable right now".
    The host rebuilt and checked each file behind 20 agents' turns on its lock, past the member's 60 seconds and a
    tunnel's 100, and did it anyway; the agents tried again until they gave up. The host answers within
    ANSWER_WITHIN now, and the member asks after the rest."""
    host, slug, guest, gslug, link, client = pair
    monkeypatch.setattr(collab, "ANSWER_WITHIN", 0.2)
    slow = host.add_note

    def add_note(*args):
        time.sleep(1)
        return slow(*args)

    monkeypatch.setattr(host, "add_note", add_note)
    agent, _ = guest.local_agent("claude-1")
    seen = []
    send = link.client.send

    def watch(request, *args, **kwargs):
        r = send(request, *args, **kwargs)
        seen.append((request.url.path, r.status_code))
        return r

    caplog.set_level("INFO", logger=collab.logger.name)
    with client:  # (one event loop for the requests: the job goes on between them, as on the host's server)
        monkeypatch.setattr(link.client, "send", watch)
        said = guest.add_note(agent, gslug, "loops over the entity list", "func_80000410")
    assert said, said
    assert "/collab/note took over" in caplog.text and "/collab/note ended after" in caplog.text
    assert ("/collab/note", 202) in seen and ("/collab/job", 200) in seen
    assert host.store.one("SELECT 1 FROM notes WHERE text='loops over the entity list'")
    r = client.get(f"/collab/job?room={slug}&id=nope", headers={"authorization": f"Bearer {link.token}"})
    assert r.status_code == 400 and "no such job" in r.json()["error"]
