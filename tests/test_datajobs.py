"""A file whose functions all match, handed out for its data (app/datajobs.py): a GameCube game's twelve such files sat
unlinked, since agents only ever claimed functions."""

import os
import time
from types import SimpleNamespace

import pytest

from decompnet.app import datajobs
from decompnet.app.datajobs import DataJobs
from decompnet.forks import linkcheck
from decompnet.forks.datadiff import Item, Section
from decompnet.network import Network, NetworkError
from decompnet.store import Store

LEFT = {"main/a": 32, "main/b": 495, "main/c": 64, "main/big": datajobs.MOST_BYTES + 1, "main/done": 0, "main/open": 8}


class Net:
    def __init__(self, store):
        self.store, self.links, self.selections = store, {}, {}

    def selection(self, slug, name):
        return self.selections.get(name, {})

    def _project(self, slug):
        return self.store.one("SELECT * FROM projects WHERE slug=?", slug)

    _own_release_cutoff = Network._own_release_cutoff

    def _event(self, db, project_id, agent_id, kind, detail):
        db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                   (project_id, agent_id, kind, detail, time.time()))


@pytest.fixture
def jobs(tmp_path, monkeypatch):
    store = Store(tmp_path / "db.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(id, slug, root, config) VALUES(1, 'game', ?, '{}')", (str(tmp_path),))
        for unit, status in [("main/a", "matched"), ("main/b", "matched"), ("main/b", "matched"), ("main/c", "matched"),
                             ("main/big", "matched"), ("main/done", "matched"), ("main/open", "matched"),
                             ("main/open", "open"), ("main/linked", "matched"), ("main/aside", "matched"),
                             ("main/aside", "asm")]:
            db.execute("INSERT INTO functions(project_id, name, unit, status) VALUES(1, ?, ?, ?)",
                       (f"f{db.execute('SELECT COUNT(*) FROM functions').fetchone()[0]}", unit, status))
        for i, name in enumerate(["agent-1", "agent-2", "agent-3"], 1):
            db.execute("INSERT INTO agents(id, name, token_hash) VALUES(?, ?, ?)", (i, name, name))
    units = [SimpleNamespace(name=n, source=f"src/{n[5:]}.c", target=None, base=None)
             for n in ["main/a", "main/b", "main/c", "main/big", "main/done", "main/open", "main/linked",
                       "main/aside"]]
    states = {u.source: ("Matching" if u.name == "main/linked" else "NonMatching",) for u in units}
    fp = SimpleNamespace(root=tmp_path, linkable=lambda: True, link_states=lambda: states, units=lambda: units,
                         units_for=lambda s: [u for u in units if u.source == s])
    net, cfg = Net(store), {}
    forks = SimpleNamespace(net=net, get=lambda slug: (net._project(slug), fp, cfg),
                            link_failures=lambda root, cfg: cfg.get("link_failed") or {},
                            link_causes=lambda fp, source: linkcheck.Causes())
    monkeypatch.setattr(DataJobs, "_bytes_left", lambda self, u, alike=True: LEFT.get(u.name, 0))
    return DataJobs(forks)


def agent(n):
    return SimpleNamespace(id=n, name=f"agent-{n}")


def test_the_files_whose_functions_all_match_and_whose_data_is_short_least_left_first(jobs):
    """Not a file with a function still open, one already linked, one whose data matches, or one too big to write."""
    assert jobs.todo("game") == [("src/a.c", 32), ("src/c.c", 64), ("src/b.c", 495)]
    assert jobs.left("game") == 3


def test_every_file_not_linked_says_what_it_waits_for(jobs):
    """One verdict the jobs, the helpers' stop and the files' page all read: a GameCube game's helpers said "nothing
    left to decompile here 🎉" with 49 of its 80 files unlinked, none of them a job."""
    jobs.forks.get("game")[2]["link_failed"] = {"src/c.c": f"{datajobs.NOT_GIVEN}, so it wasn't linked: x"}
    v = jobs.verdicts("game")
    assert v["src/a.c"] == ("job", 32, "")
    assert v["src/done.c"] == ("link", 0, "")
    assert v["src/aside.c"][0] == "set_aside" and "1 of its functions is set aside" in v["src/aside.c"][2]
    assert v["src/big.c"][0] == "too_big"
    assert v["src/c.c"][0] == "no_data"  # (the data step's failure: no edit of the C fixes it, so no job)
    assert "src/open.c" not in v and "src/linked.c" not in v
    assert jobs.todo("game") == [("src/a.c", 32), ("src/b.c", 495)]
    assert sorted(jobs.blocked("game")) == ["no_data", "set_aside", "too_big"]


def test_tries_are_agents_since_the_split_config_changed(jobs, tmp_path):
    """Counted by claim, a GameCube game's files ran out of tries on leases that ran out and on restarts."""
    for _ in range(datajobs.TRIES + 1):  # (the same agent claiming again after a restart: one try)
        jobs._held.clear()
        jobs.claim(agent(1), "game")
    assert jobs.verdicts("game")["src/a.c"][0] == "job"
    with jobs.forks.net.store.tx() as db:  # (two more agents had it)
        for n in (2, 3):
            jobs.forks.net._event(db, 1, n, "data_job", "src/a.c")
    assert jobs.verdicts("game")["src/a.c"][0] == "tries"
    config = tmp_path / "config"
    config.mkdir()
    (config / "splits.txt").write_text("a.c:\n")  # (its files cut again: what was tried was about other objects)
    later = time.time() + 5
    os.utime(config / "splits.txt", (later, later))
    assert jobs.verdicts("game")["src/a.c"][0] == "job"


def test_a_job_the_agent_released_is_neither_takeable_nor_claimed_by_it_for_a_while(jobs, monkeypatch):
    """takeable said a job was waiting, claim kept the agent off it for good: a GameCube game's lone helper started
    sessions that found nothing, and paused after five."""
    for n in (2, 3):  # (the other jobs held by others)
        jobs.claim(agent(n), "game")
    jobs.claim(agent(1), "game")
    jobs.release(agent(1), "game", "src/b.c", "one table is short")
    assert not jobs.takeable(agent(1), "game")
    assert jobs.claim(agent(1), "game") is None
    monkeypatch.setattr(Net, "_own_release_cutoff", lambda self, db, agent_id, now: now + 1)  # (the window is over)
    assert jobs.takeable(agent(1), "game")
    assert jobs.claim(agent(1), "game").startswith("DATA JOB (claimed): src/b.c")


def test_an_edit_judges_the_file_as_its_job_was_judged(jobs, monkeypatch):
    """A job only because its link failed isn't done once the bytes are the original's: the link failed again, and
    another try was gone."""
    monkeypatch.setattr(DataJobs, "_bytes_left", lambda self, u, alike=True: 0 if alike else LEFT.get(u.name, 0))
    jobs.forks.get("game")[2]["link_failed"] = {"src/a.c": "main.dol differs at 0x80401000"}
    jobs.claim(agent(1), "game")
    assert "32 bytes of src/a.c's data are still left" in jobs.after_edit(agent(1), "game", "src/a.c")


def test_helpers_with_nothing_left_but_files_unlinked_pause_and_say_why(jobs):
    from decompnet.app.agents import Manager

    said = {}
    m = SimpleNamespace(_left=lambda slug, task: 0, _pause=lambda s, why, hint="": said.update(pause=why),
                        _finish=lambda s, why: said.update(finish=why),
                        net=SimpleNamespace(fork_slug=lambda slug: slug, forks=SimpleNamespace(data_jobs=jobs, link_note=lambda slug: "")))
    m._unlinked = lambda slug: Manager._unlinked(m, slug)
    assert Manager._ready(m, SimpleNamespace(slug="game"), agent(1), "") is None
    assert "finish" not in said
    assert "2 files still aren't linked" in said["pause"] and "aside.c" in said["pause"] and "big.c" in said["pause"]
    jobs.forks.net.links["game"] = object()  # (a room's member: the host's files aren't its to judge)
    said.clear()
    assert Manager._ready(m, SimpleNamespace(slug="game"), agent(1), "") is None
    assert "🎉" in said["finish"]


def test_one_job_one_agent_and_it_keeps_its_own(jobs):
    first = jobs.claim(agent(1), "game")
    assert first.startswith("DATA JOB (claimed): src/a.c") and "32 bytes" in first
    assert jobs.claim(agent(2), "game").startswith("DATA JOB (claimed): src/c.c")
    assert jobs.claim(agent(1), "game").startswith("DATA JOB (claimed): src/a.c")  # (its own again, not a new one)
    assert jobs.held(agent(1), "game") == "src/a.c"


def test_a_release_keeps_the_notes_for_the_next_agent(jobs):
    jobs.claim(agent(1), "game")
    assert jobs.release(agent(2), "game", "src/a.c", "x") is None  # (not its job: a function's release, then)
    with pytest.raises(NetworkError):
        jobs.release(agent(1), "game", "src/a.c", " ")
    assert "Released" in jobs.release(agent(1), "game", "src/a.c", "the jump table at the end is still short")
    brief = jobs.claim(agent(2), "game")
    assert brief.startswith("DATA JOB (claimed): src/a.c") and "the jump table at the end is still short" in brief


def test_a_file_handed_out_its_tries_without_matching_is_left(jobs):
    for n in range(datajobs.TRIES):
        assert jobs.claim(agent(1 + n), "game").startswith("DATA JOB (claimed): src/a.c")
        jobs.release(agent(1 + n), "game", "src/a.c", "no luck")
    assert [s for s, _ in jobs.todo("game")] == ["src/c.c", "src/b.c"]


def test_a_released_job_goes_to_another_agent_not_back_to_the_one_that_gave_it_up(jobs):
    """A GameCube game's helper got the job it had just released back from every claim_function."""
    jobs.claim(agent(1), "game")
    jobs.release(agent(1), "game", "src/a.c", "one variable in the project's symbols, four in the C")
    assert jobs.claim(agent(1), "game").startswith("DATA JOB (claimed): src/c.c")
    assert jobs.claim(agent(2), "game").startswith("DATA JOB (claimed): src/a.c")


def test_the_originals_bytes_named_differently_are_a_job_only_once_their_link_failed(jobs, monkeypatch):
    """Alike data (datadiff.same_layout) is the link's to decide; a failed link makes it a job again, its brief saying
    why the game didn't build."""
    monkeypatch.setattr(DataJobs, "_bytes_left", lambda self, u, alike=True: 0 if alike else LEFT.get(u.name, 0))
    assert jobs.todo("game") == []
    jobs.forks.get("game")[2]["link_failed"] = {"src/a.c": "main.dol differs at 0x80401000"}
    assert jobs.todo("game") == [("src/a.c", 32)]
    assert "main.dol differs at 0x80401000" in jobs.claim(agent(1), "game")


def test_an_edit_renews_the_job_and_says_when_it_is_done(jobs):
    jobs.claim(agent(1), "game")
    assert "32 bytes of src/a.c's data" in jobs.after_edit(agent(1), "game", "src/a.c")
    assert jobs.after_edit(agent(2), "game", "src/a.c") == ""  # (not its job)
    LEFT["main/a"] = 0
    try:
        assert "Data job done" in jobs.after_edit(agent(1), "game", "src/a.c")
        assert jobs.held(agent(1), "game") is None
        assert [s for s, _ in jobs.todo("game")] == ["src/c.c", "src/b.c"]
    finally:
        LEFT["main/a"] = 32


def test_no_jobs_in_a_room_or_where_files_are_not_linked(jobs):
    jobs.forks.net.links["game"] = object()
    assert jobs.todo("game") == []
    del jobs.forks.net.links["game"]
    jobs.forks.get("game")[1].linkable = lambda: False
    assert jobs.todo("game") == []


def test_bytes_left_counts_what_is_missing_different_or_only_yours():
    a, b, c = Item("a", b"\0\0\0\1", 4), Item("b", b"abcdefgh", 8), Item("c", None, 16)
    sec = Section(".data", [a, b, c], [a], rows=[(" ", a, a), ("<", b, None), ("|", c, Item("c", None, 8)),
                                                 (">", None, Item("x", b"zz", 2))])
    assert datajobs.bytes_left([sec]) == 8 + datajobs.ZEROED + 2


def test_a_zeroed_global_counts_as_one_definition_whatever_its_size():
    """A GameCube game's files with a 20 KiB thread stack or a 256 KiB buffer to define waited as too big to write."""
    stack = Item("ThreadStack", None, 20480)
    sec = Section(".bss", [stack], None, rows=[("<", stack, None)])
    assert datajobs.bytes_left([sec]) == datajobs.ZEROED < datajobs.MOST_BYTES


def test_a_helper_with_no_function_to_claim_sees_a_data_job_waiting(jobs):
    """Manager._all_given_up asks this before a session: helpers whose open functions were all held by others waited,
    "nothing to claim", with three files' data waiting."""
    assert jobs.takeable(agent(1), "game")
    jobs.claim(agent(1), "game")
    jobs.claim(agent(2), "game")
    assert jobs.takeable(agent(1), "game")  # (its own)
    jobs.claim(agent(2), "game")  # (agent 2 keeps src/c.c; src/b.c is still free)
    assert jobs.takeable(agent(3), "game")
    jobs.claim(agent(3), "game")
    assert not jobs.takeable(agent(4), "game")  # (every one held by another)
    jobs.forks.net.selections["agent-1"] = {"units": ["main/a"]}
    assert not jobs.takeable(agent(1), "game")  # (a work selection gets functions only)


def test_a_helper_with_a_data_job_waiting_starts_its_session(jobs):
    """Manager._all_given_up: the helper starts instead of waiting with "nothing to claim"."""
    from decompnet.app.agents import Manager

    net = SimpleNamespace(claimable=lambda a, slug: 0, fork_slug=lambda slug: slug,
                          forks=SimpleNamespace(data_jobs=jobs))
    s = SimpleNamespace(slug="game")
    assert Manager._all_given_up(SimpleNamespace(net=net), s, agent(1), "") is False


def test_the_host_lists_its_jobs_and_who_holds_each_for_a_rooms_members(jobs):
    """Room._fork_state sends this: a GameCube room's guests found "nothing left" while the host's files waited."""
    assert [j["agent"] for j in jobs.listing("game")] == [None, None, None]
    jobs.claim(agent(2), "game")
    assert jobs.listing("game")[0] == {"source": "src/a.c", "left": 32, "agent": "agent-2"}


class Link:
    """A member's link to the host: the host's list of jobs from its last state, and what it sent the host."""
    member = "alex"

    def __init__(self):
        self.data_jobs, self.sent = [], []

    def call(self, route, agent, /, **data):
        self.sent.append((route, agent.name, data))
        return "Released the data job for src/a.c"


def test_a_rooms_member_counts_takes_and_gives_back_the_hosts_jobs(jobs):
    link = jobs.forks.net.links["game"] = Link()
    link.data_jobs = [{"source": "src/a.c", "left": 32, "agent": "alex.agent-1"},
                      {"source": "src/c.c", "left": 64, "agent": "sam.agent-1"}]
    assert jobs.left("game") == 2  # (a helper's session goes on while the host has jobs)
    assert jobs.takeable(agent(1), "game")  # (its own, by the name the host knows it by)
    assert not jobs.takeable(agent(2), "game")  # (both held by others)
    link.data_jobs.append({"source": "src/b.c", "left": 495, "agent": None})
    assert jobs.takeable(agent(2), "game")
    assert jobs.release(agent(1), "game", "src/a.c", "the table's last row is short").startswith("Released")
    assert link.sent == [("/collab/release", "agent-1",
                          {"function": "src/a.c", "notes": "the table's last row is short", "data_job": True})]
    assert jobs.release(agent(1), "game", "func_80001234", "x") is None  # (no such file: a function's release)
