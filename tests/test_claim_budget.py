"""How long one claim works a function: a near-match gets a larger move-on budget and a new diff at its best counts as
progress; the brief lists what was already tried at the best; and one claim gets at most COMPILE_LIMIT times the
move-on number of compiles that don't beat its best. ROM mode here; tests/test_forks.py runs the project-mode side."""

import json
import time

from decompnet import network
from decompnet.network import (
    compile_limit,
    move_on_brief,
    no_best_text,
    stall_budget,
    state_text,
    tried_brief,
)

from .test_claims import _game, _held


def _brief(net, name, agent):
    """A function's brief without a compiler or its assembly (this game has neither): what the brief says of its
    compiles is what's looked at."""
    net._seed_for = lambda *a, **k: None
    net._asm_text = lambda fn, proj: ""
    net._extra_brief = lambda fn, proj: []
    with net.store.tx() as db:
        db.execute("INSERT OR IGNORE INTO context_versions(project_id,version,header,created_at,unit) "
                   "VALUES(1,1,'',0,'')")
        db.execute("UPDATE projects SET config=?", (json.dumps({"kind": "rom", "compiler": {"toolchain": "x",
                                                                                            "flags": []}}),))
    return net.get_function(name, "game", agent)


def _fid(net, name):
    return net.store.one("SELECT id FROM functions WHERE name=?", name)["id"]


def _attempts(net, agent, name, scores, digests=None):
    fid = _fid(net, name)
    with net.store.tx() as db:
        for i, s in enumerate(scores):
            db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,context_version,source,created_at,"
                       "diff_digest) VALUES(?,?,?,?,?,?,?,?)",
                       (fid, agent.id, s, s is not None, 1, "int f(){}", time.time(),
                        digests[i] if digests else None))


# ------------------------------------------------------------ near-matches (RetroReversing 466e2fc30)

def test_a_near_match_gets_a_larger_budget_and_a_new_diff_at_the_best_counts_as_progress(tmp_path):
    """Near-matches sat at scores 10-15 for hundreds of attempts, each helper sent away after 3 compiles."""
    assert stall_budget(10) == 3
    assert stall_budget(10, 12) == network.NEAR_MATCH_BUDGET
    assert stall_budget(10, 400) == 3 and stall_budget(10, 0) == 3
    assert stall_budget(1000, 12) == network.NEAR_MATCH_BUDGET  # (bigger than the biggest size's)
    # a tie at the best with a diff not seen there is progress; the same diff again is not
    assert network._no_better([12, 12, 12], ["a", "b", "c"]) == 0
    assert network._no_better([12, 12, 12], ["a", "b", "b"]) == 1
    assert network._no_better([12, 12]) == 1
    assert network.diff_digest([(" ", "x", "x")]) is None
    assert network.diff_digest([("r", "a", "b")]) != network.diff_digest([("r", "a", "c")])

    net, _ = _game(tmp_path, [("f", 10, "open")])
    a, _ = net.local_agent("a")
    net._record(net._function("f", "game"), a, 12, "int f(){return 9;}", 1, mismatch_rows=[("r", "a", "b")])
    net.claim_row(a, "game", "f")
    fid = _fid(net, "f")
    for i in range(4):
        net._record(net._function("f", "game"), a, 12, f"int f(){{return {i};}}", 1, mismatch_rows=[("r", "a", str(i))])
    st = net.stall_status(fid, a.id)
    assert st["after"] == network.NEAR_MATCH_BUDGET and st["no_better"] == 0
    assert "near-match" in move_on_brief(net._function("f", "game"))
    assert net.store.one("SELECT COUNT(DISTINCT diff_digest) AS n FROM attempts")["n"] == 5


def test_without_a_claim_the_move_on_count_reads_back_as_far_as_a_near_matchs_budget(tmp_path):
    net, _ = _game(tmp_path, [("f", 10, "open")])
    a, _ = net.local_agent("a")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_score=12")
    _attempts(net, a, "f", [12] + [30] * 19)
    st = net.stall_status(_fid(net, "f"), a.id)
    assert st["claimed_at"] is None and st["compiles"] == 20 and st["no_better"] == 19 < st["after"]


# ------------------------------------------------------- already tried at the best (RetroReversing 6747a4f3c)

def test_the_brief_lists_what_was_tried_at_the_best_and_a_compile_there_is_flagged(tmp_path):
    net, _ = _game(tmp_path, [("f", 10, "open")])
    a, _ = net.local_agent("a")
    b, _ = net.local_agent("b")
    get = lambda: net._function("f", "game")  # noqa: E731
    net._record(get(), a, 12, "int f(void)\n{\n    return 1;\n}", 1, mismatch_rows=[("r", "x", "y")])
    net._record(get(), b, 12, "int f(void)\n{\n    return 2;\n}", 1, mismatch_rows=[("r", "x", "y")])
    net._record(get(), b, 12, "int f(void)\n{\n    return 3;\n}", 1, mismatch_rows=[("r", "x", "z")])
    table = "\n".join(net.tried_at_best(get()))
    assert "Already tried at this best (score 12): 3 compiles, 2 distinct diffs" in table
    assert table.count("\n| ") == 4  # the header, its rule and two diffs
    assert "`return 3;` for `return 1;`" in table  # what its C changed from the best attempt (the first)
    assert "Already tried at this best" in _brief(net, "f", a)  # in the brief
    fid = get()["id"]
    # the compile just recorded reproduces a known diff: flagged, never refused
    assert net.judged_at_best_note(fid, 12, "int f(void)\n{\n    return 3;\n}") == ""  # (its diff, z, was new)
    net._record(get(), a, 12, "int f(void)\n{\n    return 4;\n}", 1, mismatch_rows=[("r", "x", "y")])
    note = net.judged_at_best_note(fid, 12, "int f(void)\n{\n    return 4;\n}")
    assert "Already judged at this best: this same diff was reached 2 times by 2 agents" in note
    net._record(get(), a, 12, "int f(void)\n{\n  return 1;\n}", 1, mismatch_rows=[("r", "x", "q")])
    assert "this exact source" in net.judged_at_best_note(fid, 12, "int f(void)\n{\n  return 1;\n}")
    assert net.judged_at_best_note(fid, 40, "int f(void) { return 1; }") == ""  # not at the best


def test_no_table_without_a_positive_best_or_a_second_compile(tmp_path):
    net, _ = _game(tmp_path, [("f", 10, "open")])
    a, _ = net.local_agent("a")
    assert net.tried_at_best(net._function("f", "game")) == []
    net._record(net._function("f", "game"), a, 12, "int f(){return 1;}", 1, mismatch_rows=[("r", "x", "y")])
    assert net.tried_at_best(net._function("f", "game")) == []


# --------------------------------------------------- one claim's compile limit (n-delic/decompdecomp#314)

def test_one_claim_gets_twice_the_move_on_number_of_compiles_without_a_better_score(tmp_path):
    # the move-on number counts compiles without a better score in a row, so a better score now and then started it
    # again; the limit counts them over the whole claim
    net, _ = _game(tmp_path, [("f", 10, "open"), ("g", 10, "open")])
    a, _ = net.local_agent("a")
    net.claim_row(a, "game", "f")
    after = stall_budget(10)
    assert (after, compile_limit(after)) == (3, 6)
    # a better score every third compile: never "move on", but 5 that beat nothing (a failed build counts)
    _attempts(net, a, "f", [100, None, 120, 90, None, 95, 80, 85])
    assert net._over_compile_limit(a, "f", "game") is None
    note = net.stall_note(_fid(net, "f"), a.id)
    assert "Move-on count: no better in 1/3" in note and "Compiles without a better score left on this claim: 1" in note
    _attempts(net, a, "f", [None])  # a build that fails
    assert "that was the last compile without a better score" in net.stall_note(_fid(net, "f"), a.id)
    res = net.attempt(a, "f", "int f(void) { return 1; }", "game")  # refused before anything is built
    assert res["score"] is None and not res["matched"]
    assert res["text"].startswith("Not compiled: 6 of your 9 compiles of f since you claimed it didn't beat")
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts")["n"] == 9  # not recorded
    # the release goes through at once, though the move-on number was never reached
    assert net.release_function(a, "f", "close twice, never matched", "game").startswith("Released f")
    assert _held(net, a) is None


def test_compiles_that_keep_getting_better_are_never_cut_off(tmp_path):
    net, _ = _game(tmp_path, [("f", 2000, "open"), ("g", 10, "open")])
    a, _ = net.local_agent("a")
    net.claim_row(a, "game", "f")
    _attempts(net, a, "f", [100000 - 10 * i for i in range(40)] + [None] * (compile_limit(stall_budget(2000)) - 1))
    assert net._over_compile_limit(a, "f", "game") is None
    _attempts(net, a, "f", [99999])
    assert net._over_compile_limit(a, "f", "game")


def test_a_near_matchs_new_diffs_at_the_best_still_end_at_the_limit(tmp_path):
    """A tie with a new diff resets the move-on count, but not the claim's limit: it would never end otherwise."""
    net, _ = _game(tmp_path, [("f", 10, "open")])
    a, _ = net.local_agent("a")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_score=12")
    net.claim_row(a, "game", "f")
    n = compile_limit(network.NEAR_MATCH_BUDGET)
    _attempts(net, a, "f", [12] * (n + 1), [f"d{i}" for i in range(n + 1)])
    st = net.stall_status(_fid(net, "f"), a.id)
    assert st["no_better"] == 0 and st["no_gain"] == n
    assert net._over_compile_limit(a, "f", "game")


def test_the_compile_limit_is_per_claim_and_not_for_the_apps_own_workers_or_you(tmp_path):
    net, _ = _game(tmp_path, [("f", 10, "open"), ("g", 10, "open")])
    a, _ = net.local_agent("a")
    for name in ("autopilot", "you"):
        own, _ = net.local_agent(name)
        net.claim_row(own, "game", "f")
        _attempts(net, own, "f", [None] * 20)
        assert net._over_compile_limit(own, "f", "game") is None
        net.release(own, "f", "", "game")
    with net.store.tx() as db:
        db.execute("UPDATE attempts SET created_at=created_at-60")
    net.claim_row(a, "game", "f")
    _attempts(net, a, "f", [None] * compile_limit(stall_budget(10)))
    assert net._over_compile_limit(a, "f", "game")
    net.release_function(a, "f", "nothing builds", "game")
    with net.store.tx() as db:  # (a later claim of its: the old compiles are before it)
        db.execute("UPDATE attempts SET created_at=created_at-60")
        db.execute("UPDATE events SET created_at=created_at-3600 WHERE kind='release'")
    net.claim_row(a, "game", "f")
    assert net._over_compile_limit(a, "f", "game") is None


def test_a_room_members_agent_on_the_host_is_not_limited(tmp_path):
    """The member's own app counts its compiles; the host only confirms what it sends (how it judges stays)."""
    net, _ = _game(tmp_path, [("f", 10, "open")])
    with net.store.tx() as db:
        aid = db.execute("INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin) VALUES(?,?,?,?,1,?)",
                         ("alex.claude-1", "alex", "remote:x", time.time(), "collab:game")).lastrowid
    member = network.Agent(aid, "alex.claude-1", "alex", True)
    net.claim_row(member, "game", "f")
    _attempts(net, member, "f", [None] * 20)
    assert net._over_compile_limit(member, "f", "game") is None


# ------------------------------------------------------------- compiles with no best (n-delic/decompdecomp#314)

def test_agents_read_compiles_that_left_no_best_as_such_not_as_not_started(tmp_path):
    assert no_best_text(0) == "not started"
    assert no_best_text(1) == "1 compile, no best yet"
    assert no_best_text(12) == "12 compiles, no best yet"
    row = {"status": "open", "best_score": None, "attempts": 12}
    assert state_text(row) == "12 compiles, no best yet"
    assert state_text(row | {"attempts": 0}) == "not started"
    assert state_text(row | {"best_score": 40}) == "best 40"
    assert state_text(row | {"status": "matched"}) == "matched"
    assert state_text(row | {"status": "asm"}) == "set aside"
    assert tried_brief(row) == ["tried before: 12 compiles, no best yet (the notes below say what was tried, if any)"]
    assert tried_brief(row | {"attempts": 0}) == []
    assert tried_brief(row | {"best_score": 40}) == []  # the best attempt's section says it
    assert tried_brief(row | {"status": "matched"}) == []
    net, _ = _game(tmp_path, [("f", 10, "open")])
    a, _ = net.local_agent("a")
    _attempts(net, a, "f", [None] * 12)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET attempts=12")
    brief = _brief(net, "f", a)
    assert "tried before: 12 compiles, no best yet" in brief and "one claim gets at most 6 compiles" in brief
