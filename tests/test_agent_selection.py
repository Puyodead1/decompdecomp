"""A helper's work selection: the order it takes functions in, which ones, how many compiles each, its move-on number.
The user's choice, kept by the queue and the judge rather than left to the model's prompt."""

import json

import pytest

from decompnet import network
from decompnet.app import agents
from decompnet.network import NetworkError

from .test_agents import URL, _game, quiet  # noqa: F401  (fixture)


def _scores(net, **best):
    with net.store.tx() as db:
        for name, score in best.items():
            db.execute("UPDATE functions SET best_score=?, best_source='int f;', n_insns=10 WHERE name=?", (score, name))


def test_a_work_selection_is_checked():
    assert network.validate_selection(None) == {}
    assert network.validate_selection({"strategy": "least_tried", "match_below": "50", "max_tries": 3,
                                       "stall_compiles": "", "other": 1}) == {
        "strategy": "least_tried", "match_below": 50.0, "max_tries": 3}
    for bad in ({"strategy": "fastest"}, {"match_below": 101}, {"max_tries": 0}, {"max_tries": 1.5},
                {"stall_compiles": True}, {"match_below": "x"}, "x"):
        with pytest.raises(NetworkError):
            network.validate_selection(bad)


def test_the_queue_takes_only_what_the_selection_does(tmp_path):
    """Below 50% matched: f1 (90%) is left out; one never compiled counts as 0%. Named, it's refused with why."""
    net = _game(tmp_path, functions=3)
    _scores(net, f0=900, f1=100)  # f0 10% matched, f1 90%, f2 untried
    agent, _ = net.local_agent("claude-opus-1")
    net.set_selection("game", agent.name, {"match_below": 50, "strategy": "hardest"})
    with pytest.raises(NetworkError, match="90% matched.*below 50%"):
        net.claim_row(agent, "game", "f1")
    got = net.claim_row(agent, "game")
    assert got["name"] in ("f0", "f2")
    assert net.selection_left(agent, "game") == 2
    other, _ = net.local_agent("claude-opus-2")
    assert net.claim_row(other, "game", "f1")["name"] == "f1"  # another helper's choices are its own


def test_the_new_orders_and_filters_of_a_selection(tmp_path):
    """From RetroReversing's fork: untried first, the longest unchecked first, only functions no C has compiled for
    yet (a filter: the helper stops when there's none), and only functions no agent of its model has tried (whatever its effort)."""
    assert network.model_key("claude-mythos-5-1-low-1") == network.model_key("claude-mythos-5-1-high-12") == \
        "claude-mythos-5-1"
    assert network.model_key("opencode-deepseek-v4.1-flash-high-4") == "opencode-deepseek-v4.1-flash"
    assert network.validate_selection({"strategy": "no_compiling_c", "model_untried": True}) == {
        "strategy": "no_compiling_c", "model_untried": True}
    with pytest.raises(NetworkError):
        network.validate_selection({"model_untried": "yes"})
    net = _game(tmp_path, functions=3)
    low, _ = net.local_agent("claude-opus-low-1")
    with net.store.tx() as db:  # f0: compiled (scored) by low long ago; f1: a compile error only, lately; f2: never
        ids = {r["name"]: r["id"] for r in db.execute("SELECT id, name FROM functions")}
        db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,created_at) VALUES(?,?,5,1,1)",
                   (ids["f0"], low.id))
        db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,created_at) VALUES(?,?,NULL,0,9)",
                   (ids["f1"], low.id))
        db.execute("UPDATE functions SET attempts=1 WHERE name IN ('f0', 'f1')")
        db.execute("UPDATE functions SET best_score=5, best_source='int f;' WHERE name='f0'")
    pick = lambda name, sel: (net.set_selection("game", name, sel),  # noqa: E731
                              net.claim_row(net.local_agent(name)[0], "game"))[1]["name"]
    def unclaim(*sql):
        with net.store.tx() as db:
            db.execute("DELETE FROM claims")
            for q in sql:
                db.execute(q)

    assert pick("claude-opus-2", {"strategy": "untried"}) == "f2"
    unclaim()
    assert pick("claude-opus-3", {"strategy": "oldest_checked"}) == "f2"  # (never checked first)
    unclaim("UPDATE functions SET status='matched' WHERE name='f2'")
    assert pick("claude-opus-4", {"strategy": "oldest_checked"}) == "f0"  # (checked at 1, before f1's 9)
    unclaim()
    sweeper, _ = net.local_agent("claude-opus-5")
    net.set_selection("game", sweeper.name, {"strategy": "no_compiling_c"})
    assert net.selection_left(sweeper, "game") == 1  # f1: its only try didn't compile
    with pytest.raises(NetworkError, match="C has compiled for f0 already"):
        net.claim_row(sweeper, "game", "f0")
    assert net.claim_row(sweeper, "game")["name"] == "f1"
    unclaim()
    high, _ = net.local_agent("claude-opus-high-6")  # low's model, another effort: f0 and f1 were its model's
    net.set_selection("game", high.name, {"model_untried": True})
    assert net.selection_left(high, "game") == 0 and net.claim_row(high, "game") is None
    with pytest.raises(NetworkError, match="an agent of your model has tried f1"):
        net.claim_row(high, "game", "f1")
    fresh, _ = net.local_agent("codex-gpt-6-1")  # another model: both are new to it
    net.set_selection("game", fresh.name, {"model_untried": True})
    assert net.selection_left(fresh, "game") == 2


def test_max_tries_releases_the_function_and_keeps_its_best(tmp_path):
    net = _game(tmp_path)
    agent, _ = net.local_agent("claude-opus-1")
    net.set_selection("game", agent.name, {"max_tries": 2})
    fn = net.claim_row(agent, "game", "f0")
    with net.store.tx() as db:
        for _ in range(2):
            db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,created_at) VALUES(?,?,5,1,0)",
                       (fn["id"], agent.id))
    with pytest.raises(NetworkError, match="2 times, the most your work selection allows"):
        net.check_tries(agent, net._function("f0", "game"))
    assert net.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 0
    assert net.selection_left(agent, "game") == 0
    with pytest.raises(NetworkError, match="most your work selection allows"):
        net.claim_row(agent, "game", "f0")


def test_a_helpers_own_move_on_number(tmp_path):
    net = _game(tmp_path)
    agent, _ = net.local_agent("claude-opus-1")
    fn = net.claim_row(agent, "game", "f0")
    assert net.stall_status(fn["id"], agent.id)["after"] == network.stall_budget(4)
    net.set_selection("game", agent.name, {"stall_compiles": 25})
    assert net.stall_status(fn["id"], agent.id)["after"] == 25
    assert "move on after 25 compiles" in network.move_on_brief(fn, net.stall_after(fn, agent))
    assert "your number, as the user set it" in network.move_on_brief(fn, 25)


def test_a_helpers_selection_is_kept_with_it_and_pauses_it_when_nothing_is_left(tmp_path, quiet):  # noqa: F811
    net = _game(tmp_path)
    m = agents.Manager(net, tmp_path, URL)
    (sid,) = m.start("claude", "game", 1, {"model": "opus", "selection": {"max_tries": 1}})
    s = m.sessions[sid]
    assert net.selection("game", s.agent_name) == {"max_tries": 1} and s.snapshot()["selection"] == {"max_tries": 1}
    assert m.set_selection(sid, {"strategy": "random"}) == {"strategy": "random"}
    row = net.store.one("SELECT options FROM helpers WHERE id=?", sid)
    assert json.loads(row["options"])["selection"] == {"strategy": "random"}
    assert m.set_selection(sid, {}) == {} and net.selection("game", s.agent_name) == {}
    with pytest.raises(NetworkError):
        m.start("claude", "game", 1, {"model": "opus", "selection": {"max_tries": -1}})
