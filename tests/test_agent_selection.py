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
