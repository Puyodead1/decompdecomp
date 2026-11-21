"""A deep search (app/deep.py): the permuter on one function the user picks, for as long as they say, beside any
agent holding it. From RetroReversing's fork; on a 2000s Linux game, by hand, it took one of the last three functions
from 270 to 50 and another from 501 to 270 in 80 minutes, where the permuter's own limits never let it near them."""

import time

import pytest

from decompnet.app import deep, permute
from decompnet.app.support import Jobs
from decompnet.network import NetworkError

from .test_permute import AGENT, FakeNet, batches


class Net(FakeNet):
    def local_agent(self, name):
        return AGENT, ""

    def _function(self, name, slug=None):
        row = self.store.one("SELECT * FROM functions WHERE name=?", name)
        if row is None:
            raise NetworkError(f"no function {name}")
        return row


class Scripted(deep.Search):
    """Scores from a table, recorded as the permuter's _record would: a better score is the function's best, 0 its
    match."""

    def __init__(self, net, scores, **kw):
        super().__init__(net, **kw)
        self.scores = scores

    def _judge(self, agent, proj, fn, source, best, fork):
        score = self.scores.get(source, 1000)
        if score < best:
            with self.net.store.tx() as db:
                db.execute("UPDATE functions SET best_score=?, best_source=?, status=? WHERE id=?",
                           (score, source, "matched" if score == 0 else "open", fn["id"]))
        return score


def test_a_search_keeps_going_past_the_permuters_limits_and_keeps_what_it_finds(monkeypatch):
    """Turn after turn until it matches: no claim taken or refused (an agent holds the function), no permuter turn
    counted, and the result says how it went. Its progress is published as it goes."""
    net = Net()
    with net.store.tx() as db:  # an agent holds it, and the permuter's own turns are all used up
        db.execute("INSERT INTO agents(id, name, token_hash) VALUES(2, 'claude-opus-1', 'y')")
        db.execute("INSERT INTO claims VALUES(1, 2, 0, 9e12)")
        db.execute("UPDATE functions SET permuted=100")
    batches(monkeypatch, ["far", "closer"], ["far again"], ["closest"], ["same"])
    shown = []
    search = Scripted(net, {"closer": 30, "closest": 10, "same": 0}, minutes=5, variants=1000, progress=shown.append)
    result = search.run("game", "f")
    assert result["matched"] and result["reason"] == "matched" and result["start_score"] == 40
    assert result["tested"] == 5 and result["improved"] >= 2
    row = net.function()
    assert row["status"] == "matched" and row["permuted"] == 100
    assert net.store.one("SELECT agent_id FROM claims WHERE function_id=1")["agent_id"] == 2
    assert shown[0]["start_score"] == 40 and shown[-1]["best_score"] == 0
    assert '"deep"' in row["meta"] and "matched after 5 variants" in deep.summary(result)


def test_a_search_ends_at_its_limits_or_when_stopped(monkeypatch):
    net = Net()
    batches(monkeypatch, *[[f"v{i}", f"w{i}"] for i in range(50)])
    result = Scripted(net, {"v0": 35}, minutes=5, variants=3).run("game", "f")
    assert result["reason"] == "variants" and result["tested"] == 3 and result["best_score"] == 35
    batches(monkeypatch, *[[f"x{i}"] for i in range(50)])
    search = Scripted(net, {}, minutes=5, variants=1000)
    search.cancelled = lambda: search.tested >= 2  # (Stop pressed after its second variant)
    result = search.run("game", "f")
    assert result["reason"] == "stopped" and result["tested"] == 2 and result["best_score"] == 35
    batches(monkeypatch)  # (nothing new to write from this C, and no rewrite applies)
    monkeypatch.setattr(permute, "available", lambda: False)
    monkeypatch.setattr(permute, "mutate", lambda source, rng: None)
    assert Scripted(net, {}, minutes=5, variants=1000).run("game", "f")["reason"] == "exhausted"


def test_searches_start_once_per_function_and_only_on_c_that_scores(monkeypatch):
    net = Net()
    jobs = Jobs()
    searches = deep.Searches(net, jobs)
    with pytest.raises(NetworkError, match="minutes must be a whole number from 1 to 120"):
        searches.start("game", "f", minutes=500)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_score=NULL")
    with pytest.raises(NetworkError, match="no C that compiles yet"):
        searches.start("game", "f")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_score=40")
    monkeypatch.setattr(deep.Search, "run", lambda self, slug, name, log: (
        [time.sleep(0.01) for _ in range(500) if not log.cancelled()], {"reason": "stopped"})[1])
    jid = searches.start("game", "f")
    assert searches.start("game", "f") == jid and searches.job_for("game", "f") == jid
    jobs.cancel(jid)
    deadline = time.monotonic() + 10
    while jobs.jobs[jid]["state"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
    assert jobs.jobs[jid]["state"] == "cancelled" and jobs.jobs[jid]["error"] == deep.STOPPED
    assert searches.job_for("game", "f") is None
    # (a room guest's too: test_collab, a guest's search shares what it finds with the host)


def test_a_search_of_a_projects_function_judges_its_variants(monkeypatch):
    """A project's turn renews its hold once its unit is its own (trial_run); a search holds nothing, so that ended
    every deep search of a GameCube game before its first variant: "no better in 0 variants and 0 s"."""
    from contextlib import contextmanager

    from .test_permute import HEADER

    class Forks:
        @contextmanager
        def trial_run(self, proj, unit):
            yield

        def permuter_header(self, fork, name):
            return HEADER

        def permuter_name(self, fork, name, source):
            return name

        def tree_wanted(self, proj):
            return False


        def unit_wanted(self, proj, unit):

            return False

    class ForkNet(Net):
        forks = Forks()

        def fork_slug(self, slug):
            return slug

    batches(monkeypatch, ["far", "closer"], ["closest"])
    result = Scripted(ForkNet(), {"closer": 30, "closest": 0}, minutes=5, variants=1000).run("game", "f")
    assert result["matched"] and result["tested"] == 3


def test_a_search_waits_out_a_change_of_the_whole_tree_instead_of_ending(monkeypatch):
    """A turn steps aside when something waits for the project's tree alone (a room member's match or edit): a
    search took such a turn, with nothing tried, for the end of what it could write ("0 variants and 0 s")."""
    from contextlib import contextmanager

    from .test_permute import HEADER

    turns = []

    class Forks:  # (wanted through the first two turns: a member's two matches)
        @contextmanager
        def trial_run(self, proj, unit):
            turns.append(1)
            yield

        def permuter_header(self, fork, name):
            return HEADER

        def permuter_name(self, fork, name, source):
            return name

        def tree_wanted(self, proj):
            return len(turns) <= 2


        def unit_wanted(self, proj, unit):

            return False

    class ForkNet(Net):
        forks = Forks()

        def fork_slug(self, slug):
            return slug

    monkeypatch.setattr(deep, "YIELD_WAIT", 0)
    batches(monkeypatch, ["far", "closer"], ["closest"])
    result = Scripted(ForkNet(), {"closer": 30, "closest": 0}, minutes=5, variants=1000).run("game", "f")
    assert result["matched"] and result["tested"] == 3 and len(turns) >= 3


def test_a_searchs_turns_are_the_permuters_length_so_agents_get_the_file_between_them(monkeypatch):
    """A project's turn holds its function's source file: a search's one turn held it for its 30 minutes, and five
    agents in that file waited till their calls timed out."""
    seconds = []
    orig = permute.Permuter._permute

    def recording(self, agent, proj, fn, st):
        seconds.append(self.seconds)
        return orig(self, agent, proj, fn, st)

    monkeypatch.setattr(permute.Permuter, "_permute", recording)
    monkeypatch.setattr(deep, "TURN_GAP", 0)
    batches(monkeypatch, ["far"], ["closest"])
    result = Scripted(Net(), {"closest": 0}, minutes=30, variants=1000).run("game", "f")
    assert result["matched"] and seconds and max(seconds) <= permute.SECONDS


def test_a_search_tries_local_rewrites_of_the_best_c_first(monkeypatch):
    """The Deep permuter's first pass, taken in when it and Deep search became one: a few targeted rewrites of the
    best C (declaration order, a temporary...) before the permuter's random ones, kept when they score better."""
    net = Net()
    monkeypatch.setattr(deep.permuter_local, "variants", lambda source, name: [("swap", "rewrite"), ("temp", "worse")])
    batches(monkeypatch, ["far"], ["same"])
    shown = []
    search = Scripted(net, {"rewrite": 25, "same": 0}, minutes=5, variants=1000, progress=shown.append)
    result = search.run("game", "f")
    assert result["matched"] and result["tested"] == 4
    assert [h["score"] for h in shown[-1]["history"]] == [40, 25, 0]  # (the tab's chart: start, rewrite, match)
    assert shown[-1]["starting_score"] == 40 and shown[-1]["variant_limit"] == 1000
