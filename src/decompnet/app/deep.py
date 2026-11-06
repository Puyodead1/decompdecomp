"""A deep search: the permuter on one function the user picks, for as long as they say, from its page.

The permuter on its own (permute.py) takes near misses: at most 6% off, at most MAX_INSNS instructions, a few turns
of a minute each, and never a function an agent holds. A 722-instruction function one register away from matching
(a 2000s Linux game's read_tga, 35 off) was none of those, nor were two others of its game's last three: run by hand
on a copy for 80 minutes, the permuter took one from 270 to 50 and another from 501 to 270. This is that, in the app,
from RetroReversing's fork (its "deep permuter").

It runs as a job of its own (support.Jobs: Stop cancels it, its progress is the job's), at the workers' lower CPU
priority but not on them: it's the user's own choice, not background work waiting its turn. It works beside an agent
holding the function, taking and refusing no claim: a project's try puts the source file back under the unit's lock
(forkengine.attempt, background), a ROM project's judges without the file. What beats the function's best is
recorded as the permuter's at once, so a search that's stopped keeps what it found, and the next starts from there.
"""

from __future__ import annotations

import json
import threading
import time

from ..network import NetworkError
from . import workers
from .permute import Permuter, State

MINUTES = (1, 120)  # how long a search may run
DEFAULT_MINUTES = 30
VARIANTS = (1, 1_000_000)  # how many variants it may judge
DEFAULT_VARIANTS = 100_000
MAX_SEARCHES = workers.WORKERS  # at once, in the whole app
PROGRESS_SECONDS = 0.5  # how often its progress is published
STOPPED = "The deep search was stopped: what it found is kept as the function's best attempt."


def _limit(value, bounds: tuple[int, int], default: int, what: str) -> int:
    if value in (None, ""):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = None
    if number is None or isinstance(value, bool) or not bounds[0] <= number <= bounds[1]:
        raise NetworkError(f"{what} must be a whole number from {bounds[0]:,} to {bounds[1]:,}")
    return number


class Search(Permuter):
    """One function's search: the permuter's turns (Permuter._permute) one after another until its time or its
    variants run out, it matches, the user stops it, or nothing new is left to write."""

    def __init__(self, net, minutes: int, variants: int, cancelled=lambda: False, progress=lambda state: None):
        super().__init__(net)
        self.minutes, self.max_variants = minutes, variants
        self.cancelled, self.publish = cancelled, progress
        self.tested = 0
        self.started = time.monotonic()
        self.deadline = self.started + minutes * 60
        self.st = State()
        self._shown = 0.0
        self.start_score = self.best = None
        self.reason = ""

    # a search takes no claim and counts no turn: it works beside whoever holds the function
    def _hold(self, agent, fn) -> bool:
        return True

    def _let_go(self, agent, fn) -> None:
        pass

    @staticmethod
    def _seed(fn) -> str:  # (each search its own variants: the permuter's seed would write the same ones again)
        return f"{fn['id']}-deep-{time.time_ns()}"

    def _over(self) -> str:
        if self.cancelled():
            return "stopped"
        if self.tested >= self.max_variants:
            return "variants"
        if time.monotonic() >= self.deadline:
            return "time"
        return ""

    def _score(self, agent, proj, fn, source: str, best: int, fork: str | None) -> int | None:
        if (why := self._over()):
            self.reason = self.reason or why
            self.st.stop.set()
            return None
        self.tested += 1
        score = self._judge(agent, proj, fn, source, best, fork)
        if score is not None and (self.best is None or score < self.best):
            self.best = score
        self._show()
        return score

    def _judge(self, agent, proj, fn, source: str, best: int, fork: str | None) -> int | None:
        """A variant's score, recorded when it beats `best`: a project's try beside the agent's claim, a ROM
        project's as the permuter judges it."""
        if fork:
            with self.net.progress.judging(proj["slug"]):
                return self.net.forks.attempt(agent, fork, fn["name"], source, keep=False, quiet=best,
                                              background=True).get("score")
        return super()._score(agent, proj, fn, source, best, fork)

    def _show(self, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self._shown >= PROGRESS_SECONDS:
            self._shown = now
            self.publish({"tested": self.tested, "start_score": self.start_score, "best_score": self.best,
                          "improved": self.st.improved, "seconds": round(now - self.started),
                          "minutes": self.minutes, "max_variants": self.max_variants})

    def run(self, slug: str, name: str, log=lambda line: None) -> dict:
        agent, _ = self.net.local_agent("permuter")
        proj = self.net.project_row(slug)
        fn = self.net._function(name, slug)
        self.start_score = self.best = fn["best_score"]
        n_insns = fn["n_insns"] or 1
        log(f"{fn['name']}: from {fn['best_score']} ({_percent(fn['best_score'], n_insns)}), for up to "
            f"{self.minutes} min or {self.max_variants:,} variants")
        self._show(force=True)
        rounds = 0
        while not self.reason:
            fn = self.net.store.one("SELECT * FROM functions WHERE id=?", fn["id"])
            if fn is None or fn["status"] != "open":
                self.reason = "matched" if fn is not None and fn["status"] == "matched" else "gone"
                break
            if (why := self._over()):
                self.reason = why
                break
            self.seconds = max(1, int(self.deadline - time.monotonic()))
            before = self.tested
            self._permute(agent, proj, fn, self.st)
            rounds += 1
            if self.tested == before and not self.reason:  # nothing new left to write from this C, nor any rewrite
                self.reason = self._over() or "exhausted"  # (or its time ran out as the turn began)
        row = self.net.store.one("SELECT status, best_score FROM functions WHERE id=?", fn["id"])
        matched = row is not None and row["status"] == "matched"
        best = 0 if matched else row["best_score"] if row is not None else self.best
        result = {"function": fn["name"], "reason": "matched" if matched else self.reason, "matched": matched,
                  "tested": self.tested, "start_score": self.start_score, "best_score": best,
                  "improved": self.st.improved, "seconds": round(time.monotonic() - self.started),
                  "n_insns": n_insns, "finished_at": time.time()}
        self.best = best
        self._show(force=True)
        _remember(self.net, fn["id"], result)
        log(summary(result))
        return result


def _percent(score, n_insns: int) -> str:
    if score is None:
        return "no score"
    return f"{max(0.0, 100.0 * (1 - score / max(1, n_insns * 100))):.1f}%"


REASONS = {"matched": "it matched", "time": "its time ran out", "variants": "it judged every variant it was given",
           "stopped": "you stopped it", "exhausted": "the permuter had nothing new to write from this C",
           "gone": "the function isn't open any more"}


def summary(result: dict) -> str:
    n = result["n_insns"]
    if result["matched"]:
        return f"{result['function']} matched after {result['tested']:,} variants ({result['seconds']} s)."
    moved = (f"from {result['start_score']} to {result['best_score']} ({_percent(result['best_score'], n)})"
             if result["best_score"] != result["start_score"] else f"no better than {result['start_score']}")
    return (f"{result['function']}: {moved} in {result['tested']:,} variants and {result['seconds']} s; it ended "
            f"because {REASONS.get(result['reason'], result['reason'])}.")


def _remember(net, function_id: int, result: dict) -> None:
    """The last search, on the function's page (its meta's "deep")."""
    with net.store.tx() as db:
        row = db.execute("SELECT meta FROM functions WHERE id=?", (function_id,)).fetchone()
        if row is None:
            return
        meta = json.loads(row["meta"] or "{}")
        meta["deep"] = {k: result[k] for k in ("reason", "tested", "start_score", "best_score", "seconds",
                                                "finished_at")}
        db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), function_id))


class Searches:
    """The deep searches running in the app: one per function, MAX_SEARCHES at once."""

    def __init__(self, net, jobs):
        self.net, self.jobs = net, jobs
        self.running: dict[tuple[str, str], str] = {}  # (slug, function) -> job id
        self._lock = threading.Lock()

    def job_for(self, slug: str, name: str) -> str | None:
        with self._lock:
            jid = self.running.get((slug, name))
            if jid is not None and self.jobs.jobs.get(jid, {}).get("state") != "running":
                self.running.pop((slug, name), None)
                return None
            return jid

    def start(self, slug: str, function: str, minutes=None, variants=None) -> str:
        """Start a search on a function (or say which one runs on it): its job's id."""
        minutes = _limit(minutes, MINUTES, DEFAULT_MINUTES, "minutes")
        variants = _limit(variants, VARIANTS, DEFAULT_VARIANTS, "variants")
        if slug in self.net.links:
            raise NetworkError("in a room, the host's permuter searches: start a deep search on the host's computer")
        fn = self.net._function(function, slug)
        if fn["status"] != "open":
            raise NetworkError(f"{fn['name']} isn't open: a deep search is for a function that doesn't match yet")
        if not fn["best_source"] or fn["best_score"] is None:
            raise NetworkError(f"{fn['name']} has no C that compiles yet: a deep search rewrites its best attempt, "
                               "so it needs one with a score first")
        key = (slug, fn["name"])
        with self._lock:
            if (jid := self.running.get(key)) and self.jobs.jobs.get(jid, {}).get("state") == "running":
                return jid
            live = [j for j in self.running.values() if self.jobs.jobs.get(j, {}).get("state") == "running"]
            if len(live) >= MAX_SEARCHES:
                raise NetworkError(f"{len(live)} deep searches are running already, the most at once: stop one, or "
                                   "wait for one to end")

            def run(log):
                workers._lower_priority()  # (this job's thread only: the app and the agents come first)
                search = Search(self.net, minutes, variants, cancelled=log.cancelled, progress=log.progress)
                return search.run(slug, fn["name"], log)

            jid = self.running[key] = self.jobs.start("deep-search", run, cancel_message=STOPPED)
        return jid
