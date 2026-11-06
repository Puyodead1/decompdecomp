"""The Background work page (app/monitor.py): every project's background parts at work, the app's jobs and the
shared workers' queue, with Stop for each. A PC game's machine drafts held every worker for hours while another
game's permuter waited behind them, and nothing on screen said so."""

import threading
import time
from types import SimpleNamespace

from decompnet.app import monitor, workers
from decompnet.app.support import Jobs


class Part:
    def __init__(self, **jobs):
        self.jobs, self.stopped = jobs, []

    def stop(self, slug):
        self.stopped.append(slug)
        self.jobs[slug].state = "stopped"


def test_the_monitor_shows_each_part_at_work_and_stops_it(monkeypatch):
    fair = workers.FairPool(1, caps={})
    monkeypatch.setattr(workers, "_pool", fair)
    gate = threading.Event()
    fair.submit(gate.wait, owner=("pc", "drafts"), label="draft 12")
    fair.submit(time.sleep, 0, owner=("pc", "drafts"))
    fair.submit(time.sleep, 0, owner=("trek", "permuter"), label="read_tga")
    net = SimpleNamespace(drafter=Part(pc=SimpleNamespace(state="running", current="")),
                          permuter=Part(trek=SimpleNamespace(state="running", current=""),
                                        old=SimpleNamespace(state="done", current="")),
                          flagsurvey=Part(), twins=Part())
    jobs = Jobs()
    release = threading.Event()
    jid = jobs.start("deep-search", lambda log: (log.progress({"tested": 7, "best_score": 50, "start_score": 270}),
                                                 release.wait(10))[1])
    searches = SimpleNamespace(running={("trek", "aiChooseAttacker"): jid})
    deadline = time.monotonic() + 10
    while not jobs.jobs[jid].get("progress") and time.monotonic() < deadline:
        time.sleep(0.01)
    w = monitor.snapshot(net, jobs, searches)
    parts = {(p["project"], p["kind"]): p for p in w["parts"]}
    assert set(parts) == {("pc", "drafts"), ("trek", "permuter")}  # (not the permuter that's done)
    assert parts[("pc", "drafts")]["running"][0]["label"] == "draft 12" and parts[("pc", "drafts")]["queued"] == 1
    assert parts[("trek", "permuter")]["queued"] == 1 and parts[("trek", "permuter")]["running"] == []
    deep_job = next(j for j in w["jobs"] if j["id"] == jid)
    assert deep_job["label"] == "Deep search" and deep_job["function"] == "aiChooseAttacker"
    assert deep_job["progress"]["best_score"] == 50 and w["size"] == 1
    # Stop: the part stops and what it queued goes; a job is cancelled
    assert monitor.stop(net, jobs, "drafts", "pc") and net.drafter.stopped == ["pc"]
    assert ("pc", "drafts") not in {(r["project"], r["kind"]) for r in fair.snapshot() if r["queued"]}
    assert monitor.stop(net, jobs, "job", jid) and jobs.cancel_events[jid].is_set()
    assert not monitor.stop(net, jobs, "nothing", "pc")
    gate.set()
    release.set()
