"""What the app does in the background, for every project, and Stop for each (the Background work page).

A PC game's machine drafts held every shared worker for hours while another game's permuter waited behind them, and
nothing on screen said so: the permuter's line read as if it were working. From RetroReversing's fork (its
background work monitor), each part says here what it does: machine drafts, the permuter and the flag survey of each
project, its twins pass, deep searches on single functions and the app's other jobs, with the shared workers' queue
(workers.FairPool.snapshot): who works, and who waits for whom.
"""

from __future__ import annotations

import time

from . import workers

# the parts a project runs in the background: (kind, what it's called, the engine's attribute)
PARTS = (("drafts", "Machine drafts", "drafter"), ("permuter", "Permuter", "permuter"),
         ("survey", "Flag survey", "flagsurvey"), ("twins", "Twins", "twins"))
JOB_KINDS = {"deep-search": "Deep search", "compare": "Comparing compilers", "recheck": "Check again",
             "reimport": "Reimport", "import": "Import"}


def _running(job) -> bool:
    if job is None:
        return False
    if hasattr(job, "is_set"):  # (the flag survey's: an Event, set once it ends)
        return not job.is_set()
    return getattr(job, "state", None) == "running"


def snapshot(net, jobs=None, searches=None) -> dict:
    """{"parts": each project's background parts at work, "jobs": the app's running jobs (deep searches among them,
    with their progress), "workers": the shared workers' queue, "size": how many workers}."""
    pool = workers.pool()
    queue = {(r["project"], r["kind"]): r for r in pool.snapshot()}
    parts = []
    for kind, label, attr in PARTS:
        part = getattr(net, attr, None)
        for slug, job in list(getattr(part, "jobs", {}).items()):
            if not _running(job):
                continue
            row = {"kind": kind, "label": label, "project": slug, "queued": 0, "running": []}
            if (q := queue.get((slug, kind))) is not None:
                row.update(queued=q["queued"], running=q["running"])
            current = getattr(job, "current", "") or ""
            row["detail"] = current if isinstance(current, str) else ", ".join(current)
            parts.append(row)
    deep_jobs = {jid: key for key, jid in (searches.running.items() if searches is not None else [])}
    running = []
    for jid, job in list((jobs.jobs if jobs is not None else {}).items()):
        if job.get("state") != "running":
            continue
        key = deep_jobs.get(jid)
        running.append({"id": jid, "kind": job["kind"], "label": JOB_KINDS.get(job["kind"], job["kind"]),
                        "project": key[0] if key else "", "function": key[1] if key else "",
                        "seconds": round(time.time() - job["t"]), "progress": job.get("progress"),
                        "last": job["log"][-1] if job.get("log") else ""})
    return {"parts": sorted(parts, key=lambda r: (r["project"], r["kind"])), "jobs": running,
            "workers": pool.snapshot(), "size": pool.size}


def stop(net, jobs, kind: str, key: str) -> bool:
    """Stop a project's part (`kind` one of PARTS', `key` its project) or a job (`kind` "job", `key` its id)."""
    if kind == "job":
        return bool(jobs is not None and jobs.cancel(key))
    for name, _, attr in PARTS:
        if name == kind:
            getattr(net, attr).stop(key)
            workers.cancel((key, kind))
            return True
    return False
