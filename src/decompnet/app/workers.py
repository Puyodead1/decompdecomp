"""The background workers machine drafts (drafts.py), the permuter (permute.py) and the flag survey (flagsurvey.py)
share, for every project.

One pool, so "up to four workers" holds for the app as a whole: each part with a pool of its own made eight threads
on a big computer, beside the agents' compiles. Each worker lowers its own CPU priority as it starts (on Linux a
thread's own, inherited by what it runs; on macOS, the thread's QoS), so the app and
the agents come first.

The pool takes turns: each piece of work has an owner (its project and its kind: "drafts", "permuter", "survey"),
and a free worker takes the next owner's oldest piece in turn, not the oldest piece of all. A first-come pool let a
PC game's machine drafts (Ghidra, minutes each, 687 of them) hold all four workers for hours while another game's
permuter waited behind them, with no sign of it anywhere. Drafts also never hold every worker (KIND_CAPS), stopping
a part drops what it has queued (cancel), and snapshot() says who waits and who works.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor  # noqa: F401  (ThreadPoolExecutor: tests' stand-ins)

RESERVED_CORES = 2  # left to the app itself and the agents' compiles
# Past four, the judge's own Python work (about 5 ms of a variant's 16, under the interpreter's one lock) is the
# limit, not the cores, and the app itself waits for that lock. Demo ROM, 12 cores: 1 worker judged 80 variants a
# second, 2 129, 4 172, 8 193; a GUI request took 0.1 ms alone, 6 ms beside 4 workers, 31 ms beside 8.
MAX_WORKERS = 4
WORKERS = max(1, min(MAX_WORKERS, (os.cpu_count() or 1) - RESERVED_CORES))
NICE = 10  # how much lower the workers' CPU priority is

_pool: FairPool | None = None
_lock = threading.Lock()


def _lower_priority() -> None:
    """Lower only this worker, without lowering the GUI or the agent threads beside it."""
    if os.name == "nt":
        import ctypes

        kernel = ctypes.windll.kernel32
        kernel.GetCurrentThread.restype = ctypes.c_void_p
        kernel.SetThreadPriority.argtypes = (ctypes.c_void_p, ctypes.c_int)
        kernel.SetThreadPriority(kernel.GetCurrentThread(), -1)  # THREAD_PRIORITY_BELOW_NORMAL
    elif sys.platform == "darwin":
        import ctypes

        # Darwin's nice value belongs to the process, so os.nice would slow the GUI too.
        # Set this worker's QoS instead. Utility threads still let the interactive window run first.
        system = ctypes.CDLL(None)
        system.pthread_set_qos_class_self_np.argtypes = (ctypes.c_uint, ctypes.c_int)
        system.pthread_set_qos_class_self_np(0x11, 0)  # QOS_CLASS_UTILITY
    else:
        os.nice(NICE)


# what one kind of work may hold at once: machine drafts leave a worker for the permuter and the flag survey
KIND_CAPS = {"drafts": max(1, WORKERS - 1)}
OTHER = ("", "other")  # the owner of work submitted without one


class FairPool:
    """WORKERS threads at a lower CPU priority, taking turns between owners ((project, kind)), each owner's work in
    the order it came. submit() returns a concurrent.futures.Future, so wait() and result() work as with an
    executor."""

    def __init__(self, workers: int = WORKERS, caps: dict[str, int] | None = None):
        self.size = workers
        self.caps = dict(KIND_CAPS if caps is None else caps)
        self._cv = threading.Condition()
        self._queues: dict[tuple, deque] = {}
        self._order: deque = deque()  # owners with queued work, the next to be served first
        self._running: dict[int, tuple] = {}  # thread id -> (owner, label, started)
        self._threads: list[threading.Thread] = []

    def submit(self, fn, *args, owner: tuple = OTHER, label: str = "") -> Future:
        future: Future = Future()
        with self._cv:
            self._queues.setdefault(owner, deque()).append((future, fn, args, label))
            if owner not in self._order:
                self._order.append(owner)
            if len(self._threads) < self.size:
                t = threading.Thread(target=self._work, daemon=True, name=f"background-worker_{len(self._threads)}")
                self._threads.append(t)
                t.start()
            self._cv.notify()
        return future

    def _take(self):
        """The next owner's oldest piece of work that its kind's cap allows, or None (under the lock)."""
        busy: dict[str, int] = {}
        for owner, _, _ in self._running.values():
            busy[owner[1]] = busy.get(owner[1], 0) + 1
        for _ in range(len(self._order)):
            owner = self._order[0]
            self._order.rotate(-1)  # (served or not, the next one is next)
            queue = self._queues.get(owner)
            if not queue:
                continue
            if (cap := self.caps.get(owner[1])) is not None and busy.get(owner[1], 0) >= cap:
                continue
            job = queue.popleft()
            if not queue:
                del self._queues[owner]
                self._order.remove(owner)
            return owner, job
        return None

    def _work(self) -> None:
        _lower_priority()
        me = threading.get_ident()
        while True:
            with self._cv:
                while (taken := self._take()) is None:
                    self._cv.wait()
                owner, (future, fn, args, label) = taken
                self._running[me] = (owner, label, time.time())
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        future.set_result(fn(*args))
                    except BaseException as e:  # (the future carries it to whoever waits)
                        future.set_exception(e)
            finally:
                with self._cv:
                    self._running.pop(me, None)
                    self._cv.notify_all()  # (a kind under its cap again may have work waiting)

    def cancel(self, owner: tuple) -> int:
        """Drop an owner's queued work (what runs finishes): how many pieces were dropped."""
        with self._cv:
            queue = self._queues.pop(owner, deque())
            if owner in self._order:
                self._order.remove(owner)
        for future, *_ in queue:
            future.cancel()
        return len(queue)

    def snapshot(self) -> list[dict]:
        """Each owner with work: how much waits, and what runs (its label, for how long)."""
        now = time.time()
        with self._cv:
            out: dict[tuple, dict] = {}
            for owner, queue in self._queues.items():
                out.setdefault(owner, {"project": owner[0], "kind": owner[1], "queued": 0, "running": []})["queued"] = len(queue)
            for owner, label, started in self._running.values():
                out.setdefault(owner, {"project": owner[0], "kind": owner[1], "queued": 0, "running": []})[
                    "running"].append({"label": label, "seconds": round(now - started)})
        return sorted(out.values(), key=lambda r: (r["project"], r["kind"]))

    def waiting(self, owner: tuple) -> dict:
        """What an owner waits for: its queued pieces, and the other owners' work running on the workers now."""
        with self._cv:
            queued = len(self._queues.get(owner, ()))
            others = sorted({f"{o[0]} ({o[1]})" if o[0] else o[1] for o, _, _ in self._running.values() if o != owner})
            mine = sum(o == owner for o, _, _ in self._running.values())
        return {"queued": queued, "running": mine, "busy_with": others}


def pool() -> FairPool:
    """The shared workers, started the first time something needs them."""
    global _pool
    with _lock:
        if _pool is None:
            _pool = FairPool()
        return _pool


def submit(owner: tuple, fn, *args, label: str = "") -> Future:
    """fn(*args) on the shared workers, as `owner`'s ((project, kind)) work."""
    return pool().submit(fn, *args, owner=owner, label=label)


def cancel(owner: tuple) -> int:
    with _lock:
        live = _pool
    return live.cancel(owner) if live is not None else 0
