"""The flag survey, in the background: every source file of a project whose files have flags of their own
(Console.file_flags: PC, V.Flash), built with the other flags its console's games were built with
(Console.survey_variants), on spare CPU. Where its open functions match with other flags as they are, and every
match holds, the file keeps them (ForkEngine.survey_file); where they'd break matched functions, the file is divided
first (it was two of the game's).

Why: on a V.Flash game, one file's open functions matched at -O1 as they were, while agents left notes about
register allocation ("tried register asm, c & 0xff, u32...") and the permuter took its four turns on them at -O3.
search_flags finds the same, but only when an agent thinks to ask, and only one function at a time.

A file is surveyed again only when its text or flags changed since (STATE/flag-survey.json). It runs on the
background workers the permuter and machine drafts share (workers.py), one file at a time, files with the most open
functions agents got close on first.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path

from ..forks.project import STATE
from ..network import NetworkError
from . import workers

log = logging.getLogger("decompdecomp")
FILE = "flag-survey.json"  # in the project's STATE folder: {source: what it was surveyed as}


class FlagSurvey:
    def __init__(self, net):
        self.net = net
        self.jobs: dict[str, threading.Event] = {}

    def start(self, slug: str) -> bool:
        """Survey the project's files in the background, once each (again when one changes). False when it can't
        run there (not a fork whose files have flags of their own, a room member's copy) or runs already."""
        if (fork := self.net.fork_slug(slug)) is None or fork in self.net.links:
            return False
        try:
            if not self.net.forks.takes_file_flags(fork):
                return False
        except NetworkError:
            return False
        if (stop := self.jobs.get(fork)) is not None and not stop.is_set():
            return False
        stop = self.jobs[fork] = threading.Event()
        threading.Thread(target=self._loop, args=(fork, stop), daemon=True, name=f"flag-survey-{fork}").start()
        return True

    def stop(self, slug: str) -> None:
        if (stop := self.jobs.get(slug)) is not None:
            stop.set()

    def todo(self, slug: str) -> list[str]:
        """The files to survey, most open near functions first: those whose text or flags changed since."""
        proj, fp, cfg = self.net.forks.get(slug)
        done = _read(fp.root)
        units = {u.name: u.source for u in fp.units() if u.source}
        counts: dict[str, int] = {}
        for r in self.net.store.all("SELECT unit, COUNT(*) AS n FROM functions WHERE project_id=? AND status='open' "
                                    "AND best_score IS NOT NULL GROUP BY unit", proj["id"]):
            if (source := units.get(r["unit"])) is not None:
                counts[source] = counts.get(source, 0) + r["n"]
        return [s for s in sorted(counts, key=lambda s: -counts[s]) if done.get(s) != _key(self.net, slug, fp, s)]

    def _loop(self, slug: str, stop: threading.Event) -> None:
        try:
            for source in self.todo(slug):
                if stop.is_set():
                    return
                try:
                    said = workers.pool().submit(self.net.forks.survey_file, slug, source).result()
                except NetworkError:
                    return  # the project is gone
                except Exception:  # one odd file must not stop the rest
                    log.info("flag survey: %s", source, exc_info=True)
                    said = None
                if said:
                    log.info("flag survey: %s", said)
                _, fp, _ = self.net.forks.get(slug)
                done = _read(fp.root)
                done[source] = _key(self.net, slug, fp, source)
                (Path(fp.root) / STATE / FILE).write_text(json.dumps(done, indent=1, sort_keys=True), encoding="utf-8")
        finally:
            stop.set()


def _read(root) -> dict:
    try:
        data = json.loads((Path(root) / STATE / FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _key(net, slug: str, fp, source: str) -> str:
    """What a file was surveyed as: its text and flags."""
    try:
        text = (Path(fp.root) / source).read_bytes()
    except OSError:
        text = b""
    flags = net.forks.file_flags_of(slug, source)
    return hashlib.sha1(text + json.dumps(flags).encode()).hexdigest()
