"""A file's data, handed out as a job: what's left once every function in a file matches.

A file is linked into the game once its whole object is the original's, its data too (strings, constants, tables,
globals). Agents claim functions, so a file whose last function matched was never anyone's again: the agent that
matched it was shown the data once, and moved on. A GameCube game's twelve files with every function matching sat
unlinked for good, from 32 to 264,000 bytes of data short. claim_function now gives such a file to one agent as a
data job (the files closest to linked first, under the "finish" order forks claim in by default): it writes the data
with edit_file, checks it with file_status, and once it matches, decompdecomp links the file (ForkEngine.link_soon,
from edit_file's _file_done) and the job is done.

Only where files are linked one by one and their data can be compared (a dtk-template project, GameCube and Wii):
COFF objects (PC, Xbox) give no data verdict. A room's members claim from the host, which hands out functions only:
the host's own agents do the data jobs (ROADMAP).
"""

from __future__ import annotations

import threading
import time

from elftools.common.exceptions import ELFError

from ..forks import datadiff
from ..network import IN_BUILD, Agent, NetworkError

CLAIM_SECONDS = 30 * 60  # a job is held this long from its claim or its holder's last edit of the file
# Files with more data than this left wait: a table of 81 KiB or a GBA program of 264 KiB in a GameCube game isn't a
# job for edit_file (ROADMAP: binary data as a file the source includes)
MOST_BYTES = 16 * 1024
TRIES = 3  # handed out this often (to another agent, or after a release) with its data still short: left as it is
DIFF_ROWS = 40


def bytes_left(sections: list[datadiff.Section]) -> int:
    """How much of a file's data isn't the original's yet: what's missing, different or only in yours."""
    return sum((x.size if x is not None else 0) + (y.size if y is not None and x is None else 0)
               for sec in sections for mark, x, y in sec.rows if mark != " ")


BRIEF = """DATA JOB (claimed): {source}

Every function in {source} matches. What keeps the file from being linked into the game (the goal: the game built
from this C, byte for byte) is its data: {left:,} bytes of it aren't the original's yet. Make its object hold the
original's data, in the same sections and order:
1. file_status("{source}") shows the file's data next to the original's (< missing from yours, > only yours,
   | different). Run it after each change.
2. read_data(name) reads what a global holds in the original: its bytes, as numbers, floats and strings.
3. edit_file("{source}", ...) defines the data in the file (headers for shared types): const tables go to .rodata,
   other initialised data to .data, zeroed globals to .bss; a static the original keeps inside a function
   (name$123) belongs inside that function; what this file's object defines is defined here, not declared extern.
   Literals the functions use come out in the order the functions use them. edit_file keeps a change only while
   every function still matches.
When the data matches, decompdecomp links the file into the game and edit_file says so; then claim_function for the
next job. Stuck: release_function("{source}", notes) with what you tried and what's left, for the next agent.
{notes}
The file's data now:
{diff}"""


class DataJobs:
    def __init__(self, forks):
        self.forks = forks
        self._held: dict[tuple[int, str], tuple[int, float]] = {}  # (project, source) -> (agent, until)
        self._lock = threading.Lock()
        self._left: dict[tuple, int | None] = {}  # (target, base, their mtimes) -> bytes left (None: no verdict)

    def _bytes_left(self, unit) -> int | None:
        """How much of a unit's data is short (None: its objects can't be compared, COFF or none built)."""
        if unit.target is None or not unit.target.exists():
            return None
        base = unit.base if unit.base is not None and unit.base.exists() else None
        key = (unit.target, base, unit.target.stat().st_mtime_ns, base.stat().st_mtime_ns if base else 0)
        if key not in self._left:
            try:
                self._left[key] = bytes_left(datadiff.compare(unit.target, base))
            except (ELFError, OSError, ValueError):
                self._left[key] = None
        return self._left[key]

    def todo(self, slug: str) -> list[tuple[str, int]]:
        """(source file, bytes of data left) of each file whose functions all match and whose data doesn't, not
        linked, with at most MOST_BYTES left and its tries not used up: the least left first."""
        proj, fp, _ = self.forks.get(slug)
        if slug in self.forks.net.links or not fp.linkable():
            return []
        rows = self.forks.net.store.all(
            "SELECT unit FROM functions WHERE project_id=? AND unit != '' AND " + IN_BUILD + " GROUP BY unit "
            "HAVING SUM(status='matched') = COUNT(*)", proj["id"])
        if not rows:
            return []
        states = fp.link_states()
        units = {u.name: u for u in fp.units()}
        tried = {r["detail"]: r["n"] for r in self.forks.net.store.all(
            "SELECT detail, COUNT(*) AS n FROM events WHERE project_id=? AND kind='data_job' GROUP BY detail", proj["id"])}
        left: dict[str, int] = {}
        for r in rows:
            u = units.get(r["unit"])
            if u is None or not u.source or states.get(u.source, ("",))[0] != "NonMatching":
                continue
            n = self._bytes_left(u)
            if n is None:
                left.pop(u.source, None)  # (no verdict for one of its units: none for the file)
                continue
            left[u.source] = left.get(u.source, 0) + n
        return sorted(((s, n) for s, n in left.items() if 0 < n <= MOST_BYTES and tried.get(s, 0) < TRIES),
                      key=lambda x: (x[1], x[0]))

    def left(self, slug: str) -> int:
        """How many data jobs there are, held ones included (a helper's session isn't over while one is)."""
        try:
            return len(self.todo(slug))
        except (NetworkError, OSError):
            return 0

    def held(self, agent: Agent, slug: str) -> str | None:
        """The file this agent holds a data job for, if any."""
        proj = self.forks.net._project(slug)
        now = time.time()
        with self._lock:
            return next((s for (pid, s), (who, until) in self._held.items()
                         if pid == proj["id"] and who == agent.id and until > now), None)

    def claim(self, agent: Agent, slug: str) -> str | None:
        """A data job for this agent (the one it holds, or the next nobody does), as its brief; None when there's
        none."""
        proj = self.forks.net._project(slug)
        todo = dict(self.todo(slug))
        now = time.time()
        with self._lock:
            self._held = {k: v for k, v in self._held.items() if v[1] > now}
            mine = next((s for (pid, s), (who, _) in self._held.items() if pid == proj["id"] and who == agent.id), None)
            if mine is not None and mine not in todo:  # (its data matches now, or it's out of tries)
                del self._held[(proj["id"], mine)]
                mine = None
            if mine is None:
                taken = {s for (pid, s) in self._held if pid == proj["id"]}
                mine = next((s for s in todo if s not in taken), None)
                if mine is None:
                    return None
                with self.forks.net.store.tx() as db:
                    self.forks.net._event(db, proj["id"], agent.id, "data_job", mine)
            self._held[(proj["id"], mine)] = (agent.id, now + CLAIM_SECONDS)
        return self.brief(slug, mine, todo[mine])

    def brief(self, slug: str, source: str, left: int) -> str:
        proj, fp, _ = self.forks.get(slug)
        notes = self.forks.net.store.all(
            "SELECT e.detail, a.name FROM events e LEFT JOIN agents a ON a.id=e.agent_id WHERE e.project_id=? AND "
            "e.kind='data_release' AND e.detail LIKE ? ORDER BY e.id DESC LIMIT 3", proj["id"], f"{source}: %")
        said = "".join(f"\n- {r['name'] or 'an agent'}: {r['detail'][len(source) + 2:]}" for r in notes)
        diff = []
        for u in fp.units_for(source):
            if u.target is not None and u.target.exists():
                try:
                    diff.append(datadiff.render(datadiff.compare(u.target, u.base), DIFF_ROWS))
                except (ELFError, OSError, ValueError) as e:
                    diff.append(f"(couldn't compare the data: {e})")
        return BRIEF.format(source=source, left=left, diff="\n".join(d for d in diff if d) or "(nothing differs)",
                            notes=f"\nWhat agents before you said:{said}\n" if said else "")

    def release(self, agent: Agent, slug: str, source: str, notes: str) -> str | None:
        """An agent gives up its data job (None when it holds no job for this file: a function's release, then)."""
        proj = self.forks.net._project(slug)
        with self._lock:
            held = self._held.get((proj["id"], source))
            if held is None or held[0] != agent.id:
                return None
            if not notes.strip():
                raise NetworkError("say in notes what you tried and what's left of the file's data, for the next agent")
            del self._held[(proj["id"], source)]
        with self.forks.net.store.tx() as db:
            self.forks.net._event(db, proj["id"], agent.id, "data_release", f"{source}: {notes.strip()[:800]}")
        return f"Released the data job for {source}; your notes are kept for the next agent. claim_function for the next."

    def after_edit(self, agent: Agent, slug: str, source: str) -> str:
        """After an edit of a file: the job renewed while its data is short, done once it matches. '' when this
        agent holds no job for it."""
        proj, fp, _ = self.forks.get(slug)
        key = (proj["id"], source)
        with self._lock:
            held = self._held.get(key)
            if held is None or held[0] != agent.id:
                return ""
            short = [n for u in fp.units_for(source) if (n := self._bytes_left(u))]
            if short:
                self._held[key] = (agent.id, time.time() + CLAIM_SECONDS)
                return f"\nData job: {sum(short):,} bytes of {source}'s data still aren't the original's (file_status shows which)."
            del self._held[key]
        with self.forks.net.store.tx() as db:
            self.forks.net._event(db, proj["id"], agent.id, "data_done", source)
        return f"\n✅ Data job done: {source}'s data matches. claim_function for the next."

