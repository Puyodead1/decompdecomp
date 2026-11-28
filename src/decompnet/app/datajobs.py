"""A file's data, handed out as a job: what's left once every function in a file matches.

A file is linked into the game once its whole object is the original's, its data too (strings, constants, tables,
globals). Agents claim functions, so a file whose last function matched was never anyone's again: the agent that
matched it was shown the data once, and moved on. A GameCube game's twelve files with every function matching sat
unlinked for good, from 32 to 264,000 bytes of data short. claim_function now gives such a file to one agent as a
data job (the files closest to linked first, under the "finish" order forks claim in by default): it writes the data
with edit_file, checks it with file_status, and once it matches, decompdecomp links the file (ForkEngine.link_soon,
from edit_file's _file_done) and the job is done.

Only where files are linked one by one and their data can be compared (a dtk-template project, GameCube and Wii):
COFF objects (PC, Xbox) give no data verdict. In a room the host holds the jobs: /collab/claim hands a member's agent
one as it does its own (ForkEngine.claim_work), the member's edits are made on the host already (/collab/edit), its
release goes there too, and the host's list of jobs comes with its state (the member's link.data_jobs), so a member's
helpers keep working while jobs are left. A room's guests found "nothing left" while the host's files waited.
"""

from __future__ import annotations

import threading
import time

from elftools.common.exceptions import ELFError

from ..forks import datadiff
from ..forks.project import config_changed
from ..network import IN_BUILD, Agent, NetworkError

CLAIM_SECONDS = 30 * 60  # a job is held this long from its claim or its holder's last edit of the file
# Files with more than this left to write wait (ROADMAP: binary data as a file the source includes). What's left is
# counted in what an agent writes: initialised bytes, and ZEROED for each zeroed global (.bss), one definition whatever
# its size. Counted by size, a GameCube game's six files with 23 to 264 KiB "left" waited, all of it .bss but 2 KiB
MOST_BYTES = 16 * 1024
ZEROED = 8
# Agents (each counted once) a job is handed to, since the project's split config last changed, before it's left as
# it is. Counted by claim, a GameCube game's files ran out of tries on leases that ran out and on the app's restarts,
# for good, and its helpers stopped with files unlinked.
TRIES = 3
DIFF_ROWS = 40
LISTED_SECONDS = 10  # a room's members get the host's list of jobs this fresh
# The start of a link failure that is the data step's (ForkEngine.link): decompdecomp couldn't give the file its data,
# which no edit of the file's C fixes. A GameCube game's helpers were handed such files as data jobs, three times each.
NOT_GIVEN = "Its data couldn't be given to it"
# Why a file whose functions are all matched or set aside isn't linked and isn't a job (Verdict.why's kinds), as the
# helpers' stop message says it
BLOCKED = {"set_aside": "hold set-aside code (a file with set-aside code doesn't link yet)",
           "no_data": "couldn't be given their data by decompdecomp (the files' page says why)",
           "too_big": f"have more than {MOST_BYTES // 1024} KiB of data left to write (more than a data job holds)",
           "tries": f"had their data job tried by {TRIES} agents without matching",
           "unbuilt": "have no object to compare (the project's last build didn't make it)"}


def bytes_left(sections: list[datadiff.Section]) -> int:
    """How much of a file's data is left to write: what's missing, different or only in yours, in bytes for
    initialised data and ZEROED for each zeroed global."""
    def cost(item: datadiff.Item) -> int:
        return ZEROED if item.data is None else item.size

    return sum(cost(x) if x is not None else cost(y) for sec in sections for mark, x, y in sec.rows
               if mark != " " and (x or y) is not None)


BRIEF = """DATA JOB (claimed): {source}

Every function in {source} matches. What keeps the file from being linked into the game (the goal: the game built
from this C, byte for byte) is its data, about {left:,} bytes of it left to write (a zeroed global counts {zeroed}: one
definition, whatever its size). Make its object hold the original's data, in the same sections and order:
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
        self._listed: dict[str, tuple[float, list[dict]]] = {}  # slug -> (when, listing): a room's state asks often

    def _link(self, slug: str):
        """The room this copy is a member of, for this project (None: it holds its own jobs)."""
        return self.forks.net.links.get(slug)

    @staticmethod
    def _host_name(link, agent: Agent) -> str:
        """The name the host knows one of this member's agents by (Room.agent_for)."""
        from .collab import member_label

        return f"{link.member}.{member_label(agent.name)}"

    def _bytes_left(self, unit, alike: bool = True) -> int | None:
        """How much of a unit's data is left to write (bytes_left; None: its objects can't be compared, COFF or none
        built). `alike`: none when it's the original's bytes, only named or cut differently (datadiff.same_layout):
        the link decides, and a GameCube game's helpers got jobs no C could finish, a symbol's size in the project's
        config. Not for a file whose link failed: what's left is then the names its job's brief shows."""
        if unit.target is None or not unit.target.exists():
            return None
        base = unit.base if unit.base is not None and unit.base.exists() else None
        key = (unit.target, base, unit.target.stat().st_mtime_ns, base.stat().st_mtime_ns if base else 0, alike)
        if key not in self._left:
            try:
                if alike and datadiff.same_layout(unit.target, base):
                    n = 0
                elif not (n := bytes_left(datadiff.compare(unit.target, base))):
                    # nothing to write by name, and still not the original's layout: strings aligned differently, a
                    # table pointing into code that moved. A GameCube game's such files were nobody's job and never
                    # linked; one whose link failed is a job too, the failure in its brief.
                    n = datadiff.layout(unit.target, base)[0] or (0 if alike else 1)
                self._left[key] = n
            except (ELFError, OSError, ValueError):
                self._left[key] = None
        return self._left[key]

    def verdicts(self, slug: str) -> dict[str, tuple[str, int, str]]:
        """What each file not linked yet with no open function waits for, one answer every caller reads (the jobs,
        the helpers' stop, the files' page): source -> (state, bytes of data left, why). state: "job" (an agent's to
        write), "link" (nothing left to write: the link decides), or a BLOCKED kind. A GameCube game's helpers said
        "nothing left to decompile here 🎉" with 49 of its 80 files unlinked: files with set-aside code, out of tries
        or too big were no job and nobody's word."""
        proj, fp, cfg = self.forks.get(slug)
        if slug in self.forks.net.links or not fp.linkable():
            return {}
        failed = self.forks.link_failures(fp.root, cfg)
        rows = self.forks.net.store.all(
            "SELECT unit, COUNT(*) AS n, SUM(status='matched') AS won FROM functions WHERE project_id=? AND unit != '' "
            "AND " + IN_BUILD + " GROUP BY unit HAVING SUM(status='open' AND aside_mark IS NULL AND copy_mark IS NULL) = 0",
            proj["id"])
        if not rows:
            return {}
        states = fp.link_states()
        units = {u.name: u for u in fp.units()}
        tries = self._tries(proj, fp.root)
        out: dict[str, tuple[str, int, str]] = {}
        for r in rows:
            u = units.get(r["unit"])
            if u is None or not u.source or states.get(u.source, ("",))[0] != "NonMatching":
                continue
            was = out.get(u.source, ("job", 0, ""))
            if was[0] not in ("job", "link"):
                continue  # (blocked by another of its units)
            why = failed.get(u.source, "")
            if r["won"] < r["n"]:
                aside = r["n"] - r["won"]
                out[u.source] = ("set_aside", 0, f"{aside} of its functions {'are' if aside != 1 else 'is'} set aside")
                continue
            if why.startswith(NOT_GIVEN):
                out[u.source] = ("no_data", 0, why)
                continue
            n = self._bytes_left(u, alike=not why)
            if n is None:
                out[u.source] = ("unbuilt", 0, "its object or the original's couldn't be read")
                continue
            out[u.source] = ("job", was[1] + n, "")
        for source, (state, n, why) in out.items():
            if state != "job":
                continue
            if not n:
                out[source] = ("link", 0, "")
            elif n > MOST_BYTES:
                out[source] = ("too_big", n, f"{n:,} bytes of data left to write")
            elif tries.get(source, 0) >= TRIES:
                out[source] = ("tries", n, f"{tries[source]} agents had its data job")
        return out

    def _tries(self, proj, root) -> dict[str, int]:
        """How many agents each file's data job was handed to since the split config last changed (TRIES)."""
        return {r["detail"]: r["n"] for r in self.forks.net.store.all(
            "SELECT detail, COUNT(DISTINCT agent_id) AS n FROM events WHERE project_id=? AND kind='data_job' "
            "AND created_at >= ? GROUP BY detail", proj["id"], config_changed(root))}

    def todo(self, slug: str) -> list[tuple[str, int]]:
        """(source file, bytes of data left) of each file whose functions all match and whose data doesn't, not
        linked, with at most MOST_BYTES left and its tries not used up: the least left first."""
        return sorted(((s, n) for s, (state, n, _) in self.verdicts(slug).items() if state == "job"),
                      key=lambda x: (x[1], x[0]))

    def blocked(self, slug: str) -> dict[str, list[tuple[str, str]]]:
        """The files that can't be linked and are no job, by BLOCKED kind: [(source, why)]."""
        out: dict[str, list[tuple[str, str]]] = {}
        try:
            verdicts = self.verdicts(slug)
        except (NetworkError, OSError):
            return out
        for source, (state, _, why) in sorted(verdicts.items()):
            if state in BLOCKED:
                out.setdefault(state, []).append((source, why))
        return out

    def _free(self, proj, agent: Agent, sources) -> list[str]:
        """The jobs among these a claim by this agent may get: none held by another, none it released itself lately
        (network.SELF_RELEASE_WINDOW, as for functions). claim and takeable both ask this: takeable said a released
        job was waiting, claim kept the agent off it for good, and a GameCube game's helpers started sessions that
        found nothing, then paused after five."""
        now = time.time()
        with self._lock:
            others = {s for (pid, s), (who, until) in self._held.items()
                      if pid == proj["id"] and who != agent.id and until > now}
        with self.forks.net.store.tx() as db:
            cutoff = self.forks.net._own_release_cutoff(db, agent.id, now)
            released = {r["detail"].split(": ", 1)[0] for r in db.execute(
                "SELECT detail FROM events WHERE project_id=? AND agent_id=? AND kind='data_release' AND created_at > ?",
                (proj["id"], agent.id, cutoff))}
        return [s for s in sources if s not in others and s not in released]

    def listing(self, slug: str) -> list[dict]:
        """The jobs, for a room's members: {"source", "left", "agent": who holds it, None for nobody}. Kept for
        LISTED_SECONDS: every member's state asks."""
        now = time.time()
        if (got := self._listed.get(slug)) is not None and now - got[0] < LISTED_SECONDS:
            return got[1]
        proj = self.forks.net._project(slug)
        with self._lock:
            held = {s: who for (pid, s), (who, until) in self._held.items() if pid == proj["id"] and until > now}
        names = {r["id"]: r["name"] for r in self.forks.net.store.all(
            f"SELECT id, name FROM agents WHERE id IN ({','.join('?' * len(held)) or 'NULL'})", *held.values())}
        out = [{"source": s, "left": n, "agent": names.get(held[s]) if s in held else None} for s, n in self.todo(slug)]
        self._listed[slug] = (now, out)
        return out

    def left(self, slug: str) -> int:
        """How many data jobs there are, held ones included (a helper's session isn't over while one is)."""
        if (link := self._link(slug)) is not None:
            return len(link.data_jobs)
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

    def takeable(self, agent: Agent, slug: str) -> bool:
        """Whether a claim by this agent would get a data job now: it holds one, or one nobody holds is waiting (not
        for a helper with a work selection: ForkEngine.claim hands those functions only). Helpers whose open functions
        were all held by others or given up waited for one instead (Manager._all_given_up), with six files' data
        waiting for them."""
        if self.forks.net.selection(slug, agent.name):
            return False
        if (link := self._link(slug)) is not None:  # (the host's jobs, from its last state)
            return any(j.get("agent") in (None, self._host_name(link, agent)) for j in link.data_jobs)
        try:
            todo = self.todo(slug)
        except (NetworkError, OSError):
            return False
        return bool(self._free(self.forks.net._project(slug), agent, [s for s, _ in todo]))

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
            # (not one this agent gave back lately: every claim handed a helper the job it had just released)
            free = self._free(proj, agent, list(todo))
        with self._lock:
            if mine is None:
                taken = {s for (pid, s) in self._held if pid == proj["id"]}
                mine = next((s for s in free if s not in taken), None)
                if mine is None:
                    return None
                with self.forks.net.store.tx() as db:
                    self.forks.net._event(db, proj["id"], agent.id, "data_job", mine)
            self._held[(proj["id"], mine)] = (agent.id, now + CLAIM_SECONDS)
            self._listed.pop(slug, None)
        return self.brief(slug, mine, todo[mine])

    def brief(self, slug: str, source: str, left: int) -> str:
        proj, fp, cfg = self.forks.get(slug)
        notes = self.forks.net.store.all(
            "SELECT e.detail, a.name FROM events e LEFT JOIN agents a ON a.id=e.agent_id WHERE e.project_id=? AND "
            "e.kind='data_release' AND e.detail LIKE ? ORDER BY e.id DESC LIMIT 3", proj["id"], f"{source}: %")
        said = "".join(f"\n- {r['name'] or 'an agent'}: {r['detail'][len(source) + 2:]}" for r in notes)
        diff = []
        for u in fp.units_for(source):
            if u.target is not None and u.target.exists():
                try:
                    diff.append(datadiff.render(datadiff.compare(u.target, u.base), DIFF_ROWS))
                    if lines := datadiff.layout(u.target, u.base)[1]:
                        diff.append("How the object differs from the original's, names aside:\n"
                                    + "\n".join(f"- {line}" for line in lines[:12]))
                except (ELFError, OSError, ValueError) as e:
                    diff.append(f"(couldn't compare the data: {e})")
        if causes := self.forks.link_causes(fp, source):
            diff.append("What keeps the file's objects from linking (whatever the data above says):\n" + causes.text())
        if why := self.forks.link_failures(fp.root, cfg).get(source):  # (its data is the original's bytes, and it still didn't)
            said += f"\n- decompdecomp's last try to link it failed (the game didn't build identically):\n{why[-1500:]}"
        return BRIEF.format(source=source, left=left, zeroed=ZEROED, diff="\n".join(d for d in diff if d) or "(nothing differs)",
                            notes=f"\nWhat agents before you said:{said}\n" if said else "")

    def release(self, agent: Agent, slug: str, source: str, notes: str) -> str | None:
        """An agent gives up its data job (None when it holds no job for this file: a function's release, then)."""
        if (link := self._link(slug)) is not None:  # (the host holds the room's jobs)
            _, fp, _ = self.forks.get(slug)
            if not fp.units_for(source):
                return None
            said = link.call("/collab/release", agent, function=source, notes=notes, data_job=True)
            self._listed.pop(slug, None)
            return said
        proj = self.forks.net._project(slug)
        with self._lock:
            held = self._held.get((proj["id"], source))
            if held is None or held[0] != agent.id:
                return None
            if not notes.strip():
                raise NetworkError("say in notes what you tried and what's left of the file's data, for the next agent")
            del self._held[(proj["id"], source)]
            self._listed.pop(slug, None)
        with self.forks.net.store.tx() as db:
            self.forks.net._event(db, proj["id"], agent.id, "data_release", f"{source}: {notes.strip()[:800]}")
        return f"Released the data job for {source}; your notes are kept for the next agent. claim_function for the next."

    def after_edit(self, agent: Agent, slug: str, source: str) -> str:
        """After an edit of a file: the job renewed while its data is short, done once it matches. '' when this
        agent holds no job for it."""
        proj, fp, cfg = self.forks.get(slug)
        key = (proj["id"], source)
        # judged as todo judges it: a job only because its link failed isn't done when its bytes are the original's
        alike = source not in self.forks.link_failures(fp.root, cfg)
        with self._lock:
            held = self._held.get(key)
            if held is None or held[0] != agent.id:
                return ""
            short = [n for u in fp.units_for(source) if (n := self._bytes_left(u, alike=alike))]
            if short:
                self._held[key] = (agent.id, time.time() + CLAIM_SECONDS)
                return f"\nData job: about {sum(short):,} bytes of {source}'s data are still left to write (file_status shows which)."
            del self._held[key]
            self._listed.pop(slug, None)
        with self.forks.net.store.tx() as db:
            self.forks.net._event(db, proj["id"], agent.id, "data_done", source)
        return f"\n✅ Data job done: {source}'s data matches. claim_function for the next."

