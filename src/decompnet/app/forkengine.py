"""Fork projects: continue a public decomp with your agents, inside the project's own source tree.

Progress comes from objdiff reports. Agents claim functions (so parallel agents never collide), write them into
the project's real source files, build just that unit with the project's own build system and let objdiff judge.
A 100% match is committed to a local git branch, ready for the user to push or open a pull request with.
Guards from people who ran agents on decomps before: agents can only write C/C++ sources and headers (never
targets, assembly, configs or build scripts), inline assembly is refused, and a header edit is undone if it costs a
single match.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from bisect import bisect_left
from collections import defaultdict
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from elftools.common.exceptions import ELFError

from .. import __version__, arch, classes, coffobj, consoles, seeds, similarity, structs, toolchains
from ..arch import advice as arch_advice
from ..forks import (
    convention,
    csource,
    datadiff,
    dolcheck,
    drafts,
    dtkdata,
    dtksplits,
    ghidra,
    identity,
    ltcg,
    methods,
    objdiff,
    standins,
    unresolved,
)
from ..forks.objdiff import MappingConflict, ObjdiffError
from ..forks.project import (
    EDITABLE,
    GAME,
    PROGRAM,
    SCOPES,
    STATE,
    UNIT_SECONDS,
    ForkError,
    ForkProject,
    config_changed,
    project_macro,
)
from ..hostenv import NO_WINDOW
from ..network import (
    ASM_PAGE,
    BRIEF_CHARS,
    COPY,
    GAME_CODE,
    IN_BUILD,
    NOT_C_AGENTS,
    NOT_C_MODELS,
    PROGRESS_COLUMNS,
    Agent,
    Network,
    NetworkError,
    asm_page,
    fit_brief,
    model_of,
    move_on_brief,
    set_aside,
    state_text,
    tried_brief,
)
from ..rom import RomError
from ..scoring import percent_text
from ..textedit import replace_once
from . import datajobs
from .collab import Refused
from .datajobs import DataJobs
from .engine.compilers import ROOM_COMPILER

_REPO = re.compile(r"^(https://(github\.com|gitlab\.com|codeberg\.org|git\.[\w.-]+)/[\w.-]+/[\w.-]+?)(\.git)?/?$")
# A match has to come from C/C++: no inline assembly, asm functions, asm includes or embedded binaries.
def _path_glob(glob: str) -> str:
    """A shell-style pattern an agent wrote, as pathlib takes it: `**` only as a whole path component
    ("src/**.cpp" -> "src/**/*.cpp", "src**/x.h" -> "src*/**/x.h"; pathlib raised ValueError on those)."""
    glob = glob.strip().lstrip("/")
    glob = re.sub(r"(?<=[^/])\*\*", "*/**", glob)
    return re.sub(r"\*\*(?=[^/])", "**/*", glob)


_CHEAT = re.compile(r"\b(__asm__|__asm|asm|_asm)\b|INCLUDE_ASM|GLOBAL_ASM|INCLUDE_RODATA|\.incbin|#\s*include\s*[\"<][^\">]*\.(s|S|asm|bin|inc\.c)[\">]")


# `register int x asm("r4");` binds a variable to a register: an accepted matching technique (pret's GBA
# projects use it), not assembly code, so it doesn't count as inline asm.
_REGVAR = re.compile(r"\b(?:asm|__asm__|__asm)\s*\(\s*\"\$?[a-z]{1,2}\d{0,2}\"\s*\)", re.I)


# A typed extern with an assembler *name* changes linkage only; it emits no assembly.
# Keep this grammar narrow so instruction strings/extended asm still fail the check.
_LINKAGE_DECL = re.compile(
    r'\bextern\s+__typeof__\s*\(\s*[A-Za-z_]\w*\s*\)\s+[A-Za-z_]\w*\s+'
    r'__asm__\s*\(\s*"[A-Za-z_]\w*"\s*\)\s*'
    r'__attribute__\s*\(\(\s*visibility\s*\(\s*"hidden"\s*\)\s*\)\)\s*;')


def _strip_comments(code: str) -> str:
    return _REGVAR.sub(" ", _LINKAGE_DECL.sub(" ", re.sub(r"//[^\n]*|/\*.*?\*/", " ", code, flags=re.S)))


def _rewrite(path: Path, text: str) -> None:
    """`path.write_text(text, encoding="utf-8")`, the same bytes, writing only from the first 4 KB block that differs.
    A compile writes the agent's version of a unit's source and an undo writes the original back: a dtk unit can be
    a megabyte, and only the part from the changed function on is new. An unchanged file is only touched, so a build
    still sees it as new."""
    data = text.replace("\n", os.linesep).encode("utf-8")  # as text mode writes it
    try:
        with open(path, "r+b") as f:
            old = f.read()
            if old == data:
                os.utime(path)
                return
            at = 0
            while old[at:at + 4096] == data[at:at + 4096]:
                at += 4096
            f.seek(at)
            f.write(data[at:])
            f.truncate()
    except FileNotFoundError:
        path.write_bytes(data)


def _config_stamp(root: Path, globs: tuple[str, ...]) -> tuple | None:
    """When each file a project's compilers and file ranges are read from last changed: objdiff.json (its source
    files) and the console's (Console.compiler_config). None while one changed just now: a second write within the
    file system's clock tick could leave the same stamp (git's "racy" files)."""
    out, recent = [], time.time_ns() - 2_000_000_000
    for path in (root / "objdiff.json", *(p for glob in globs for p in sorted(root.glob(glob)))):
        try:
            info = path.stat()
        except OSError:
            out.append((path, None))
            continue
        if info.st_mtime_ns > recent:
            return None
        out.append((path, info.st_mtime_ns, info.st_size, info.st_ino))
    return tuple(out)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "fork"


def objdiff_diff(fp: ForkProject, unit, symbol: str, target_only: bool = False):
    from ..forks import objdiff

    if not target_only:
        return fp.diff(unit, symbol)
    return objdiff.diff(unit.target, None, symbol, cwd=fp.root, options=fp.diff_options(unit))


def scaled(fuzzy: float | None, n_insns: int) -> int:
    """objdiff's match percentage as a score on the engine's scale (0 = matched)."""
    if fuzzy is None:
        return n_insns * 100
    return 0 if fuzzy >= 100 else max(1, round((1 - fuzzy / 100) * n_insns * 100))


class _UnitLock:
    """A source file's lock (re-entrant, like threading.RLock) that says when another thread waits for it: a
    permuter turn holding the file for a minute lets go early then. A deep search's turns on a GameCube game's file of
    200 functions held up the agents' edits and the room's confirmations in that file, and a room guest's requests
    gave up at 60 s, as if the host had gone."""

    def __init__(self):
        self._lock = threading.RLock()
        self._count = threading.Lock()
        self._waiting = 0

    @property
    def wanted(self) -> bool:
        return self._waiting > 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if self._lock.acquire(False):  # (free, or this thread's already: never counted as waiting)
            return True
        if not blocking:
            return False
        with self._count:
            self._waiting += 1
        try:
            return self._lock.acquire(True, timeout)
        finally:
            with self._count:
                self._waiting -= 1

    def release(self) -> None:
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()


class _TreeLock:
    """Work on different source files runs side by side; a change any file may depend on (a header) runs alone.
    A thread that holds it exclusively may take it again either way."""

    def __init__(self):
        self._cond = threading.Condition()
        self._readers = 0
        self._writer: int | None = None
        self._waiting = 0
        self._mine = threading.local()

    @property
    def wanted(self) -> bool:
        """Whether something waits to take it exclusively: from then on nobody new takes it shared, so a long holder
        (the permuter's turn) lets go early, or everything waits for it."""
        return self._waiting > 0

    @contextmanager
    def shared(self):
        me = threading.get_ident()
        depth = getattr(self._mine, "depth", 0)
        if self._writer == me or depth:
            self._mine.depth = depth + 1
            try:
                yield
            finally:
                self._mine.depth -= 1
            return
        with self._cond:
            while self._writer is not None or self._waiting:
                self._cond.wait()
            self._readers += 1
        self._mine.depth = 1
        try:
            yield
        finally:
            self._mine.depth = 0
            with self._cond:
                self._readers -= 1
                self._cond.notify_all()

    @contextmanager
    def exclusive(self):
        me = threading.get_ident()
        if self._writer == me:
            yield
            return
        if getattr(self._mine, "depth", 0):
            raise RuntimeError("a shared holder can't take the tree exclusively")
        with self._cond:
            self._waiting += 1
            while self._writer is not None or self._readers:
                self._cond.wait()
            self._waiting -= 1
            self._writer = me
        try:
            yield
        finally:
            with self._cond:
                self._writer = None
                self._cond.notify_all()


BATCH_UNITS = 16  # units one run of a project's build takes at most


class _UnitBuilds:
    """One project's unit builds, which take turns (ninja's log is the tree's): the builds asked for while one runs
    go together in the next run (ForkProject.build_units), as many as BATCH_UNITS. The four permuter workers and the
    agents of a project took turns one unit at a time: on an x86 game's LTCG units 8 built one by one took 5.6 s,
    in one run 1.3 s. A build asked for while a run is going waits for the next run: what that run builds may be
    an older copy of its file. Whoever finds no run going builds the next batch, its own build among them or not."""

    @dataclass(eq=False)
    class _Ask:
        unit: object
        result: tuple[bool, str] | None = None
        error: BaseException | None = None
        shared: bool = False  # the error is the whole run's, raised in each of its threads

    def __init__(self):
        self._cond = threading.Condition()
        self._queue: list = []
        self._running = False

    def build(self, unit, run) -> tuple[bool, str]:
        """`unit` built in the next run of `run` (units -> one (ok, log) each, in order)."""
        ask = self._Ask(unit)
        with self._cond:
            self._queue.append(ask)
        while True:
            with self._cond:
                while ask.result is None and ask.error is None and self._running:
                    self._cond.wait()
                if ask.result is not None or ask.error is not None:
                    break
                self._running = True
                batch, self._queue = self._queue[:BATCH_UNITS], self._queue[BATCH_UNITS:]
            try:
                results = run([a.unit for a in batch])
                if len(results) != len(batch):
                    raise RuntimeError(f"a build of {len(batch)} units said {len(results)} results")
                for a, r in zip(batch, results):
                    if isinstance(r, BaseException):  # its own build raised (build_units): its caller's alone
                        a.error, a.shared = r, False
                    else:
                        a.result = r
            except BaseException as e:  # each of the batch hears it, as a build of its own would have raised it
                for a in batch:
                    a.error, a.shared = e, True
            finally:
                with self._cond:
                    self._running = False
                    self._cond.notify_all()
        if ask.error is None:
            return ask.result
        if not ask.shared:
            raise ask.error
        # each thread raises a copy of its own: raising the one exception in every thread of the batch writes each
        # one's frames into its traceback, side by side (one that can't be copied still is, but nothing else of it
        # is changed)
        try:
            mine = copy.copy(ask.error)
        except Exception:  # noqa: BLE001
            raise ask.error  # noqa: B904
        raise mine.with_traceback(None) from ask.error


_BUILD_ERROR = re.compile(r"\berror\b|^FAILED:|fatal|undefined reference|unresolved external", re.I)


def _matched_in(rep: dict) -> set[tuple[str, str]]:
    """(unit, function) of every function an objdiff report has matching."""
    return {(u["name"], f["name"]) for u in rep.get("units", []) for f in u.get("functions", [])
            if float(f.get("fuzzy_match_percent") or 0) >= 100}


_ADDRESS_NAMED = re.compile(r"(\w+)_([0-9A-F]{8})")


def _named_back(lost: set[tuple[str, str]], rep: dict) -> dict[tuple[str, str], str]:
    """{(unit, name_<address>): name} for each lost function whose unit now has it under its plain name: dtk's name for
    a local symbol another object referred to, given back when that reference became the file's own."""
    names = {(u["name"], f["name"]) for u in rep.get("units", []) for f in u.get("functions", [])}
    out = {}
    for unit, name in lost:
        if (m := _ADDRESS_NAMED.fullmatch(name)) and (unit, m.group(1)) in names:
            out[(unit, name)] = m.group(1)
    return out


def _tail(log: str, lines: int = 14) -> str:
    """Where a build log says why: its error lines, else its end. ninja goes on building other files after one fails,
    so the end was their warnings: agents splitting a PC game's files read "unknown pragma" five times and never the
    error."""
    every = log.strip().splitlines()
    at = [i for i, ln in enumerate(every) if _BUILD_ERROR.search(ln)]
    if not at:
        return "\n".join(every[-lines:])
    # with CodeWarrior's "#" lines around each: the file and line before "Error:", what's wrong after it (a GameCube
    # game's cut said only "#   Error:      ^"); another tool's warnings after an error stay out
    keep: set[int] = set()
    for i in at:
        keep.add(i)
        for step in (-1, 1):
            j = i + step
            while 0 <= j < len(every) and abs(j - i) <= 4 and every[j].lstrip().startswith("#"):
                keep.add(j)
                j += step
    return "\n".join(every[j] for j in sorted(keep)[:lines * 2])


def with_constant_values(rows: list, console, fp) -> list:
    """A diff's differing rows with the values of the float constants the target loads by address (x86's
    `mulss xmm0, [_D_00412340]`: "; target's D_00412340 = 0.0174532924f"), read from the user's copy: the agent
    sees the literal to write instead of an address. Rows on processors without a reader stay as they are."""
    reader = arch.get(console.arch).float_operands
    if reader is None:
        return rows
    order = ">" if console.big_endian else "<"
    out = []
    for mark, target, yours in rows:
        if mark != " " and target:
            said = []
            for addr, kind in reader(target):
                raw = console.data_bytes(fp, addr, 4 if kind == "f" else 8)
                if raw:
                    value = struct.unpack(order + kind, raw)[0]
                    said.append(f"D_{addr:08X} = {value:.9g}f" if kind == "f" else f"D_{addr:08X} = {value:.17g}")
            if said:
                yours = f"{yours}   ; target's {', '.join(said)}"
        out.append((mark, target, yours))
    return out


def _floor_pct(pct: float, matched: bool) -> float:
    """For display: 100 only for a match (99.96 or code whose constants differ reads 99.9)."""
    return 100.0 if matched else min(99.9, int(pct * 10) / 10)


def _digest(code: str) -> str:
    """A function's text, whitespace aside."""
    return hashlib.sha1(re.sub(r"\s+", " ", code).strip().encode()).hexdigest()


def ltcg_unresolved(base: Path) -> list[str]:
    """What a unit's last harness link left unresolved (dll2coff's <object>.ltcg.json): not written yet."""
    try:
        return list(json.loads(base.with_suffix(".ltcg.json").read_text(encoding="utf-8")).get("unresolved") or [])
    except (OSError, ValueError, AttributeError):
        return []


def _definition_start(clean: str, name: str) -> int | None:
    """Where the file-scope declaration holding the first call of `name` in a function body starts (its line, after
    the last `;` or `}` at file scope before it: a #pragma just above it goes with it), in comment-blanked C. `name`
    "": the file's first function's."""
    depth, last = 0, 0
    for k, c in enumerate(clean):
        if c == "{":
            if not name and depth == 0 and clean[:k].rstrip().endswith(")"):  # (a function's body: _without_bodies)
                return _line_of(clean, last)
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                last = k + 1
        elif c == ";" and depth == 0:
            last = k + 1
        elif name and depth > 0 and clean.startswith(name, k) and (k == 0 or not (clean[k - 1].isalnum() or clean[k - 1] == "_")) \
                and re.match(rf"{re.escape(name)}\s*\(", clean[k:]):
            return _line_of(clean, last)
    return None


def _line_of(clean: str, last: int) -> int:
    """The start of the line where what follows `last` (a file-scope `;` or `}`) begins."""
    start = last
    while True:  # (blank lines, and a #pragma pop or reset that ends the function before it, aren't its own)
        while start < len(clean) and clean[start] in " \t\r\n":
            start += 1
        end = clean.find("\n", start)
        line = clean[start:end if end >= 0 else len(clean)]
        if not re.match(r"#\s*pragma\s+(pop\b|\w+\s+reset\b)", line):
            break
        start += len(line)
    return clean.rfind("\n", 0, start) + 1


def started_from_scratch(fp: ForkProject) -> bool:
    """Whether decompdecomp made the project from the user's copy of a game (its manifest says so), wherever this
    copy came from: a clone of the folder, a room member's copy."""
    try:
        return (fp.manifest or {}).get("created") == "from scratch"
    except (OSError, ValueError):
        return False


def _set_aside(fp: ForkProject) -> dict[str, str]:
    """Symbol -> why it's set aside, for functions a project says aren't the game's own (library code, middleware,
    an SDK, the C runtime): config/<version>/set_aside.json, or the file the manifest names (`set_aside`)."""
    manifest = fp.manifest or {}
    rel = manifest.get("set_aside") or (f"config/{manifest['version']}/set_aside.json" if manifest.get("version") and (
        fp.root / "config" / str(manifest["version"]) / "set_aside.json").is_file() else None)
    if not rel:
        return {}
    try:
        data = json.loads((fp.root / rel).read_text(encoding="utf-8"))
        info = json.loads((fp.root / rel).with_name("functions.json").read_text(encoding="utf-8")) \
            if isinstance(data.get("ranges"), list) or isinstance(data.get("functions"), dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}
    return objdiff.expand_set_aside(data, info)


def _copies(fp: ForkProject) -> dict[str, str]:
    """Symbol -> the symbol it's a copy of, for functions the same as another in another of the game's programs (a
    V.Flash game's modules each link its engine again): config/<version>/copies.json. Counted once (network.COPY)."""
    version = (fp.manifest or {}).get("version")
    try:
        data = json.loads((fp.root / "config" / str(version) / "copies.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _module(unit: str) -> str:
    """The program a unit is of, for a function that moves between its source files: its first folder, "" for a unit
    with none (a PC game's .exe: text_0043A160 is a file of it, not a program of its own, and every split of one lost
    its functions' rows, left as "gone" beside a new row named _func_0043AC30')."""
    return unit.split("/", 1)[0] if "/" in unit else ""


def _matched_in(rep: dict, broken: set[str] = frozenset()) -> set[tuple[str, str]]:
    """(unit, function) pairs a progress report counts as matched; units that don't build are measured from an old
    object, so nothing in them counts."""
    return {(u["name"], f["name"]) for u in rep.get("units", []) if u["name"] not in broken
            for f in u.get("functions", []) if (f.get("fuzzy_match_percent") or 0) >= 100}


_INCLUDE_LINE = re.compile(r'^#\s*include\s*"[^"]+"\s*$')
# what autopilot_instances adds to a file for the STL probes it needs (consoles/pc/stl.py's PRELUDE)
STL_HEADERS = ("#include <map>\n", "#include <set>\n", "#include <list>\n", "#include <vector>\n", "#include <deque>\n",
               "#include <string>\n", "#include <locale>\n")
STL_TYPES = ("struct STL_P20 { int a[5]; };\n", "struct STL_P24 { int a[6]; };\n")
_ASM_KEYS = ("asm_twin", "asm_code")  # meta saying a function is hand-written assembly (kept by sync)
# kept by sync too: the agents' verdicts that no C makes it (red in the map), the user giving it back to them (or the
# next check would set it aside again), and agents' proposals to join it or end it elsewhere (each sync, after every
# match, dropped them: on a small PC game three agents of three models proposed the same join over twenty minutes, a
# match between each, and it never added up)
# The user's good enough mark too (network.mark_good_enough): dropped by every sync, a GameCube game's 37 functions
# marked good enough were "set aside" (off the progress total, 58 KB of code) and no longer the user's mark
_KEPT_KEYS = (*_ASM_KEYS, "not_c", "reopened", "joins", "boundaries", "library_said", "library", "good_enough")
GOOD_ENOUGH_SAID = "good enough:"  # how network.mark_good_enough's asm_code begins


def kept_meta(was: dict, same_size: bool, best_score=None) -> dict:
    """What a sync keeps of a function's meta: _KEPT_KEYS while its code is the same size, else only that the user
    gave it back to the agents. Its asm_code goes when it was set aside or no file could hold it (decided again each
    sync). A good enough mark a sync before this dropped, its words still there, comes back."""
    kept = _KEPT_KEYS if same_size else ("reopened",)
    out = {k: v for k, v in was.items() if k in kept
           and not (k == "asm_code" and (was.get("set_aside") or was.get("no_file")))}
    if "good_enough" not in out and str(out.get("asm_code", "")).startswith(GOOD_ENOUGH_SAID):
        out["good_enough"] = {"score": best_score, "t": time.time()}
    return out
_ASM_DEF = re.compile(r"\s*(?:(?:static|inline|extern)\s+)*asm\b")
_MSVC_C = re.compile(r"[_@]([A-Za-z_]\w*?)(?:@\d+)?")  # how MSVC decorates a C function's name (PC, Xbox)
_OLD_SYMBOL = re.compile(r"@?[A-Za-z_]\w*(?:@\d+)?")  # rename_symbol's old name (a PC report's @f@8 too)
_THUNK_NAME = re.compile(r"@\d+@[A-Za-z_]\w*")  # a CodeWarrior this-adjust thunk's name: @48@f__4CFooFv (#300)
# a source file that includes another source file: Mario Party 6's REL runtime.c files are one line,
# #include "src/Runtime.PPCEABI.H/runtime.c" (its asm helpers, which every module links a copy of)
_SOURCE_INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+\.(?:c|cc|cp|cpp))"', re.M)
_PRAGMA = re.compile(r"^#\s*pragma\b")
TRY_ALL_SECONDS = 120  # try_compiler "all" stops trying more versions after this (Codex gives a tool call 180)
COMPARE_SECONDS = 900  # a comparison of every compiler and flag variant on one function stops after this
FILE_FUNCTIONS = 200  # functions a file decompdecomp gives code holds at most (start_files)
COMMIT_TRIES = 5  # a commit waits out a locked index this often
# Files a link tries one at a time, in one run: each is a whole build and check, with every helper's compile waiting
# on it. A GameCube game retried the same 40 failing files after every match, and never got to the rest.
LINK_ONE_BY_ONE = 10


def _around(source: str, span: tuple[int, int], file_text: str, rel: str) -> tuple[list[str], list[str], list[str]]:
    """What an agent sends around the one definition, as (includes, lines before it, lines after it): project
    includes, prototypes and extern declarations, `#pragma` lines (push/pop wrappers). Lines the file has already
    are left out (a wrapper's pragmas aren't: they belong to this function). Anything else (a struct, a global,
    another function) isn't placed: edit_file is for that, and this says so."""
    have = {ln.strip() for ln in file_text.splitlines()}
    clean = csource._blank(source)

    def lines(lo: int, hi: int) -> list[str]:
        return [real.strip() for real, c in zip(source[lo:hi].splitlines(), clean[lo:hi].splitlines()) if c.strip()]

    includes, before, after, other = [], [], [], []
    for ln in lines(0, span[0]):
        if _INCLUDE_LINE.match(ln):
            if ln not in have:
                includes.append(ln)
        elif _PRAGMA.match(ln):
            before.append(ln)
        elif drafts._DECL.match(ln):
            if ln not in have:
                before.append(ln)
        elif ln not in have:
            other.append(ln)
    for ln in lines(span[1], len(source)):
        if _PRAGMA.match(ln):
            after.append(ln)
        elif ln not in have:
            other.append(ln)
    if other:
        listing = "\n".join(other[:6]) + ("\n..." if len(other) > 6 else "")
        raise NetworkError(f"compile_and_diff takes one function definition, plus any #include \"...\", one-line "
                           f"prototypes, extern declarations or #pragma lines it needs (those are placed for you). These "
                           f"lines aren't any of that and aren't in {rel}:\n{listing}\nHelper functions, structs and "
                           f"the prototypes you want shared go in through edit_file (a header, or the top of {rel}), not "
                           "inside compile_and_diff's source: edit_file them first, then compile_and_diff the function "
                           "alone. Nothing was compiled.")
    return includes, before, after


def _headers_defining(fp: ForkProject, rel: str, include_lines: list[str], names: set[str]) -> list[str]:
    """Of a file's #include "..." lines, those whose header defines one of `names` (a type, macro or function),
    looked up where the project's builds look: include/, the file's own folder, src/, the project root."""
    out = []
    for line in include_lines:
        m = re.search(r'"([^"]+)"', line)
        if not m:
            continue
        for base in (fp.root / "include", (fp.root / rel).parent, fp.root / "src", fp.root):
            h = base / m.group(1)
            if not h.is_file():
                continue
            try:
                text = csource._blank(h.read_text(errors="replace", encoding="utf-8"))
            except OSError:
                break
            if any(re.search(rf"(?:struct|union|enum)\s+{re.escape(n)}\b|\}}\s*{re.escape(n)}\s*;|#\s*define\s+{re.escape(n)}\b|"
                             rf"\b{re.escape(n)}\s*\(", text) for n in names):
                out.append(line)
            break
    return out


def _module(unit: str) -> str:
    """The module a unit's file belongs to: its name's first folder ("game/text_10001000": a PC game's DLL; a
    GameCube REL's), none for the program's own (a PC program's "text_00401000"), so a split moves its functions."""
    return unit.split("/", 1)[0] if "/" in unit else ""


def _data_symbols(target: Path | None) -> set[str]:
    """The data symbols of a target object: objdiff's report counts data in a code section as a function (a DS
    program's BuildInfo, the SDK's build information with its RSA text, sits in .text), and agents tried to write it
    as one. Empty when it can't be read (a COFF object: PC, Xbox)."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    try:
        with open(target, "rb") as f:
            symtab = ELFFile(f).get_section_by_name(".symtab")
            return {s.name for s in symtab.iter_symbols() if s["st_info"]["type"] == "STT_OBJECT"} if symtab else set()
    except (OSError, TypeError, ELFError):
        return set()


_QUOTED_INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.M)
MAX_HEADERS = 64  # headers permuter_header follows from one file


# an old-style definition's head: its parameters by name, then their declarations (`f(a, b) u8 *a; s32 b;`)
# (possessive `\s*+`: with `\s*` before `[^;{}()]+`, which takes spaces too, a head that isn't one backtracked through
# every way of splitting each declaration's indentation, and the polishing of a GameCube game's file held the app for
# minutes: _without_bodies)
_OLD_STYLE = re.compile(r"\(\s*+\w+(?:\s*+,\s*+\w+)*\s*+\)(?:\s*+[^;{}()]+;)+\s*$")
OLD_STYLE_HEAD = 4096  # characters of a head looked at for an old-style definition: its parameters' declarations


def _without_bodies(text: str) -> str:
    """A C file with each function's body cut to `;` (its definition becomes its prototype): its declarations, as
    a parser needs them to read one of its functions. An old-style definition becomes `f();`: its head cut short
    (`f(a, b) u8 *a; s32 b;`) is no declaration, and pycparser refused every function of a GameCube game's file
    that had two ("Syntax error in base.c"), so Deep search ended at once with nothing tried."""
    # A head is read from the end of what came before at file scope (the last `}`), and at most OLD_STYLE_HEAD of it:
    # each `{` read the whole file before it, twice over, and a file of 6,000 lines took minutes.
    clean, out, i, depth, start, old, after = csource._blank(text), [], 0, 0, None, None, 0
    for k, c in enumerate(clean):
        if c == "{":
            if depth == 0:
                at = max(after, k - OLD_STYLE_HEAD)
                head = clean[at:k].rstrip()
                if head.endswith(")"):  # a body, not a struct's or an initializer's
                    start, old = k, None
                elif (m := _OLD_STYLE.search(head)) is not None:
                    start, old = k, at + m.start()
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                after = k + 1
                if start is not None:
                    out += [text[i:old] + "()" if old is not None else text[i:start], ";"]
                    i, start, old = k + 1, None, None
    return "".join(out) + text[i:]


def _type_blocks(text: str) -> list[tuple[set[str], str]]:
    """The file-scope type definitions of a C file: (the names they define, their text)."""
    clean = csource._blank(text)
    out, i = [], 0
    pattern = re.compile(r"^[ \t]*(typedef\b|struct\s+\w+\s*\{|union\s+\w+\s*\{|enum\s*\w*\s*\{)", re.M)
    depth_at = []
    depth = 0
    for k, c in enumerate(clean):  # depth before each character
        depth_at.append(depth)
        depth += (c == "{") - (c == "}")
    for m in pattern.finditer(clean):
        if m.start() < i or depth_at[m.start()] != 0:
            continue
        j, d = m.start(), 0
        while j < len(clean):  # to the `;` that ends it at depth 0
            c = clean[j]
            d += (c == "{") - (c == "}")
            if c == ";" and d == 0:
                break
            j += 1
        block = text[m.start():j + 1]
        names = set(re.findall(r"(?:struct|union|enum)\s+(\w+)", block[:block.find("{")] if "{" in block else block))
        tail = block[block.rfind("}") + 1:] if "}" in block else block
        names |= {n for n in re.findall(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*[;,)]", tail)
                  if n not in ("typedef", "struct", "union", "enum", "const", "volatile")}
        if names:
            out.append((names, block.strip()))
        i = j + 1
    return out


def _file_scope_lines(text: str) -> list[str]:
    """The lines of a C file outside every function body and struct (brace depth 0), stripped."""
    clean, depth, out = csource._blank(text), 0, []
    for real, c in zip(text.splitlines(), clean.splitlines()):
        if depth == 0 and c.strip() and "{" not in c and "}" not in c:
            out.append(real.strip())
        depth = max(0, depth + c.count("{") - c.count("}"))
    return out


_CLOSING = re.compile(r"^#\s*pragma\s+(pop\b|\w+\s+reset\b)")


def _pragmas_around(text: str, lo: int, hi: int) -> tuple[int, int]:
    """Widen a definition's span over the #pragma lines right above and below it (its wrapper), and the comment
    between them and the definition (a polish puts one there: stopping at it left the file's #pragma push behind, never
    popped, when the next rewrite came without the comment). Above, a pop or reset ends the function before; below,
    only pops and resets right after it are its own: the next function's push, past a blank line, went with a
    GameCube game's SetGVol, and its pop left alone broke the file's build."""
    start = above = csource.comment_above(text, lo)
    while start > 0:
        prev = text.rfind("\n", 0, start - 1) + 1
        line = text[prev:start].strip()
        if not _PRAGMA.match(line) or _CLOSING.match(line):
            break
        start = prev
    start = start if start < above else lo
    end = hi
    while end < len(text):
        nl = text.find("\n", end)
        nl = len(text) if nl < 0 else nl
        line = text[end:nl].strip()
        if not line and end == hi and hi and text[hi - 1] != "\n":
            end = nl + 1 if nl < len(text) else nl  # (the rest of the definition's own last line)
            continue
        if not _CLOSING.match(line):
            break
        end = nl + 1 if nl < len(text) else nl
    return start, end


def _with_includes(text: str, includes: list[str], prelude: str = "") -> str:
    """The file with new #include lines after its last one (or at the top), and `prelude` (type definitions)
    after those."""
    if not includes and not prelude:
        return text
    last = None
    for m in re.finditer(r"^[ \t]*#\s*include\b[^\n]*\n", text, re.M):
        last = m
    block = "".join(ln + "\n" for ln in includes) + (prelude.rstrip("\n") + "\n\n" if prelude else "")
    return text[:last.end()] + block + text[last.end():] if last else block + text


def _observed(cfg: dict, d) -> list[str]:
    """What a project's diff shows beyond its rows (the frame's size, registers moved along a chain, a delay slot),
    from its console's processor (arch/advice.py), as ROM mode says it. A fork's projects row names no processor:
    its console does."""
    return arch_advice.diff_lines(consoles.of(cfg).arch, d.rows, objdiff=True,
                                   addresses=getattr(d, "addresses", (None, None)))


def _renamed_note(d) -> str:
    """objdiff's rules accept a reference to a differently named symbol; the game's link doesn't."""
    if not d.renamed:
        return ""
    pairs = ", ".join(f"`{mine}` (the original uses `{orig}`)" for orig, mine in d.renamed[:5])
    return (f"\n⚠️ Some references use other names than the original: {pairs}. objdiff counts the match, but the "
            "game links by name: use the original's names (or rename the symbol everywhere) so the code links.")


FAR_CLOSER = 3  # times closer a function's C comes with other flags, matching nothing yet, for search_flags to keep them
def _far_closer(results: list[tuple], own: list[str]) -> tuple | None:
    """search_flags' (score, flags, why) of the variant a function's C comes FAR_CLOSER with than with its file's own
    flags, breaking nothing (a score: it built and every match held), or None."""
    ours = next((r[0] for r in results if r[1] == own), None)
    near = min((r for r in results if r[0] is not None and r[1] != own), default=None, key=lambda r: r[0])
    return near if near is not None and ours and near[0] * FAR_CLOSER <= ours else None


CLOSER = 10  # match points the open functions of a file come closer by, on average, for the survey to keep flags


def _closer(rows: dict, before: dict, after: dict) -> float | None:
    """How much closer a file's open functions came with other flags, on average (None: not clearly, CLOSER, and
    most of them). A V.Flash game's file was -O0 code built at -O3: no agent's C matched at -O3, none of it at -O0
    yet either (C written against -O3), so a survey of matches alone never changed its flags."""
    opened = [n for n, r in rows.items() if r["status"] == "open" and n in before and n in after]
    if not opened:
        return None
    steps = [(after[n] or 0) - (before[n] or 0) for n in opened]
    gain = sum(steps) / len(steps)
    return gain if gain >= CLOSER and sum(d > 0 for d in steps) * 2 > len(steps) else None


def _problem_kind(m) -> str:
    """What kind of difference objdiff's 100% didn't see, for the diff view's list."""
    if getattr(m, "jump_table", False):  # (forks/jumptables.py)
        return "a switch case goes elsewhere"
    return "a reference differs" if isinstance(m, MappingConflict) else "a loaded constant differs"


def progress_moved(before: dict | None, now: dict) -> str | None:
    """The feed's line for a sync, or None when the share of code that matches is what it was: a room's member
    measures after each of the host's commits, and its feed was "sync 89.51% of code matches" every few seconds,
    burying what its agents did."""
    said = f"{float(now.get('matched_code_percent', 0)):.2f}% of code matches"
    was = (before or {}).get("matched_code_percent")
    return None if was is not None and f"{float(was):.2f}% of code matches" == said else said


class ForkEngine:
    def __init__(self, net):
        self.net = net
        self.data_jobs = DataJobs(self)  # a file whose functions all match, handed out for its data (app/datajobs.py)
        self._trees: dict[int, _TreeLock] = defaultdict(_TreeLock)  # project id -> its source tree's lock
        self._unit_locks: dict[tuple[int, str], _UnitLock] = defaultdict(_UnitLock)
        self._build_locks: dict[int, threading.Lock] = defaultdict(threading.Lock)  # one build at a time per tree
        self._unit_builds: dict[int, _UnitBuilds] = defaultdict(_UnitBuilds)  # project id -> its units' builds
        self._git_locks: dict[int, threading.Lock] = defaultdict(threading.Lock)
        self._try_local = threading.local()  # the units this thread tries compilers on (_trying)
        self._mlock = threading.Lock()
        # (project id, unit) -> (sha1 of its source, base object mtime, {function: match %}): what objdiff said
        # the last time it measured the unit, so a compile doesn't need a second objdiff run to know the baseline
        self._scores: dict[tuple[int, str], tuple[str, int | None, dict]] = {}
        self._best_diffs: dict[str, dict] = {}  # a best attempt's diff, by what it was built from
        # (project id, unit) -> whether its object is a try's now, for the units in a run of tries (trial_run)
        self._trials: dict[tuple[int, str], bool] = {}
        self._index: dict[int, dict] = {}  # project id -> {unit: {"mtime", "order", "ops"}}
        self._indexing: set[int] = set()
        self._index_dirty: set[int] = set()  # projects whose index has entries index.json doesn't have yet
        self._ilock = threading.Lock()
        self._linking: dict[str, dict] = {}  # slug -> background link run
        self._preflight_locks: dict[int, threading.Lock] = defaultdict(threading.Lock)
        self._preflighted: set[int] = set()  # projects checked since the app started (overview's check)
        self._parts: dict[Path, tuple] = {}  # project root -> (its config files' stat, _file_parts' answer)

    # ------------------------------------------------------------------ pre-flight

    def preflight(self, slug: str, log=lambda *_: None) -> str | None:
        """Whether the project builds on this computer before helpers spend compiles on it: its setup finished and
        build.ninja's programs exist (ForkProject.build_problem). When they don't, the setup's configure step runs
        again (a project folder moved from another home); what's still wrong is kept on the project (its overview
        shows it) and returned. None: it builds."""
        proj, fp, cfg = self.get(slug)
        if not cfg.get("ready"):
            return None  # not set up yet: Setup says so
        with self._preflight_locks[proj["id"]]:
            self._preflighted.add(proj["id"])
            why = fp.build_problem()
            if why is not None and (fp.root / "objdiff.json").exists():
                log(f"{slug}: {why}; running its setup's configure step again")
                ok, tail = fp.reconfigure(cfg.get("version"), log=log)
                why = fp.build_problem() or (None if ok else f"its setup failed: {_tail(tail, 4)}")
                if why is None:
                    self.net.bump_generation(proj["id"])
            if self.get(slug)[2].get("build_problem") != why:
                self.net._update_cfg(slug, lambda c: c.__setitem__("build_problem", why))
        return why

    def _preflight_once(self, slug: str) -> None:
        """The first look at a project in this run of the app (its page opened): pre-flight it in the background."""
        try:
            pid = self.net._project(slug)["id"]
        except NetworkError:
            return
        if pid in self._preflighted:
            return
        self._preflighted.add(pid)

        logger = logging.getLogger("decompdecomp")

        def run() -> None:
            try:
                self.preflight(slug, log=lambda m: logger.info("%s", m))
            except Exception:  # the page works without it
                logger.exception("pre-flight of %s failed", slug)
        threading.Thread(target=run, daemon=True, name=f"preflight-{slug}").start()

    # ------------------------------------------------------------------ locks, builds, baselines

    def _tree(self, proj) -> _TreeLock:
        with self._mlock:
            return self._trees[proj["id"]]

    def unit_wanted(self, proj, unit: str) -> bool:
        """Whether another thread waits for a unit's source file (_UnitLock.wanted): a permuter turn holding it ends."""
        return self._unit_lock(proj, unit).wanted

    def _unit_lock(self, proj, unit: str) -> _UnitLock:
        with self._mlock:
            return self._unit_locks[(proj["id"], unit)]

    def _build_lock(self, proj) -> threading.Lock:
        # (from decomp.anything: two threads asking a defaultdict for a new key can each make a lock of their own)
        with self._mlock:
            return self._build_locks[proj["id"]]

    def _git_lock(self, proj) -> threading.Lock:
        with self._mlock:
            return self._git_locks[proj["id"]]

    @contextmanager
    def _units_locked(self, proj, names: list[str]):
        with ExitStack() as stack:
            for n in sorted(set(names)):
                stack.enter_context(self._unit_lock(proj, n))
            yield

    def _build_unit(self, proj, fp: ForkProject, unit) -> tuple[bool, str]:
        """Build one unit's object. Builds share the tree's build files (ninja's log), so they take turns: together
        with the others asked for meanwhile, in one run of the build (_UnitBuilds)."""
        with self._mlock:  # (one per project: two first builds at once made two, and batched apart)
            builds = self._unit_builds[proj["id"]]
        return builds.build(unit, lambda units: self._build_units(proj, fp, units))

    def _build_units(self, proj, fp: ForkProject, units: list) -> list[tuple[bool, str]]:
        with self._build_lock(proj):  # (and nothing changes the build's files meanwhile)
            return fp.build_units(units)

    def _build_all(self, proj, fp: ForkProject, failed: list[str] | None = None) -> tuple[bool, str]:
        with self._build_lock(proj):
            return fp.build_all(failed=failed)

    def tree_wanted(self, proj) -> bool:
        """Whether something waits for the project's tree alone (_TreeLock.wanted): a permuter turn holding it ends."""
        return self._tree(proj).wanted

    @contextmanager
    def trial_run(self, proj, unit_name: str):
        """A run of tries at one unit's functions that aren't kept (the permuter's turn): the unit is held for the run,
        and a try that isn't kept puts its file back without building it again, as the next try builds anyway. The
        unit is built once at the end. On an LTCG unit a build is a whole-unit link of about 5 s, and every try
        built twice: half the permuter's time went to rebuilding the file it had just put back. (A unit linked
        into the game takes the tree alone for each try: such tries rebuild as before.)"""
        fp = ForkProject(Path(proj["root"]))
        try:
            unit = fp.unit(unit_name)
        except ForkError:
            yield
            return
        if unit.complete and fp.linkable():
            yield
            return
        key = (proj["id"], unit_name)
        with self._tree(proj).shared(), self._unit_lock(proj, unit_name):
            self._trials[key] = False
            try:
                yield
            finally:
                if self._trials.pop(key, False):  # the object is the last try's: the file's own again
                    hit = self._scores.get(key)
                    if self._build_unit(proj, fp, unit)[0] and hit and unit.base is not None and unit.base.exists():
                        self._scores[key] = (hit[0], unit.base.stat().st_mtime_ns, hit[2])

    def _keep_scores(self, proj, unit, text: str, scores: dict) -> None:
        mtime = unit.base.stat().st_mtime_ns if unit.base is not None and unit.base.exists() else None
        self._scores[(proj["id"], unit.name)] = (hashlib.sha1(text.encode()).hexdigest(), mtime, dict(scores))

    def _last_scores(self, proj, unit) -> dict | None:
        hit = self._scores.get((proj["id"], unit.name))
        return hit[2] if hit else None

    def _baseline(self, proj, fp: ForkProject, unit, text: str) -> tuple[dict | None, bool]:
        """({function: match %} for the unit as its source file is now, whether that builds). Scores are None when
        the file doesn't build or objdiff can't measure it."""
        hit = self._scores.get((proj["id"], unit.name))
        if (hit and unit.base is not None and unit.base.exists() and hit[0] == hashlib.sha1(text.encode()).hexdigest()
                and (hit[1] == unit.base.stat().st_mtime_ns or self._trials.get((proj["id"], unit.name)))):
            return hit[2], True  # (in a run of tries the object is the last try's: the text's scores are these)
        ok, _ = self._build_unit(proj, fp, unit)  # the object may be older than the file
        if not ok or unit.base is None or not unit.base.exists():
            return None, False
        try:
            d = fp.diff(unit, None)
        except (ObjdiffError, ForkError):
            return None, True
        self._keep_scores(proj, unit, text, d.unit_scores)
        return d.unit_scores, True

    def same_object(self, proj, fp: ForkProject, unit, path: Path, new_text: str) -> tuple[bool, str]:
        """Write `new_text` to the unit's source file and keep it only if the unit builds to the same object
        (forks/identity.py): the check every machine pass over the source is judged by. objdiff's scores can't be:
        an extra function, another order or a constant read through a symbol keep every one. Returns (kept, why
        not). The caller commits."""
        with self._tree(proj).shared(), self._units_locked(proj, [unit.name]):
            try:
                text = path.read_text(errors="replace", encoding="utf-8")
            except OSError as e:
                return False, f"its source can't be read: {e}"
            if text == new_text:
                return True, ""
            ok, _ = self._build_unit(proj, fp, unit)
            before = identity.fingerprint(unit.base) if ok and unit.base is not None else None
            if before is None:
                return False, ("it doesn't build as it is" if not ok else
                               "its object isn't one decompdecomp compares (not ELF)")
            _rewrite(path, new_text)
            ok, log = self._build_unit(proj, fp, unit)
            after = identity.fingerprint(unit.base) if ok else None
            if after == before:
                if hit := self._scores.get((proj["id"], unit.name)):
                    self._keep_scores(proj, unit, new_text, hit[2])
                return True, ""
            _rewrite(path, text)
            self._build_unit(proj, fp, unit)
            if not ok:
                return False, f"it doesn't compile so: {_tail(log, 6)}"
            return False, "its object differs: " + "; ".join(before.differences(after) if after else ["unreadable"])

    def _trying_units(self) -> set[str]:
        """The units this thread is trying compilers on (try_compiler, compare_compilers): their file's compiler is
        meant to differ from the committed one while they build."""
        return getattr(self._try_local, "units", set())

    @contextmanager
    def _trying(self, unit_name: str):
        units = self._trying_units()
        self._try_local.units = units | {unit_name}
        try:
            yield
        finally:
            self._try_local.units = units

    def _put_back_own_entry(self, proj, fp: ForkProject, unit) -> None:
        """Before a compile measures its file: the file's compiler and flags as committed, when they differ and no try
        is on it (the caller holds the file's lock, which every try holds). A GameCube game's file was built with a
        try's compiler long after the try (GC/2.0p1 for GC/1.2.5n): every compile there reopened its matches (54 at
        once), and a room member's agents were handed functions that matched."""
        console = consoles.get(self.net.cfg(proj).get("platform"))
        if not unit.source or console.file_compiler(fp, unit.source) is None:
            return
        with self._build_lock(proj):
            ok, changed = fp.git("diff", "--name-only", "HEAD", "--", "config", "configure.py")
            paths = [fp.root / r for r in changed.split()] if ok and changed.strip() else []
            if not paths:
                return
            now_c, now_f = console.file_compiler(fp, unit.source), console.file_flags(fp, unit.source)
            saved = {path: path.read_text(encoding="utf-8") for path in paths if path.exists()}
            try:
                for path in saved:
                    ok, head = fp.git("show", f"HEAD:{path.relative_to(fp.root).as_posix()}")
                    if ok:
                        path.write_text(head + "\n", encoding="utf-8")
                head_c, head_f = console.file_compiler(fp, unit.source), console.file_flags(fp, unit.source)
            finally:
                for path, text in saved.items():
                    path.write_text(text, encoding="utf-8")
            if (now_c, now_f) == (head_c, head_f):
                return
            console.set_file_compiler(fp, unit.source, head_c)
            if head_f is not None and now_f != head_f:
                console.set_file_flags(fp, unit.source, head_f)
        said = lambda c, f: c + (f" {' '.join(f) or '(no flags of its own)'}" if f is not None else "")  # noqa: E731
        logging.getLogger("decompdecomp").warning("%s: put %s back on %s as committed (a try's leftover: it was on %s)",
                                                  proj["slug"], unit.source, said(head_c, head_f), said(now_c, now_f))

    def _commit_entry(self, proj, fp: ForkProject, rel: str, setter, message: str) -> None:
        """Commit one source file's entry of a map every file's tries write to (file_compilers.json, file_flags.json):
        the committed map is the last commit's with `setter()`'s entry, never another try's in progress, which the
        working tree keeps. A commit of the whole file swept one up: a 2007 PC game's file stayed "built with Visual
        C++ 2010" after an agent's try of it was in the map when a choice in Settings was committed."""
        path = fp.root / rel
        with self._build_lock(proj):
            now = path.read_text(encoding="utf-8")
            ok, head = fp.git("show", f"HEAD:{rel}")
            if ok:  # (one no commit has yet is as it is: projects commit their maps when they're made)
                path.write_text(head + "\n", encoding="utf-8")
            setter()
            try:
                self._commit(proj, fp, rel, message)
            finally:
                path.write_text(now, encoding="utf-8")
                setter()  # (the working tree: the tries in progress, and this entry)

    def put_back_tries(self, slug: str, log=print) -> list[str]:
        """At start, a change to the project's config no commit has is a try the app ended part-way (a restart for an
        update in the middle of try_compiler or search_flags, whose clean-up never ran): agents can't edit the config,
        and the app commits what it keeps. Put back as committed, before any helper starts; returns the files."""
        proj, fp, cfg = self.get(slug)
        if cfg.get("origin") is None and started_from_scratch(fp):
            cfg["origin"] = "scratch"  # (a copy cloned before clone() read the manifest: see there)
            self._save_cfg(proj, cfg)
            proj = self.net._project(slug)
        return self._put_back_config(proj, fp, log=log)

    def _put_back_config(self, proj, fp: ForkProject, log=None) -> list[str]:
        """The project's config as committed, where it differs (a game started from scratch: its config is the app's).
        Only the app writes it, and it commits what it keeps, so a difference no try in progress makes (the caller
        holds the tree alone, or the app is starting) is a try's leftover. A GameCube game keeps each file's compiler
        in configure.py, outside config/, where the start-up's put-back never looked: a compiler a try had left there
        went into the commit of each agent's split_file, and a file stayed on GC/1.3 that no agent chose."""
        if json.loads(proj["config"]).get("origin") != "scratch":  # (a public decomp's config may be someone's own change)
            return []
        ok, out = fp.git("diff", "--name-only", "HEAD", "--", "config", "configure.py")
        changed = out.splitlines() if ok else []
        if changed:
            fp.git("checkout", "HEAD", "--", *changed)
            logging.getLogger("decompdecomp").warning("%s: put back %s as committed (a compiler or flags try's leftover)",
                                                      proj["slug"], ", ".join(changed))
            if log:
                log(f"{proj['slug']}: put back {', '.join(changed)} as committed (a try the app was stopped in the "
                    "middle of)")
        return changed

    def _commit(self, proj, fp: ForkProject, rel: str, message: str) -> None:
        """Commit one file (agents work side by side: never sweep up another one's change)."""
        self._commit_paths(proj, fp, [rel], message)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def is_fork(proj) -> bool:
        return json.loads(proj["config"]).get("kind") == "fork"

    def get(self, slug: str):
        proj = self.net._project(slug)
        if not self.is_fork(proj):
            raise NetworkError(f"{slug} isn't a fork")
        cfg = json.loads(proj["config"])
        return proj, ForkProject(Path(proj["root"]), cfg.get("platform") or ""), cfg

    def _save_cfg(self, proj, cfg: dict) -> None:
        with self.net.store.tx() as db:
            # the room link is the database's as it is now, not as this copy of the settings read it: a sync that
            # began before the user left the room wrote the link back, and the app joined the room again at start
            now = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
            if "link" in now:
                cfg["link"] = now["link"]
            else:
                cfg.pop("link", None)
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))

    @staticmethod
    def _meta(fn) -> dict:
        return json.loads(fn["meta"]) if fn["meta"] else {}

    @staticmethod
    def _going_symbols(rows, symbols: dict[str, tuple[str, int, int]], lo: int, hi: int) -> set[str]:
        """The rows' symbols whose code is in [lo, hi): the functions a split moves. A file-local function's row
        symbol carries its address (`stateBusy_8023FC14`) where symbols.txt has the bare name (`stateBusy`,
        scope:local) at the same address: looked up verbatim it stayed in the kept file and its code moved without it
        (#300)."""
        out = set()
        for row in rows:
            symbol = ForkEngine._meta(row).get("symbol")
            if not symbol:
                continue
            known = symbols.get(symbol)
            if known is not None:
                address = known[1]
            else:
                bare = re.sub(r"_[0-9A-Fa-f]{8}$", "", symbol)
                address = None
                if bare != symbol and bare in symbols and f"{symbols[bare][1]:08X}" == symbol[-8:].upper():
                    address = symbols[bare][1]
            if address is not None and lo <= address < hi:
                out.add(symbol)
        return out

    # ------------------------------------------------------------------ creating a fork

    def policy(self, repo: str) -> dict:
        """What a public decomp says about AI and contributions (forks/policy.py), before it's forked."""
        from ..forks import policy

        m = _REPO.match(repo.strip())
        if not m:
            raise NetworkError("give a GitHub/GitLab/Codeberg repository URL (https://github.com/owner/repo)")
        return {"repo": m.group(1), **policy.check(m.group(1))}

    def clone(self, repo: str, *, name: str = "", platform: str = "", version: str | None = None, log=print) -> str:
        repo = repo.strip()
        local = Path(repo).expanduser()
        if not (_REPO.match(repo) or (local.is_dir() and (local / ".git").exists())):
            raise NetworkError("give a GitHub/GitLab/Codeberg repository URL (https://github.com/owner/repo)")
        if not shutil.which("git"):
            raise NetworkError("forking needs git: install it from https://git-scm.com")
        url = _REPO.match(repo).group(1) if _REPO.match(repo) else str(local.resolve())
        for p in self.net.store.all("SELECT slug, config FROM projects"):
            if json.loads(p["config"]).get("repo_url") == url:
                log(f"already forked as {p['slug']}")
                return p["slug"]
        base = _slug(name or url.rstrip("/").split("/")[-1])
        slug = self._free_slug(base)
        dest = self.net.workspace / slug
        log(f"cloning {url}")
        res = subprocess.run(["git", "clone", "--depth", "1", "--recurse-submodules", "--shallow-submodules", url, str(dest)],
                             capture_output=True, text=True, encoding="utf-8", errors="replace",
                             stdin=subprocess.DEVNULL, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                             creationflags=NO_WINDOW)
        if res.returncode != 0:
            from ..forks import policy
            shutil.rmtree(dest, ignore_errors=True)
            raise NetworkError(policy.git_trouble(res.stderr))
        fp = ForkProject(dest)
        fp.git("checkout", "-q", "-b", "decomp-wtf")
        kind = fp.kind()
        versions = fp.versions()
        version = version if version in versions else (versions[0] if versions else version)
        cfg = {"kind": "fork", "repo_url": url, "platform": platform, "version": version, "fork_kind": kind,
               "ready": False, "legal": {"basis": "personal-copy", "license": "the project's own license"}}
        if started_from_scratch(fp):  # a game decompdecomp started from scratch, cloned (another computer's copy):
            # still the app's own project. Taken for a public decomp, a GameCube game's 14 SDK libraries were found
            # and none set aside, autopilot refused, and a try's leftover compiler was never put back
            cfg["origin"] = "scratch"
        self._register(slug, name or url.rstrip("/").split("/")[-1], f"fork of {url}", dest, cfg, f"cloned {url}")
        log(f"cloned into {dest} ({kind} project)")
        return slug

    def _free_slug(self, base: str) -> str:
        slug, n = base, 2
        while self.net.store.one("SELECT 1 FROM projects WHERE slug=?", slug) or (self.net.workspace / slug).exists():
            slug, n = f"{base}-{n}", n + 1
        return slug

    def _register(self, slug: str, title: str, description: str, root: Path, cfg: dict, event: str) -> None:
        with self.net.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                             (slug, title, description, "", 0, str(root), json.dumps(cfg))).lastrowid
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (pid, 1, "", None, "projects keep their headers in the tree", time.time(), ""))
            self.net._event(db, pid, None, "fork", event)

    def create_scratch(self, game: Path, console: consoles.Console, *, compiler: str | None = None, log=print,
                       scope: str | None = None, options: dict | None = None,
                       parts: list[str] | None = None) -> str:
        """A game of a PROJECT-mode console (GameCube, Wii, PC, DS), from scratch: the console generates the
        community's kind of project for it (Console.create_project: dtk-template; for PC, decompdecomp's own from
        Ghidra's analysis; for DS, ds-decomp's), opened like a fork. `scope`: what the project covers (SCOPES), for
        a console whose import sets library code aside (Console.sets_aside); kept in the project's manifest.
        `options`: the user's answers to Console.import_options, given to create_project as keywords."""
        if scope is not None and scope not in SCOPES:
            raise NetworkError(f"a project covers the game's own code ({GAME!r}) or the whole program, not {scope!r}")
        scoped = {"scope": scope or GAME} if console.sets_aside else {}
        if parts is not None and console.chooses_parts:  # (the programs of the game it analyses: V.Flash's modules)
            scoped["parts"] = parts
        info = console.game_info(game)
        sha1 = info["sha1"]
        for p in self.net.store.all("SELECT slug, config FROM projects"):
            if json.loads(p["config"]).get("program_sha1") == sha1:
                log(f"already set up as {p['slug']}")
                return p["slug"]
        slug = self._free_slug(_slug(f"{info['title']} {info['id']}" if info.get("kind") != "dol" else info["title"]))
        dest = self.net.workspace / slug
        try:
            facts = console.create_project(dest, game, compiler=compiler, log=log, **scoped, **(options or {}))
            if "scope" in scoped:  # (before the first measuring, which reads it)
                ForkProject(dest).update_manifest(scope=scoped["scope"])
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        cfg = {"kind": "fork", "origin": "scratch", "repo_url": None, "platform": facts["platform"],
               "version": facts["id"], "fork_kind": "manifest", "ready": False, "compiler": facts["compiler"],
               "program_sha1": sha1,
               "legal": {"basis": "personal-copy", "license": "personal use only",
                         "statement": "imported by the owner of this copy of the game, who confirmed it was legally obtained",
                         "confirmed_at": time.time()}}
        self._register(slug, facts["title"], f"{consoles.name(facts['platform'])} game {facts['id']}, from scratch",
                       dest, cfg, f"started {facts['id']} from scratch")
        self.check(slug, log=log)
        return slug

    def needs(self, slug: str) -> dict:
        _, fp, cfg = self.get(slug)
        return fp.needs(cfg.get("version")) | {"kind": fp.kind(), "versions": fp.versions(),
                                                "version": cfg.get("version") or fp.default_game_version(),
                                                "readme": fp.readme()}

    def setup(self, slug: str, game: bytes | Path | None, filename: str = "", log=print, move: bool = False) -> dict:
        """Add the user's game (bytes, or a file on disk) and run the project's setup, then measure it."""
        proj, fp, cfg = self.get(slug)
        if game is not None:
            if isinstance(game, (bytes, bytearray)):
                tmp = fp.root / STATE / "upload.tmp"
                tmp.write_bytes(game)
                game, move = tmp, True
            self._match_version(proj, fp, cfg, Path(game), log)
            if not cfg.get("program_sha1"):  # which game it is: members of a room on it need the same one
                from .forkroom import game_identity

                try:
                    cfg["game_sha1"] = game_identity(Path(game))
                    self._save_cfg(proj, cfg)
                except (OSError, ForkError):
                    pass
            dest = fp.place_game(Path(game), filename or Path(game).name, cfg.get("version"), move=move)
            log(f"your copy of the game is at {dest.relative_to(fp.root)}")
        if not fp.needs(cfg.get("version"))["auto"]:
            raise NetworkError("this project has its own setup: follow its README, then click Check again")
        fp.setup(cfg.get("version"), log=log)
        return self.check(slug, log=log)

    def _match_version(self, proj, fp: ForkProject, cfg: dict, game: Path, log) -> None:
        """Select a public project's supported version from the supplied game."""
        from .. import consoles

        version = consoles.get(fp.detect_platform()).match_fork_game_version(fp, game, log=log)
        if version is not None:
            if version != cfg.get("version"):
                log(f"your ROM matches the project's {version} version")
                cfg["version"] = version
                self._save_cfg(proj, cfg)
            return
        # A GameCube/Wii disc names its version (GP6E01, GP6P01...).
        if fp.kind() != "dtk":
            return
        versions = fp.versions()
        from ..consoles.gc_wii import scratch as dtk  # dtk projects are GameCube and Wii ones

        gid = dtk.disc_id(game)
        if not gid or not versions or gid == cfg.get("version"):
            return
        if gid in versions:
            log(f"your disc is {gid}: using the project's {gid} version")
            cfg["version"] = gid
            self._save_cfg(proj, cfg)
        elif all(re.fullmatch(r"[A-Z0-9]{6}", v) for v in versions):
            raise NetworkError(f"this disc is {gid}, but the project decompiles {', '.join(versions)}: "
                               "pick your copy of one of those versions")

    def check_rom(self, slug: str, log=print) -> dict:
        """A game started from scratch: rebuild its program and compare it with the user's copy (its console's
        check_rebuild); what it says is kept in the project's .decomp.wtf.json and shown on the project."""
        proj, fp, cfg = self.get(slug)
        manifest = fp.manifest or {}
        console = consoles.get(manifest.get("platform"))
        if cfg.get("origin") != "scratch" or consoles.REBUILD_CHECK not in console.features:
            raise NetworkError(f"{console.name or 'this'} projects started from scratch don't rebuild here")
        with self._build_lock(proj):  # not while an agent's compile builds in the same tree
            result = console.check_rebuild(fp, manifest["version"], log=log)
        manifest["rebuild"] = result | {"t": time.time()}
        (fp.root / ".decomp.wtf.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return result

    def set_scope(self, slug: str, scope: str, log=print) -> dict:
        """What the project covers (forks/project.py SCOPES): the game's own code, or the whole program. Kept in its
        manifest, so it travels with the project's folder; measuring again then opens its set-aside functions to
        agents and counts them (or keeps them out again). Hand-written assembly stays assembly either way. The whole
        program also brings in what the project's import left unanalysed (Console.unanalysed), once. Returns the new
        measures."""
        if scope not in SCOPES:
            raise NetworkError(f"a project covers the game's own code ({GAME!r}) or the whole program, not {scope!r}")
        proj, fp, cfg = self.get(slug)
        if not fp.manifest:
            raise NetworkError("this project has no decompdecomp manifest, so it has no set-aside code to choose for")
        if fp.scope != scope:
            fp.update_manifest(scope=scope)
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], None, "scope", "this project covers the whole program now"
                                if scope != GAME else "this project covers the game's own code now")
        if scope == PROGRAM and self._unanalysed(fp, cfg) and self.analyse_unanalysed(slug, log=log) is not None:
            return self.get(slug)[2].get("measures") or {}  # (measured again with what it brought in)
        return self.sync(slug, log=log)

    def _unanalysed(self, fp: ForkProject, cfg: dict) -> str | None:
        """What the project's import left unanalysed that a new analysis can bring in (Console.unanalysed), or None.
        A console that can't tell (its program missing, say) has nothing to offer."""
        try:
            return consoles.get(cfg.get("platform")).unanalysed(fp) if fp.manifest else None
        except Exception:  # noqa: BLE001  Settings shows without it rather than failing
            return None

    def add_parts(self, slug: str, names: list[str], log=print) -> dict:
        """Analyse programs of the game the project's import left out (Console.add_parts); returns the overview."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if not console.chooses_parts:
            raise NetworkError(f"{console.name} projects analyse their whole game at import")
        if not names:
            raise NetworkError("choose the modules to analyse")
        console.add_parts(self.net, slug, names, log=log)
        return self.overview(slug)

    def analyse_unanalysed(self, slug: str, log=print) -> str | None:
        """Bring in what the project's import left unanalysed (Console.analyse_unanalysed: a new analysis of that code
        alone, through reanalyse, keeping every match, note and name). Returns what changed (None: nothing)."""
        proj, fp, cfg = self.get(slug)
        if not self._unanalysed(fp, cfg):
            return None
        return consoles.get(cfg.get("platform")).analyse_unanalysed(self.net, slug, log=log)

    def reanalyse(self, slug: str, step, paths=("config",), fix=False, baseline=False, log=print) -> str | None:
        """A console's improved analysis of its games, applied to a project made before it (Console.on_start): `step`
        changes the project's `paths` (its config, its build tools; its source files keep their ranges, so the work in
        them stays) and may add files (source files for code it found), and says what it found, as a sentence, or None
        when there's nothing to change. The project is set up again and, where the
        console checks its rebuild, the game rebuilt: a rebuild identical before and not after takes the change back,
        and so does one that differs otherwise than before, unless `fix` (a fix to its build, which may mend part).
        The project's feed says what happened. Returns the sentence (None: nothing changed). `baseline`: with no
        rebuild recorded, it's measured first, so one that already differed (a match judged wrongly) isn't taken for
        the change's doing; without, a step is kept only when the rebuild is identical."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        # the manifest's, as check_rom: the config may hold the game's id ("C32P"), and the build's folder is "c32p"
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        checks = cfg.get("origin") == "scratch" and consoles.REBUILD_CHECK in console.features
        paths = [p for p in paths if (fp.root / p).exists()]  # git refuses a path the project hasn't
        def untracked() -> set[str]:
            ok, out = fp.git("ls-files", "-z", "--others", "--exclude-standard")
            return set(out.split("\0")) - {""} if ok else set()

        def undo() -> None:  # the files the step added go too (agents can't add any: the tree is the step's)
            fp.git("checkout", "HEAD", "--", *paths)
            for rel in untracked() - there:
                (fp.root / rel).unlink(missing_ok=True)

        def set_up(failed: list[str]) -> bool:
            """The project set up: True when every step but its builds' compiles went through, `failed` the targets
            that didn't build (ninja keeps going past them, so the list is all of them)."""
            fine = True
            for cmd in fp.setup_commands(version):
                ninja = Path(cmd[0]).name in ("ninja", "ninja.exe")
                found: list[str] = []
                ok, _ = fp.run([*cmd, "-k", "0"] if ninja else cmd, log=log, failed=found)
                failed.extend(found)
                fine = fine and (ok or ninja and bool(found))  # (a ninja that failed naming nothing: its own error)
            return fine

        with self._tree(proj).exclusive(), self._build_lock(proj):
            self._put_back_config(proj, fp)  # (a try's leftover isn't committed with this change)
            before = (fp.manifest or {}).get("rebuild") or \
                (console.check_rebuild(fp, version, log=log) if checks and baseline else {})
            # What doesn't build already isn't the step's doing: an agent's attempt that doesn't compile, left in a
            # file, failed the setup, and a Visual C++ 6.0 debug build's flags for 1,540 files were taken back for it
            broken: list[str] = []
            set_up(broken)
            there = untracked()
            try:
                said = step(fp)
            except (ForkError, NetworkError, OSError) as e:
                undo()
                said, kept = f"a new analysis of the game couldn't be applied, and the project stays as it was: {e}", False
            else:
                if said is None:
                    return None
                failed: list[str] = []
                new_failures = sorted(set(failed) - set(broken)) if (fine := set_up(failed)) else []
                setup = [fine and not new_failures]
                after = console.check_rebuild(fp, version, log=log) if checks and all(setup) else {"identical": None}
                # the config says more about the same bytes: a rebuild that differs where it didn't is its doing
                kept = all(setup) and (not checks or after.get("identical") or not before.get("identical") and (
                    fix or after.get("detail") == before.get("detail")))
                if not kept:
                    undo()
                    for cmd in fp.setup_commands(version):
                        fp.run(cmd, log=log)
                    said = (f"a new analysis of the game ({said}) was taken back: the game "
                            f"{'no longer rebuilt byte for byte' if all(setup) else 'no longer built'} with it"
                            + (f" ({', '.join(new_failures[:5])}{' and more' if len(new_failures) > 5 else ''} "
                               "didn't build)" if new_failures else ""))
                else:
                    if checks:  # what the project shows (check_rom)
                        manifest = json.loads((fp.root / ".decomp.wtf.json").read_text(encoding="utf-8"))
                        manifest["rebuild"] = after | {"t": time.time()}
                        (fp.root / ".decomp.wtf.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                    if added := paths + sorted(untracked() - there):  # (none: `git commit --` takes what's staged)
                        self._commit_paths(proj, fp, added, f"Analyse the game again: {said}\n\nBy decompdecomp.")
        if kept:
            self.sync(slug, log=log)
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], None, "analysis", said)
        log(said)
        return said if kept else None

    def _merge_left_behind(self, db, proj, gone: list[int]) -> list[int]:
        """The rows of `gone` that are a function still in the project, left behind by a split before _module: each
        one's history (attempts, notes, its best) goes to the function's row, which takes its name back
        (_func_0043AC30' was named past it), and the row goes. Returns the rest."""
        rows = {r["id"]: r for r in db.execute("SELECT * FROM functions WHERE project_id=?", (proj["id"],))}
        present = {(_module(r["unit"] or ""), self._meta(r).get("symbol")): r for fid, r in rows.items()
                   if fid not in gone and not self._meta(r).get("gone")}
        rest = []
        for fid in gone:
            old = rows[fid]
            row = present.get((_module(old["unit"] or ""), self._meta(old).get("symbol")))
            if row is None:
                rest.append(fid)
                continue
            for table in ("attempts", "notes", "twin_misses", "waits"):
                db.execute(f"UPDATE {table} SET function_id=? WHERE function_id=?", (row["id"], fid))
            db.execute("DELETE FROM claims WHERE function_id=?", (fid,))
            better = old["best_source"] and old["best_score"] is not None and row["status"] != "matched" and (
                row["best_score"] is None or old["best_score"] < row["best_score"])
            db.execute("UPDATE functions SET attempts=attempts+?, abandons=abandons+? WHERE id=?",
                       (old["attempts"] or 0, old["abandons"] or 0, row["id"]))
            if better:
                db.execute("UPDATE functions SET best_score=?, best_source=?, best_agent_id=? WHERE id=?",
                           (old["best_score"], old["best_source"], old["best_agent_id"], row["id"]))
            db.execute("DELETE FROM functions WHERE id=?", (fid,))
            del rows[fid]
            symbol = self._meta(row).get("symbol") or row["name"]
            if row["name"].endswith("'") and symbol not in {r["name"] for r in rows.values()}:
                db.execute("UPDATE functions SET name=? WHERE id=?", (symbol, row["id"]))
        return rest

    def reimport(self, slug: str, game: Path, log=print) -> dict:
        """Settings' Reimport for a project decompdecomp made (Console.reimport: PC analyses its program again), every
        match, note and name kept. Returns what the GUI says: functions, matched, and what changed."""
        proj, fp, cfg = self.get(slug)
        if cfg.get("origin") != "scratch" or not consoles.get(cfg.get("platform")).reimports:
            raise NetworkError("this project's own build sets its functions: it can't be reimported")
        said = consoles.get(cfg.get("platform")).reimport(self.net, slug, game, log=log)
        agg = self.net.store.one("SELECT COUNT(*) AS n, COALESCE(SUM(status='matched'), 0) AS m FROM functions WHERE "
                                 "project_id=?", proj["id"])
        return {"slug": slug, "functions": agg["n"], "matched": agg["m"],
                "said": said or "the new analysis changed nothing (or was taken back: the project's feed says why)"}

    def check(self, slug: str, log=print, build: bool = False) -> dict:
        """After a manual setup (or to refresh): pick the project up once it has an objdiff.json. `build` (the
        project page's Re-measure and Check again): its build runs first, so sources changed outside decompdecomp (a
        rollback, an editor) are measured as they are; a measure reads build/ as it is, and a rolled-back Xbox game
        measured its broken build again and again."""
        proj, fp, cfg = self.get(slug)
        if not (fp.root / "objdiff.json").exists():
            raise NetworkError("no objdiff.json yet. The project's build creates it (often `python configure.py` "
                               "or `make`); see its README")
        cfg["ready"] = True
        self._save_cfg(proj, cfg)
        if build:
            log("building what changed since the last build")
            failed: list[str] = []
            with self._tree(proj).exclusive(), self._build_lock(proj):
                fp.build_all(log=log, failed=failed)
                rep = fp.report()
            # a unit whose source doesn't build keeps its last object: what it matched then doesn't count now
            measures = self.sync(slug, log=log, rep=rep, broken=fp.failed_units(failed))
        else:
            measures = self.sync(slug, log=log)
        if fp.linkable():
            self.link_soon(slug)  # files that are finished but not linked yet (in the project as it came, too)
        return measures

    def sync(self, slug: str, log=print, rep: dict | None = None, broken: set[str] = frozenset(),
             agent: Agent | None = None) -> dict:
        """Measure the whole project with objdiff (or take a report just made) and update every function's state.
        Functions in `broken` units (sources that don't build) don't count as matched. Functions that match now and
        didn't before are recorded as matches (credited to `agent`, whose change it was)."""
        proj, fp, cfg = self.get(slug)
        if rep is None:
            log("measuring progress with objdiff")
            try:
                with self._tree(proj).exclusive():  # never read an object while a build writes it
                    rep = fp.report()
            except (ObjdiffError, ForkError) as e:
                raise NetworkError(f"objdiff couldn't measure the project: {e}") from None
        units = {u.name: u for u in fp.units()}
        addresses = consoles.get(cfg.get("platform")).function_addresses(fp)
        data = {n: _data_symbols(u.target) for n, u in units.items()}
        rows = [(u["name"], f) for u in rep.get("units", []) for f in u.get("functions", [])
                if f["name"] not in data.get(u["name"], ())]
        listed = _set_aside(fp)
        aside = listed if fp.scope == GAME else {}  # the whole program: set-aside code is worked on and counted
        console, version = consoles.get(cfg.get("platform")), (fp.manifest or {}).get("version") or cfg.get("version")
        # real names a report doesn't give (a PC game's stay _func_0041B470@8): how the source spells them
        reals = console.real_names(fp, version)
        generated = console.generated_functions(fp, version)  # no C of their own makes them (a PC game's EH stubs)
        registers = console.register_args(fp, version)  # an argument in a register no C declaration passes one in
        statics = console.static_register_args(fp, version)  # ... or a static function's, which C makes
        static_calls = console.static_callees(fp, version)  # (and who calls those)
        joinable = console.joinable_register_args(fp, version)  # (or its callers are one file over: join_files)
        copies = _copies(fp) if fp.scope == GAME else {}  # (and every copy counts too)
        try:  # code no source file can be given (start_files): listed as to do, never handed out, counted forever
            fileless = set(self.code_without_files(slug, rep, never_only=True)["never"])
        except NetworkError:  # (not a dtk project: its code has files, or the console says what it sets aside)
            fileless = set()
        counts: dict[str, int] = defaultdict(int)
        for _, f in rows:
            counts[f["name"]] += 1
        all_rows = self.net.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"])
        existing = {(r["unit"], self._meta(r).get("symbol"), self._meta(r).get("nth", 0)): r for r in all_rows}
        used = {r["name"] for r in all_rows}
        nth: dict[tuple[str, str], int] = defaultdict(int)  # a unit can hold two functions of the same name
        held = {u: self._held(proj, u) for u in {r["unit"] for r in all_rows if '"held"' in (r["meta"] or "")}}
        texts: dict[str, str | None] = {}  # unit -> its source, for functions that match now
        # a function whose code moved to another file of its module (a split) keeps its row: attempts, notes, claims
        here: set[tuple[str, str, int]] = set()
        seen: dict[tuple[str, str], int] = defaultdict(int)
        for uname, f in rows:
            here.add((uname, f["name"], seen[(uname, f["name"])]))
            seen[(uname, f["name"])] += 1
        moved: dict[tuple[str, str], list] = defaultdict(list)  # (module, symbol) -> rows no unit has any more
        for key, r in existing.items():
            if key not in here and key[0]:
                moved[(_module(key[0]), key[1])].append(r)
        with self.net.store.tx() as db:
            for uname, f in rows:
                sym = f["name"]
                k = nth[(uname, sym)]
                nth[(uname, sym)] += 1
                fuzzy = f.get("fuzzy_match_percent") if uname not in broken else None
                size = int(f.get("size", 0))
                n = max(1, size // 4)
                u = units.get(uname)
                md = f.get("metadata") or {}
                meta = {"symbol": sym, "demangled": md.get("demangled_name"), "source": u.source if u else None}
                if k:
                    meta["nth"] = k
                if real := reals.get(sym):
                    meta["real"] = real
                old = existing.get((uname, sym, k))
                if old is None and moved.get((_module(uname), sym)):
                    old = moved[(_module(uname), sym)].pop(0)
                    name = sym if counts[sym] == 1 else f"{sym}@{uname}" + (f"#{k + 1}" if k else "")
                    used.discard(old["name"])
                    while name in used:
                        name += "'"
                    used.add(name)
                    db.execute("UPDATE functions SET unit=?, name=? WHERE id=?", (uname, name, old["id"]))
                if old is not None and "held" in self._meta(old):
                    meta["held"] = self._meta(old)["held"]
                    if sym in held.get(uname, ()):
                        fuzzy = None if fuzzy is None else min(fuzzy, 99.99)
                if old is not None:  # its code grew (pieces joined to it): why it was set aside was about a piece
                    meta.update(kept_meta(self._meta(old), old["size"] == size, old["best_score"]))
                if sym in registers:  # (claimed last, and its brief says why)
                    meta["register_arg"] = registers[sym]
                if sym in statics:
                    meta["static_register_arg"] = statics[sym]
                if sym in static_calls:
                    meta["static_callees"] = static_calls[sym]
                if sym in joinable:
                    meta["join_for_static"] = joinable[sym]
                if sym in generated and not meta.get("reopened"):  # set aside as assembly is, whatever the scope
                    meta["asm_code"] = generated[sym]
                if sym in aside:  # code the project says isn't the game's own (library code, middleware)
                    meta["asm_code"] = aside[sym]
                    meta["set_aside"] = True  # and progress takes it off, as no C code is (network.SET_ASIDE)
                if sym in copies:  # the same code as another program's: counted once, matched by twins
                    meta["copy_of"] = copies[sym]
                status = "matched" if fuzzy is not None and fuzzy >= 100 else "open" if u and u.source else "nosource"
                if status == "nosource" and uname in fileless and not meta.get("reopened"):
                    # a GameCube game's __start, memset and TRK_memset (.init) and __init_cpp_exceptions: the
                    # runtime's start-up code, which no source file of the project covers or can be given
                    meta["asm_code"] = (
                        "code outside .text no source file covers (the runtime's start-up code)" if u.auto else
                        "in an object the project's config lists no source file for (the runtime's, as a rule)")
                    meta["no_file"] = True
                    status = "asm"
                if status == "open" and any(meta.get(k) for k in _ASM_KEYS):
                    status = "asm"  # hand-written assembly (here or in its twin elsewhere): not for agents
                score = None if fuzzy is None else scaled(fuzzy, n)
                vram = md.get("virtual_address")
                if vram is None:
                    vram = addresses.get((uname, sym))
                vram = int(vram) if vram is not None else old["vram"] if old is not None else None
                if old is None:
                    name = sym if counts[sym] == 1 else f"{sym}@{uname}" + (f"#{k + 1}" if k else "")
                    while name in used:
                        name += "'"
                    used.add(name)
                    db.execute("INSERT INTO functions(project_id,name,size,n_insns,status,best_score,unit,vram,meta,asm) "
                               "VALUES(?,?,?,?,?,?,?,?,?,?)", (proj["id"], name, size, n, status, score, uname,
                                                              vram, json.dumps(meta), ""))
                else:
                    # a better attempt kept elsewhere stays the best; a 0 (identical) of a function that no longer
                    # matches doesn't: the queue and briefs would say it's done
                    if status != "matched" and old["best_source"] and old["best_score"] and old["status"] != "matched":
                        score = old["best_score"] if score is None else min(score, old["best_score"])
                    # only what changed: SQLite writes a row's pages even when its values are the same, and a
                    # GameCube game's 34,000 functions rewritten on every sync were most of what the app wrote
                    if (old["size"], old["n_insns"], old["status"], old["best_score"], self._meta(old), old["vram"]) != \
                            (size, n, status, score, meta, vram):
                        db.execute("UPDATE functions SET size=?, n_insns=?, status=?, best_score=?, meta=?, vram=? WHERE id=?",
                                   (size, n, status, score, json.dumps(meta), vram, old["id"]))
                    if old["status"] == "matched" and status != "matched":
                        self._reopened(db, proj, old, "full report" + (", the unit doesn't build" if uname in broken
                                                                         else ""), fuzzy,
                                       held=fuzzy is not None and sym in held.get(uname, ())
                                       and float(f.get("fuzzy_match_percent") or 0) >= 100)
                    if status == "matched" and old["status"] != "matched":
                        if uname not in texts:
                            try:
                                texts[uname] = (fp.root / u.source).read_text(errors="replace",
                                                                              encoding="utf-8") if u and u.source else None
                            except OSError:
                                texts[uname] = None
                        self._matched(db, proj, old, agent, texts[uname])
            gone = [r["id"] for rs in moved.values() for r in rs]  # functions no unit has any more
            gone = self._merge_left_behind(db, proj, gone)
            if gone:
                with_history = {r["function_id"] for r in db.execute(
                    f"SELECT DISTINCT function_id FROM attempts WHERE function_id IN ({','.join('?' * len(gone))})", gone)}
                for fid in gone:
                    if fid in with_history:
                        db.execute("UPDATE functions SET status='nosource', meta=json_set(COALESCE(meta, '{}'), "
                                   "'$.gone', 1) WHERE id=?", (fid,))  # (network.IN_BUILD)
                    else:
                        for table in ("claims", "notes", "compiler_tests"):
                            db.execute(f"DELETE FROM {table} WHERE function_id=?", (fid,))
                        db.execute("DELETE FROM functions WHERE id=?", (fid,))
            m = objdiff.game_measures(rep, set(aside) | set(copies))  # % of the game's own code, each copy once
            if said := progress_moved(cfg.get("measures"), m):
                self.net._event(db, proj["id"], None, "sync", said)
        log(f"{m.get('matched_functions', 0)}/{m.get('total_functions', 0)} functions match, "
            f"{float(m.get('matched_code_percent', 0)):.2f}% of code")
        cfg["measures"] = m
        cfg["uncovered"] = self._count_uncovered(rep)
        # what the project's set-aside list names, whatever its scope: the Settings panel's choice says how many
        mine = [uname for uname, f in rows if f["name"] in listed]
        cfg["set_aside"] = {"functions": len(mine), "without_source": sum(
            1 for uname in mine if not (units.get(uname) and units[uname].source))} if mine else None
        every_copy = _copies(fp)  # (whatever its scope: Settings says how many)
        cfg["copies"] = sum(1 for _, f in rows if f["name"] in every_copy) or None
        self._save_cfg(proj, cfg)
        if cfg.get("ready"):
            self.start_indexing(slug)
        return m

    # ------------------------------------------------------------------ linking
    # The end of a decomp is not a matching function but a linked file: configure.py marks it Matching, the game is
    # built from its C and checked against its checksums. decompdecomp does that for every file the moment its code and
    # data match, and keeps it only when the whole game still builds byte for byte.

    @staticmethod
    def _finished(unit: dict) -> bool:
        m = unit.get("measures") or {}
        tc, td = int(m.get("total_code") or 0), int(m.get("total_data") or 0)
        return bool(tc or td) and int(m.get("matched_code") or 0) == tc and int(m.get("matched_data") or 0) == td

    @staticmethod
    def _code_done(unit: dict) -> bool:
        m = unit.get("measures") or {}
        return int(m.get("matched_code") or 0) == int(m.get("total_code") or 0)

    @staticmethod
    def _data_alike(fp: ForkProject, name: str) -> bool:
        """Whether a unit's data is the original's byte for byte, only named or cut differently (datadiff.same_layout:
        objdiff pairs data by name, and a file whose strings were one label in the project's symbols and five literals
        in its C never counted as matching)."""
        try:
            u = fp.unit(name)
            return u.target is not None and u.target.exists() and datadiff.same_layout(u.target, u.base)
        except (ForkError, ELFError, OSError, ValueError):
            return False

    def link_candidates(self, proj, fp: ForkProject, rep: dict) -> list[str]:
        """Source files not linked yet whose every unit matches in code and data (and loads the original's constants):
        data objdiff counts as matching, or the original's bytes named or cut differently. The link decides."""
        states = fp.link_states()
        units: dict[str, list[dict]] = defaultdict(list)
        for u in rep.get("units", []):
            src = (u.get("metadata") or {}).get("source_path")
            if src:
                units[src].append(u)
        return sorted(src for src, us in units.items() if states.get(src, ("",))[0] == "NonMatching"
                      and all((self._finished(u) or (self._code_done(u) and self._data_alike(fp, u["name"])))
                              and not self._held(proj, u["name"]) for u in us))

    def link(self, slug: str, log=print, agent: Agent | None = None) -> dict:
        """Link every finished file into the game, keeping only what the project's checksum check accepts."""
        proj, fp, cfg = self.get(slug)
        if not fp.linkable():
            return {"linked": [], "failed": {}, "note": "this project has no link step decompdecomp knows (dtk-template)"}
        with self._tree(proj).exclusive(), self._build_lock(proj):
            fp.build_all()
            rep = fp.report()
            todo = self.link_candidates(proj, fp, rep)
            bare = self._code_only(fp, cfg, todo)
            if bare and not set(bare) <= self._data_tried(cfg)["files"]:
                # a file whose data is still dtk's (auto units) compares 0 bytes of data and looks finished: its C's
                # constants and globals would be defined twice. It gets its data first, then has to match it too.
                self._give_data(proj, fp, cfg, log, agent, tried=bare)
                rep = fp.report()
                todo = self.link_candidates(proj, fp, rep)
            tried = self._data_tried(cfg)
            if stuck := sorted(set(self._code_only(fp, cfg, todo)) & tried["failed"]):
                # its data couldn't be given to it: linked without it, its C defines what dtk's units define too, and
                # the build fails every time. A GameCube game's link backed out with no word anywhere of why.
                todo = [s for s in todo if s not in stuck]
                self._remember_link_failures(proj, [], {s: f"{datajobs.NOT_GIVEN}, so it wasn't linked: "
                                                           f"{tried['error']}" for s in stuck})
            todo = self._fresh_first(fp, cfg, todo)
            if not todo:
                return {"linked": [], "failed": {}}
            conf = fp.root / "configure.py"
            original = conf.read_text(errors="replace", encoding="utf-8")
            ok, out = fp.verify()
            if not ok:
                error = f"the project's checksum check fails before linking anything, so nothing was linked:\n{_tail(out)}"
                self._note_link(proj, error=error)
                return {"linked": [], "failed": {}, "error": error}

            def build_with(sources: list[str]) -> tuple[bool, str]:
                conf.write_text(fp.marked_matching(original, sources, cfg.get("version")), encoding="utf-8")
                return fp.verify()

            log(f"linking {len(todo)} finished file(s)")
            linked: list[str] = []
            failed: dict[str, str] = {}
            kept, together = False, ""
            try:
                ok, out = build_with(todo)
                if ok:
                    linked = todo
                else:  # one at a time, so one file that doesn't link keeps none of the others out
                    for src in todo[:LINK_ONE_BY_ONE]:
                        ok, out = build_with([*linked, src])
                        if ok:
                            linked.append(src)
                        else:
                            failed[src] = _tail(out)
                            if "FAILED" in out:  # (the checksum's one line says nothing to fix: say where it differs)
                                failed[src] += "\n" + dolcheck.report(fp.root, cfg.get("version") or (fp.versions() or [""])[0])
                    ok, out = build_with(linked)
                    if not ok:  # (it built a moment ago with these: no file's failure, but said)
                        together = f"the files that linked one by one didn't build again together:\n{_tail(out)}"
                        linked = []
                self._remember_link_failures(proj, linked, failed)
                if not linked:
                    self._note_link(proj, failed=failed, error=together)
                    return {"linked": [], "failed": failed}
                names = ", ".join(Path(s).name for s in linked[:6]) + (f" and {len(linked) - 6} more" if len(linked) > 6 else "")
                who = f"\n\nLinked by decompdecomp after {agent.name}'s match." if agent else "\n\nLinked by decompdecomp."
                self._commit(proj, fp, "configure.py", f"Link {names}\n\nEvery function and all data match, and the "
                                                       f"game still builds byte for byte from the C.{who}")
                kept = True
            except (ForkError, OSError) as e:
                self._note_link(proj, error=f"linking stopped: {e}")
                raise
            finally:
                if not kept:  # (whatever stopped it: configure.py as it was, and the game built from it)
                    conf.write_text(original, encoding="utf-8")
                    fp.verify()
            self._note_link(proj, linked=linked, failed=failed)
            with self.net.store.tx() as db:
                for src in linked:
                    self.net._event(db, proj["id"], agent.id if agent else None, "link", src)
            self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
            self.sync(slug, log=lambda *_: None, rep=fp.report())
        log(f"linked {len(linked)} file(s)" + (f"; {len(failed)} didn't link" if failed else ""))
        return {"linked": linked, "failed": failed}

    def _verify(self, proj, fp: ForkProject) -> tuple[bool, str]:
        with self._build_lock(proj):
            return fp.verify()

    def _file_done(self, slug: str, proj, fp: ForkProject, unit, scores: dict, agent: Agent | None) -> str:
        """When every function of a file matches: link it (in the background), or say what its data still needs."""
        if (unit.complete or not unit.source or not fp.linkable() or not scores
                or any(v is None or v < 100 for v in scores.values())):
            return ""
        data = self._data_status(unit)
        self.link_soon(slug, agent)  # the checksum decides; the comparison below is what to fix if it fails
        if data is None:  # (objects whose data can't be compared here)
            return f"\n🔗 Every function in {unit.source} matches: decompdecomp is linking the file into the game now."
        if not data:
            return (f"\n🔗 Every function and all data in {unit.source} match: decompdecomp is linking the file into the "
                    "game now (it stays linked if the game still builds byte for byte).")
        return (f"\n🔗 Every function in {unit.source} matches. To link the file into the game (the goal: the game "
                f"built from this C), its data must match too. Fix it with edit_file, then file_status to check:\n{data}")

    def _data_status(self, unit, max_rows: int = 40) -> str | None:
        """The file's data sections that differ from the original's ("" when all match, None when there's no
        verdict: COFF objects, PC and Xbox, which pyelftools can't read)."""
        if unit.target is None or not unit.target.exists():
            return ""
        try:
            if datadiff.same_layout(unit.target, unit.base):  # (named or cut differently: the same bytes link)
                return ""
            shown = datadiff.render(datadiff.compare(unit.target, unit.base), max_rows)
            if not shown and (lines := datadiff.layout(unit.target, unit.base)[1]):  # (its layout, then)
                shown = "\n".join(["differs from the original's, names aside:", *(f"- {line}" for line in lines[:12])])
            return shown
        except ELFError:  # "Magic number does not match" was shown as "data: differs" (legobatman, PC)
            return None
        except Exception as e:  # an object pyelftools can't read: say so rather than fail the tool
            return f"(couldn't compare the data: {e})"

    def file_status(self, slug: str, path: str) -> str:
        """A source file on its way to being linked: its functions, its data next to the original's, and why the last
        link attempt failed."""
        proj, fp, cfg = self.get(slug)
        rel = path.strip().lstrip("./")
        units = fp.units_for(rel)
        if not units:  # a function name: its file
            try:
                fn = self._fn(slug, path)
                units, rel = [fp.unit(fn["unit"])], fp.unit(fn["unit"]).source or ""
            except (NetworkError, ForkError):
                raise NetworkError(f"{path} isn't a source file of a unit (or a function) in this project") from None
        state = fp.link_states().get(rel, ("",))[0]
        lines = [f"## {rel}"]
        lines.append("🔗 LINKED: the game is built from this file's C and checked byte for byte." if state == "Matching"
                     else f"not linked yet ({state or 'not in configure.py'})" if fp.linkable()
                     else "this project isn't linked file by file (each function is compared on its own)")
        for u in units:
            rows = self.net.store.all("SELECT name, status, n_insns FROM functions WHERE project_id=? AND unit=? "
                                      "ORDER BY vram, name", proj["id"], u.name)
            left = [r for r in rows if r["status"] != "matched"]
            lines.append(f"unit {u.name}: " + ("no functions (data only)" if not rows else
                         f"{len(rows) - len(left)}/{len(rows)} functions match")
                         + (": still to do " + ", ".join(f"{r['name']} ({r['n_insns']} insns)" for r in left[:12])
                            if left else ""))
            if state != "Matching" and (data := self._data_status(u)) is not None:
                lines.append(f"data: {'matches' if not data else 'differs'}" + (f"\n{data}" if data else ""))
        try:
            mods = self._modules(fp, cfg)
            src = fp.src_dir()
            name = rel[len(src) + 1:] if rel.startswith(src + "/") else rel
            for module, mod in mods.items():
                for f in dtksplits.Splits.parse(mod.splits.read_text(encoding="utf-8")).files:
                    if f.name == name:
                        lines.append(f"{module} sections: " + ", ".join(f"{k} 0x{a:X}-0x{b:X}" for k, (a, b) in f.sections.items())
                                     + " (split_file divides it)")
        except (NetworkError, OSError):
            pass
        why = self.link_failures(fp.root, cfg).get(rel)
        if why and state != "Matching":
            lines += ["", "The last try to link it failed (the game didn't build identically):", why]
        return "\n".join(lines)

    @staticmethod
    def link_failures(root: Path, cfg: dict) -> dict[str, str]:
        """{source: why} of each file's last failed link, only those since the project's split config (config/) last
        changed: what failed before is about objects that aren't built any more. A GameCube game's briefs kept a
        "multiply-defined ... in auto_08_..._bss.o" from before its files were given their data, and its helpers took
        it for a link step they had to fix."""
        failed = cfg.get("link_failed") or {}
        if not failed:
            return {}
        at = cfg.get("link_failed_at") or {}  # (none for one recorded before this: when, unknown, so stale)
        changed = config_changed(root)
        return {src: why for src, why in failed.items() if at.get(src, 0.0) >= changed}

    def _fresh_first(self, fp: ForkProject, cfg: dict, todo: list[str]) -> list[str]:
        """The candidates a link tries: a file whose last link failed waits until something it's built from changed
        since (its source, a header, the split config), and those that never failed come first. The same 40 failing
        files of a GameCube game were tried after every match."""
        at = cfg.get("link_failed_at") or {}
        failed = self.link_failures(fp.root, cfg)
        if not failed:
            return todo
        src_dir = fp.root / fp.src_dir()
        shared = max([config_changed(fp.root), *(p.stat().st_mtime for p in (fp.root / "include").rglob("*")
                                                 if p.is_file())] if (fp.root / "include").is_dir() else [0.0])

        def changed(src: str) -> float:
            try:
                return max(shared, (fp.root / src).stat().st_mtime if (fp.root / src).exists()
                           else (src_dir / src).stat().st_mtime)
            except OSError:
                return shared

        return sorted((s for s in todo if s not in failed or changed(s) > at.get(s, 0.0)),
                      key=lambda s: (s in failed, at.get(s, 0.0), s))

    def _note_link(self, proj, linked: list[str] = (), failed: dict | None = None, error: str = "") -> None:
        """What the last link did, for the files' page and the helpers' stop: a link whose checksum check failed
        before it began stopped linking for good, saying nothing anywhere."""
        cfg = json.loads(self.net.store.one("SELECT config FROM projects WHERE id=?", proj["id"])["config"])
        cfg["link_last"] = {"at": time.time(), "linked": list(linked), "failed": sorted(failed or ()), "error": error[-2000:]}
        self._save_cfg(proj, cfg)

    def link_note(self, slug: str) -> str:
        """Why linking stopped, when the last link said so ("" otherwise)."""
        proj = self.net._project(slug)
        return (json.loads(proj["config"]).get("link_last") or {}).get("error") or ""

    def _remember_link_failures(self, proj, linked: list[str], failed: dict[str, str]) -> None:
        cfg = json.loads(self.net.store.one("SELECT config FROM projects WHERE id=?", proj["id"])["config"])
        known, at = cfg.get("link_failed") or {}, cfg.get("link_failed_at") or {}
        for src in linked:
            known.pop(src, None)
            at.pop(src, None)
        known.update(failed)
        at.update(dict.fromkeys(failed, time.time()))
        cfg["link_failed"], cfg["link_failed_at"] = known, {s: t for s, t in at.items() if s in known}
        self._save_cfg(proj, cfg)

    def link_soon(self, slug: str, agent: Agent | None = None) -> None:
        """Link in the background (one run per project at a time; another request while it runs runs it again)."""
        with self._mlock:
            state = self._linking.setdefault(slug, {"running": False, "again": False})
            if state["running"]:
                state["again"] = True
                return
            state["running"] = True

        def run() -> None:
            while True:
                try:
                    self.link(slug, log=lambda *_: None, agent=agent)
                except Exception:  # a background tidy-up: the next match tries again (the log says why this one failed)
                    logging.getLogger("decompdecomp").exception("%s: linking failed", slug)
                with self._mlock:
                    if not state["again"]:
                        state["running"] = False
                        return
                    state["again"] = False

        threading.Thread(target=run, daemon=True, name=f"link-{slug}").start()

    # ------------------------------------------------------------------ each file's data
    # A game started from scratch gives its files only code (.text): its data stays in dtk's auto units, so a file's
    # data can be neither compared nor linked. forks/dtkdata.py works out which stretch of each data section is whose;
    # decompdecomp gives it to them and keeps the change only if the game still builds byte for byte and no function
    # stops matching.

    def _code_only(self, fp: ForkProject, cfg: dict, sources: list[str]) -> list[str]:
        """The source files among these whose splits give them no data section."""
        if not sources or fp.kind() not in ("dtk", "manifest") or not fp.linkable():
            return []
        try:
            mods = self._modules(fp, cfg)
        except NetworkError:
            return []
        src = fp.src_dir()
        out = []
        for mod in mods.values():
            try:
                files = dtksplits.Splits.parse(mod.splits.read_text(encoding="utf-8")).files
            except OSError:
                continue
            out += [f"{src}/{f.name}" for f in files
                    if f"{src}/{f.name}" in sources and ".text" in f.sections and not set(f.sections) & set(dtkdata.DATA)]
        return sorted(out)

    def _data_plan(self, fp: ForkProject, cfg: dict) -> dict:
        """module -> (its Module, its parsed splits, {file: {section: (start, end)}}) for the modules with data to give."""
        mods = self._modules(fp, cfg)
        src = fp.src_dir()
        states = fp.link_states()
        units = {u.name: u for u in fp.units()}
        plans = {}
        for module, mod in mods.items():
            sp = dtksplits.Splits.parse(mod.splits.read_text(encoding="utf-8"))
            uses = {}
            for f in sp.files:
                u = units.get(f"{module}/{PurePosixPath(f.name).with_suffix('')}")
                if ".text" not in f.sections or u is None or u.target is None or not u.target.exists():
                    continue
                try:  # (the original's object: what its code refers to)
                    uses[f.name] = dtkdata.code_refs(u.target)
                except (ELFError, OSError):
                    continue
            # a linked file's object is built from its C, which defines its own data: it keeps what it has
            linked = {f.name for f in sp.files if states.get(f"{src}/{f.name}", ("NonMatching",))[0] != "NonMatching"}
            given = dtkdata.parts(sp.files, dtksplits.symbols(mod.symbols), uses, skip=linked)
            if given:
                plans[module] = (mod, sp, given)
        return plans

    def give_data(self, slug: str, log=print, agent: Agent | None = None) -> dict:
        """Give every file that has only code its part of the game's data (see _data_plan)."""
        proj, fp, cfg = self.get(slug)
        self._modules(fp, cfg)  # (says why when the project isn't dtk-template)
        with self._tree(proj).exclusive(), self._build_lock(proj):
            self._put_back_config(proj, fp)
            fp.build_all()
            return self._give_data(proj, fp, cfg, log, agent)

    def _give_data(self, proj, fp: ForkProject, cfg: dict, log, agent: Agent | None, tried: list[str] = ()) -> dict:
        """give_data, with the tree held alone and the project built. tried: the files that asked for it (link), so a
        change that doesn't build isn't tried again for them."""
        if tried:
            self._note_data_try(proj, cfg, tried)
        try:
            plans = self._data_plan(fp, cfg)
        except (NetworkError, OSError, ValueError) as e:
            return {"files": [], "error": str(e)}
        if not plans:
            return {"files": []}
        src = fp.src_dir()
        matched = _matched_in(fp.report())
        saved: dict[Path, str] = {}
        given: list[str] = []
        renames: dict[tuple[str, str], str] = {}
        size = 0
        program_before = self._built_before(fp)
        try:
            for mod, sp, parts in plans.values():
                saved[mod.splits] = mod.splits.read_text(encoding="utf-8")
                dtkdata.apply(sp.header, sp.files, parts)
                mod.splits.write_text(sp.render(), encoding="utf-8")
                given += [f"{src}/{name}" for name in parts]
                size += sum(b - a for secs in parts.values() for a, b in secs.values())
            log(f"giving {len(given)} file(s) their data ({size:,} bytes); the build splits the game again")
            ok, out = self._still_builds(fp, program_before)
            if not ok:
                raise ForkError(f"the game didn't build as it did with the files' data:\n{_tail(out)}")
            fp.build_all()
            rep = fp.report()
            if renames := _named_back(matched - _matched_in(rep), rep):
                # dtk names a file's local symbol name_<address> once another object refers to it, and its plain name
                # again once that reference (the data) is the file's own: a GameCube game's long2str_8009C164 became
                # long2str, its C still defined the old name, objdiff paired nothing and the data was taken back
                log(f"{len(renames)} function(s) have their own names again: "
                    + ", ".join(f"{old} → {new}" for (_, old), new in list(renames.items())[:6]))
                saved.update(self._rename_words(fp, {old: new for (_, old), new in renames.items()}))
                fp.build_all()
                rep = fp.report()
            now = _matched_in(rep)
            if lost := sorted(k for k in matched - now if (k[0], renames.get(k)) not in now):
                raise ForkError(f"{len(lost)} function(s) stopped matching once their files had their data: "
                                + ", ".join(f"{name} ({unit})" for unit, name in lost[:8]))
        except (ForkError, ObjdiffError, OSError, ValueError) as e:
            for path, old in saved.items():
                path.write_text(old, encoding="utf-8")
            fp.verify()
            fp.build_all()
            log(f"the files keep only their code: {e}")
            logging.getLogger("decompdecomp").warning("%s: the files keep only their code: %s", proj["slug"], e)
            if tried:
                self._note_data_try(proj, cfg, tried, error=str(e))
            return {"files": [], "error": f"nothing was changed: {e}"}
        if tried:
            self._note_data_try(proj, cfg, tried, error="")
        paths = [p.relative_to(fp.root).as_posix() for p in saved]
        self._commit_paths(proj, fp, paths, f"Give {len(given)} files their data ({size:,} bytes)\n\n"
                           "Each file covered only its code; the data its functions use is now its own (in link order, "
                           "the way the linker laid it out), so it can be compared and linked. The game still builds "
                           "byte for byte."
                           + (f"\n\n{len(renames)} function(s) dtk named after their address while another file referred "
                              "to them have their own names again: " + ", ".join(
                                  f"{old} → {new}" for (_, old), new in renames.items()) if renames else "")
                           + "\n\nSplit by decompdecomp.")
        with self.net.store.tx() as db:
            if renames:
                self._renamed_rows(db, proj, renames)
            self.net._event(db, proj["id"], agent.id if agent else None, "files",
                            f"{len(given)} files given their data ({size:,} bytes)")
        self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
        self.sync(proj["slug"], log=lambda *_: None, rep=rep)
        log(f"{len(given)} file(s) now have their data")
        return {"files": given, "bytes": size, "renamed": {old: new for (_, old), new in renames.items()}}

    @staticmethod
    def _data_tried(cfg: dict) -> dict:
        """The files the data step was tried for by this copy of the app, and those it failed for (with why). A try
        by an earlier copy doesn't count: the fix that makes it work is what an update brings."""
        t = cfg.get("data_tried")
        if not isinstance(t, dict) or t.get("version") != __version__:
            return {"files": set(), "failed": set(), "error": ""}
        return {"files": set(t.get("files") or ()), "failed": set(t.get("failed") or ()), "error": t.get("error") or ""}

    def _note_data_try(self, proj, cfg: dict, tried, error: str | None = None) -> None:
        """Record a data step for these files: begun (error None), done (""), or backed out (why)."""
        fresh = json.loads(self.net.store.one("SELECT config FROM projects WHERE id=?", proj["id"])["config"])
        t = self._data_tried(fresh)
        t["files"] |= set(tried)
        if error:
            t["failed"] |= set(tried)
            t["error"] = error
        elif error is not None:
            t["failed"] -= set(tried)
        fresh["data_tried"] = cfg["data_tried"] = {"version": __version__, "files": sorted(t["files"]),
                                                   "failed": sorted(t["failed"]), "error": t["error"]}
        self._save_cfg(proj, fresh)

    def _rename_words(self, fp: ForkProject, names: dict[str, str]) -> dict[Path, str]:
        """Each old name as a whole word in the project's sources and headers, as the new; {file: its old text}."""
        word = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b")
        saved = {}
        for d in ("src", "include"):
            if not (fp.root / d).is_dir():
                continue
            for p in sorted((fp.root / d).rglob("*")):
                if p.is_file() and p.suffix in self.SOURCE_SUFFIXES:
                    text = p.read_text(errors="replace", encoding="utf-8")
                    if word.search(text):
                        saved[p] = text
                        p.write_text(word.sub(lambda m: names[m.group(1)], text), encoding="utf-8")
        return saved

    def _renamed_rows(self, db, proj, renames: dict[tuple[str, str], str]) -> None:
        """Functions dtk named back keep their rows (matches, attempts, notes) and their stored C, under the new name."""
        names = {old: new for (_, old), new in renames.items()}
        word = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b")
        used = {r["name"] for r in db.execute("SELECT name FROM functions WHERE project_id=?", (proj["id"],))}
        for r in db.execute("SELECT id, best_source, matched_source FROM functions WHERE project_id=? AND "
                            "(best_source IS NOT NULL OR matched_source IS NOT NULL)", (proj["id"],)).fetchall():
            best, done = (word.sub(lambda m: names[m.group(1)], t) if t else t for t in (r["best_source"], r["matched_source"]))
            if (best, done) != (r["best_source"], r["matched_source"]):
                db.execute("UPDATE functions SET best_source=?, matched_source=? WHERE id=?", (best, done, r["id"]))
        for (unit, old), new in renames.items():
            name = new if new not in used else f"{new}@{unit}"
            used.add(name)
            db.execute("UPDATE functions SET name=?, meta=json_set(COALESCE(meta, '{}'), '$.symbol', ?) WHERE "
                       "project_id=? AND unit=? AND json_extract(meta, '$.symbol')=?", (name, new, proj["id"], unit, old))

    # ------------------------------------------------------------------ source files for all the code
    # A stretch is cut into files of at most FILE_FUNCTIONS functions: a GameCube game's one stretch of 16,695 in one
    # file made every claim and compile read all of them (objdiff's whole unit, 17 s and 32 s each; with 8 agents
    # waiting on one another, minutes: they timed out). Files this size are what contributors start from too.
    # Code no source file covers (dtk's auto_..._text units) can't be decompiled: there's nowhere to write it. Real
    # projects split it into files by hand. decompdecomp gives each such stretch of code a file of its own, the way
    # contributors start (split_file divides one further), and keeps the change only if the game still builds byte
    # for byte. A file listed in configure.py that doesn't exist yet gets created too.

    def _modules(self, fp: ForkProject, cfg: dict) -> dict:
        if fp.kind() not in ("dtk", "manifest") or not fp.linkable():
            raise NetworkError("giving code source files works on dtk-template projects (GameCube, Wii)")
        version = cfg.get("version") or (fp.versions() or [None])[0]
        try:
            return dtksplits.modules(fp.root, version)
        except (OSError, ValueError) as e:
            raise NetworkError(f"can't read the project's config for {version}: {e}") from None

    @staticmethod
    def _text_extent(unit, syms: dict) -> tuple[int, int] | None:
        """(start, end) in .text of an auto unit's code: its first symbol's address, its object's .text size."""
        from io import BytesIO

        from elftools.elf.elffile import ELFFile

        try:
            elf = ELFFile(BytesIO(unit.target.read_bytes()))
        except (OSError, AttributeError):
            return None
        sec = elf.get_section_by_name(".text")
        tab = elf.get_section_by_name(".symtab")
        if sec is None or tab is None or not sec["sh_size"]:
            return None
        idx = next(i for i, x in enumerate(elf.iter_sections()) if x.name == ".text")
        first = min(((x["st_value"], x.name) for x in tab.iter_symbols()
                     if x["st_shndx"] == idx and x.name and x["st_info"]["type"] == "STT_FUNC"), default=None)
        if first is None or first[1] not in syms or syms[first[1]][0] != ".text":
            return None
        start = syms[first[1]][1] - first[0]
        return start, start + sec["sh_size"]

    def code_without_files(self, slug: str, rep: dict | None = None, never_only: bool = False) -> dict:
        """What start_files would do: {"create": [source paths of listed files that don't exist],
        "split": [(module, source path, start, end, functions)]}, and "never": the units without a source file it
        can't give one (code outside .text, dtk's auto_..._init: the runtime's start-up code; an object the config
        doesn't list as a file), whose functions sync sets aside."""
        proj, fp, cfg = self.get(slug)
        mods = self._modules(fp, cfg)
        src = fp.src_dir()
        if rep is None:
            try:
                rep = json.loads((fp.root / STATE / "report.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                rep = {}
        rep_fns = {u["name"]: len(u.get("functions", [])) for u in rep.get("units", [])}
        cpp = {u["name"] for u in rep.get("units", [])  # code with C++ names goes in a C++ file
               if any((f.get("metadata") or {}).get("demangled_name") not in (None, f["name"]) for f in u.get("functions", []))}
        create, split, taken, never = [], [], set(), []
        listed = fp.link_states()
        parsed: dict[str, list] = {}  # module -> its splits' files (read once, not once per unit)
        for u in fp.units():
            module, _, rest = u.name.partition("/")
            if u.source or module not in mods:
                continue
            if not u.auto:
                if module not in parsed:
                    parsed[module] = dtksplits.Splits.parse(mods[module].splits.read_text(encoding="utf-8")).files
                made = [f"{src}/{f.name}" for f in parsed[module]  # (a unit name has /: on Windows Path said game\player)
                        if str(PurePosixPath(f.name).with_suffix("")) == rest and f"{src}/{f.name}" in listed]
                create += made
                if not made:
                    never.append(u.name)
                continue
            if not rest.endswith("_text"):
                never.append(u.name)
                continue
            if never_only or not rep_fns.get(u.name, 1):  # (sync asks only what can't have a file: no objects read)
                continue
            extent = self._text_extent(u, dtksplits.symbols(mods[module].symbols))
            if extent is None:
                continue
            folder = "auto" if module == "main" else f"REL/{module}"
            ext = ".cpp" if u.name in cpp else ".c"
            starts = self._starts(dtksplits.symbols(mods[module].symbols, labels=False), *extent)
            cuts = [extent[0], *starts[FILE_FUNCTIONS::FILE_FUNCTIONS], extent[1]]
            for lo, hi in zip(cuts, cuts[1:]):
                name = f"{folder}/text_{lo:08X}{ext}"
                while name in taken or (fp.root / src / name).exists() or f"{src}/{name}" in listed:
                    name = name[:-len(ext)] + "_" + ext
                taken.add(name)
                n = sum(1 for a in starts if lo <= a < hi) if len(cuts) > 2 else rep_fns.get(u.name, 0)
                split.append((module, name, lo, hi, n))
        return {"create": sorted(set(create)), "split": sorted(split), "never": sorted(never)}

    def start_files(self, slug: str, log=print, agent: Agent | None = None) -> dict:
        """Give all code a source file: create files configure.py lists, split off a file for every stretch of
        code no file covers. Verified by the game's checksum, committed, measured."""
        proj, fp, cfg = self.get(slug)
        mods = self._modules(fp, cfg)
        src = fp.src_dir()
        conf = fp.root / "configure.py"
        with self._tree(proj).exclusive(), self._build_lock(proj):
            self._put_back_config(proj, fp)  # (a try's leftover isn't committed with this change)
            fp.build_all()
            plan = self.code_without_files(slug, fp.report())
            divided = self._divide_big_files(proj, fp, mods, src, fp.report(), log)
            if not plan["create"] and not plan["split"]:
                if divided:
                    self.sync(slug, log=lambda *_: None, rep=fp.report())
                return {"created": [], "split": divided, "functions": 0}
            saved = {conf: conf.read_text(encoding="utf-8")}
            made: list[Path] = []
            program_before = self._built_before(fp)
            try:
                for path in plan["create"]:
                    p = fp.root / path
                    if not p.exists():
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_text("", encoding="utf-8")
                        made.append(p)
                by_module: dict[str, list] = defaultdict(list)
                for item in plan["split"]:
                    by_module[item[0]].append(item)
                text = saved[conf]
                for module, items in by_module.items():
                    sp_path = mods[module].splits
                    saved.setdefault(sp_path, sp_path.read_text(encoding="utf-8"))
                    sp = dtksplits.Splits.parse(saved[sp_path])
                    for _, name, start, end, _n in items:
                        sp.files.append(dtksplits.FileSplit(name, {".text": (start, end)}))
                        p = fp.root / src / name
                        p.parent.mkdir(parents=True, exist_ok=True)
                        common = '#include "common.h"\n' if (fp.root / "include" / "common.h").is_file() else ""
                        p.write_text(f"// Code of {module} that had no source file yet: decompdecomp gave it this one.\n"
                                     "// split_file divides it into the game's real files (file_status shows its range).\n"
                                     + common, encoding="utf-8")
                        made.append(p)
                    sp_path.write_text(sp.render(), encoding="utf-8")
                    text = dtksplits.add_objects(text, module, [name for _, name, _, _, _ in items])
                conf.write_text(text, encoding="utf-8")
                log(f"giving {len(plan['split'])} stretch(es) of code a source file; the build splits the game again")
                ok, out = self._still_builds(fp, program_before)
                if not ok:
                    raise ForkError(f"the game didn't build as it did with the new files:\n{_tail(out)}")
            except (ForkError, OSError, ValueError) as e:
                for path, old in saved.items():
                    path.write_text(old, encoding="utf-8")
                for p in made:
                    p.unlink(missing_ok=True)
                fp.verify()
                raise NetworkError(f"nothing was changed: {e}") from None
            fp.build_all()
            rep = fp.report()
            paths = [p.relative_to(fp.root).as_posix() for p in [*saved, *made]]
            n = sum(item[4] for item in plan["split"])
            self._commit_paths(proj, fp, paths, f"Give code without a source file one ({len(made)} files, {n} functions)\n\n"
                               "Each stretch of code no file covered gets a file of its own, so it can be decompiled; "
                               "the game still builds byte for byte.\n\nSplit by decompdecomp.")
            self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
            self.sync(slug, log=lambda *_: None, rep=rep)
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id if agent else None, "files",
                                f"{len(made)} new source files for {n} functions")
        log(f"{len(made)} new source files; {n} more functions can be decompiled")
        return {"created": plan["create"], "split": [i[1] for i in plan["split"]], "functions": n}

    @staticmethod
    def _built_before(fp: ForkProject) -> str | None:
        """Before a change of the files' layout (a cut, a split, new files, files' data): None when the game builds
        byte for byte, else a digest of what it builds (ForkProject.built_digest), which the change must leave as it
        is (_still_builds)."""
        ok, _ = fp.verify()
        return None if ok else (fp.built_digest() or "")

    @staticmethod
    def _still_builds(fp: ForkProject, before: str | None) -> tuple[bool, str]:
        """After such a change: whether the game builds as it did. One that built byte for byte must still; one that
        doesn't yet (a Wii game imported from its main.dol, its DOL a few bytes off) must build the very same
        program as before the change, every file cut or divided still linking the game's own code in its place: else
        each of its 13 big files was refused a cut, though no cut changed a byte of what it built."""
        ok, out = fp.verify()
        if ok or (before and fp.built_digest() == before):
            return True, out
        return False, out

    @staticmethod
    def _starts(syms: dict, lo: int, hi: int) -> list[int]:
        """Where code in .text [lo, hi) may be cut: each symbol's start that's inside no other symbol (not
        __save_gpr's _savegpr_14..31 labels, which dtk refuses a file to end within)."""
        out, end = [], lo
        for a, size in sorted((a, size) for sec, a, size in syms.values() if sec == ".text" and lo <= a < hi):
            if a >= end and (not out or out[-1] != a):
                out.append(a)
            end = max(end, a + size)
        return out

    @staticmethod
    def _big_units(rep: dict) -> list[dict]:
        """The report's units of files decompdecomp gave code (auto/text_XXXXXXXX, REL/<module>/text_XXXXXXXX) with
        more than FILE_FUNCTIONS functions: an older decompdecomp made one file of a whole stretch."""
        return [u for u in rep.get("units", []) if len(u.get("functions") or []) > FILE_FUNCTIONS
                and re.search(r"/(?:auto|REL/[^/]+)/text_[0-9A-F]{8}_*$", u["name"])]

    def _divide_big_files(self, proj, fp: ForkProject, mods: dict, src: str, rep: dict, log) -> list[str]:
        """Cut each file decompdecomp made that holds more than FILE_FUNCTIONS functions into files of that many, its
        C going with its functions (as split_file does, all cuts at once): kept only if the game still builds byte
        for byte and every function that matched still matches. Returns the new files. The caller holds the tree."""
        made_all: list[str] = []
        program_before = self._built_before(fp) if self._big_units(rep) else None
        for entry in self._big_units(rep):
            try:
                unit = fp.unit(entry["name"])
            except (ForkError, ValueError):
                continue
            rel = unit.source or ""
            name = rel[len(src) + 1:] if rel.startswith(src + "/") else rel
            if fp.link_states().get(rel, ("",))[0] != "NonMatching":
                continue
            owners = [(mod, sp) for mod in mods.values()
                      for sp in [dtksplits.Splits.parse(mod.splits.read_text(encoding="utf-8"))]
                      if any(f.name == name for f in sp.files)]
            if len(owners) != 1:
                continue
            mod, sp = owners[0]
            f = next(x for x in sp.files if x.name == name)
            if ".text" not in f.sections:
                continue
            lo, hi = f.sections[".text"]
            syms = dtksplits.symbols(mod.symbols)
            starts = self._starts(dtksplits.symbols(mod.symbols, labels=False), lo, hi)  # (CodeWarrior's linker hangs on a cut at a label)
            cuts = [lo, *starts[FILE_FUNCTIONS::FILE_FUNCTIONS], hi]
            if len(cuts) <= 2:
                continue
            ext = Path(name).suffix or ".c"
            parts = [(a, b, f"{Path(name).parent.as_posix()}/text_{a:08X}{ext}") for a, b in zip(cuts[1:], cuts[2:])]
            if any((fp.root / src / n).exists() or any(x.name == n for x in sp.files) for _, _, n in parts):
                log(f"{rel}: a file of the names it would be cut into exists already; left as it is")
                continue
            old_path, conf = fp.root / src / name, fp.root / "configure.py"
            text = old_path.read_text(errors="replace", encoding="utf-8") if old_path.exists() else ""
            rows = self.net.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND unit=?",
                                      proj["id"], unit.name)
            # (the build directly: the caller holds the build lock, which _baseline's build takes)
            built, _ = fp.build_unit(unit)
            try:
                before = fp.diff(unit, None).unit_scores if built else {}
            except (ObjdiffError, ForkError):
                before = {}
            protected = {n for n, pct in before.items() if pct is not None and pct >= 100}
            saved = {conf: conf.read_text(encoding="utf-8"), mod.splits: mod.splits.read_text(encoding="utf-8"),
                     old_path: text}
            made: list[Path] = []
            log(f"cutting {rel} ({len(starts):,} functions) into {len(cuts) - 1} files of up to {FILE_FUNCTIONS}")
            try:
                rest, texts = text, {}
                for a, b, n in reversed(parts):  # (from the end: each cut takes what's after it)
                    going = {s for r in rows if (s := self._meta(r).get("symbol")) in syms and a <= syms[s][1] < b}
                    texts[n], rest, _ = self._divide(rest, rows, going)
                f.sections = dict(f.sections, **{".text": (lo, cuts[1])})  # (its data stays: split_file's `data` moves it)
                sp.files.extend(dtksplits.FileSplit(n, {".text": (a, b)}) for a, b, n in parts)
                mod.splits.write_text(sp.render(), encoding="utf-8")
                ctext = saved[conf]
                spot = next(((s0, e0) for lib in dtksplits.libs(ctext) for p_, s0, e0 in lib.objects if p_ == name), None)
                if spot is None:
                    raise ForkError(f"{name} isn't in configure.py")
                indent = dtksplits.indent_of(ctext, spot[0])
                # the file's own settings go with its pieces (mw_version="GC/1.2.5n", cflags=...): on the default
                # compiler a GameCube game's SDK file stopped matching, and another's C didn't compile
                own = re.match(r'Object\(\s*\w+\s*,\s*"[^"]*"(.*)\)\s*$', ctext[spot[0]:spot[1]], re.S)
                settings = own.group(1).rstrip().rstrip(",") if own else ""
                extra = "".join(f',\n{indent}Object(NonMatching, "{n}"{settings})' for _, _, n in parts)
                conf.write_text(ctext[:spot[1]] + extra + ctext[spot[1]:], encoding="utf-8")
                for n, body in texts.items():
                    p_ = fp.root / src / n
                    p_.write_text(body, encoding="utf-8")
                    made.append(p_)
                old_path.write_text(rest, encoding="utf-8")
                ok, out = self._still_builds(fp, program_before)
                if not ok:
                    raise ForkError(f"the game didn't build as it did with the file cut:\n{_tail(out)}")
                now: dict[str, float | None] = {}
                for u in fp.units():
                    if u.source in {rel, *(f"{src}/{n}" for _, _, n in parts)}:
                        built, out = fp.build_unit(u)
                        if not built:
                            raise ForkError(f"{u.source} doesn't compile once cut:\n{_tail(out)}")
                        now.update(fp.diff(u, None).unit_scores)
                lost = sorted(n for n in protected if (now.get(n) or 0) < 100)
                if lost:
                    raise ForkError(f"these functions would stop matching: {', '.join(lost[:8])}")
            except (ForkError, ObjdiffError, OSError, ValueError) as e:
                for p_, old in saved.items():
                    p_.write_text(old, encoding="utf-8")
                for p_ in made:
                    p_.unlink(missing_ok=True)
                fp.verify()
                log(f"{rel} wasn't cut, nothing changed: {e}")
                continue
            self._commit_paths(proj, fp, [str(p_.relative_to(fp.root)) for p_ in [*saved, *made]],
                               f"Cut {Path(name).name} into {len(cuts) - 1} files of up to {FILE_FUNCTIONS} functions\n\n"
                               "One file of the whole stretch made every claim and compile read all of its functions; "
                               "the game still builds byte for byte and every match still matches.\n\nCut by decompdecomp.")
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], None, "split", f"{rel} cut into {len(cuts) - 1} files")
            made_all += [f"{src}/{n}" for _, _, n in parts]
        if made_all:
            fp.build_all()
            self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
            log(f"{len(made_all)} new source files from files too big to work on")
        return made_all

    def split_file(self, agent: Agent | None, slug: str, path: str, at: str, new_name: str = "", data: str = "") -> str:
        """Divide a source file in two at a function: it and everything after it in the file's code go to a new file
        (with their C), and so do the parts of the data sections named in `data` (".rodata:0x88 .data:0x28": where the
        new file's part of each section starts). Kept only if the game still builds byte for byte and every function
        that matched still matches."""
        if agent is not None and (link := self.net.links.get(slug)) is not None:  # the host splits it; this copy follows
            text = link.call("/collab/split_file", agent, path=path, at=at, new_name=new_name, data=data)
            if text.startswith("✅"):
                text += link.follow()
            return text
        proj, fp, cfg = self.get(slug)
        if (console := consoles.get(cfg.get("platform"))).splits_sources:
            return self._split_source(agent, slug, console, path, at, new_name)
        mods = self._modules(fp, cfg)
        src = fp.src_dir()
        rel = path.strip().lstrip("./")
        if not fp.units_for(rel):
            try:  # a function: its file
                rel = fp.unit(self._fn(slug, path)["unit"]).source or ""
            except (NetworkError, ForkError):
                raise NetworkError(f"{path} isn't a source file (or a function) of this project") from None
        name = rel[len(src) + 1:] if rel.startswith(src + "/") else rel
        owners = []
        for module, mod in mods.items():
            sp = dtksplits.Splits.parse(mod.splits.read_text(encoding="utf-8"))
            if any(f.name == name for f in sp.files):
                owners.append((module, mod, sp))
        if len(owners) != 1:
            raise NetworkError(f"{rel} is {'not in any' if not owners else 'shared by several'} module's splits; "
                               "split_file divides a file one module owns")
        module, mod, sp = owners[0]
        if fp.link_states().get(rel, ("",))[0] != "NonMatching":
            raise NetworkError(f"{rel} is linked (or not in configure.py): a linked file is finished, don't split it")
        f = next(x for x in sp.files if x.name == name)
        if ".text" not in f.sections:
            raise NetworkError(f"{rel} has no code to split")
        syms = dtksplits.symbols(mod.symbols)
        lo, hi = f.sections[".text"]
        where = at.strip()
        if where in syms and syms[where][0] == ".text":
            addr = syms[where][1]
        elif re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", where):
            addr = int(where, 16)
        else:
            try:
                fn_row = self._fn(slug, at)
                addr = syms[self._meta(fn_row).get("symbol")][1]
            except (NetworkError, KeyError):
                raise NetworkError(f"`{at}` isn't a function of {rel}: give its name or .text offset") from None
        starts = sorted(a for sec, a, _ in dtksplits.symbols(mod.symbols, labels=False).values()
                        if sec == ".text" and lo < a < hi)  # (not a label: CodeWarrior's linker hangs on one)
        if addr not in starts:
            raise NetworkError(f"`{at}` (0x{addr:X}) isn't the start of a function in {rel} (after its first one); "
                               f"its code is .text 0x{lo:X}-0x{hi:X}")
        ext = Path(name).suffix or ".c"
        new = (new_name.strip().lstrip("./") or f"{Path(name).parent.as_posix()}/text_{addr:08X}{ext}")
        new = new[len(src) + 1:] if new.startswith(src + "/") else new
        if not fp.safe_path(f"{src}/{new}", write=True) or (fp.root / src / new).exists() or \
                any(x.name == new for x in sp.files):
            raise NetworkError(f"{src}/{new} exists already: pick another new_name")
        moved_sections = {".text": (addr, hi)}
        kept = dict(f.sections, **{".text": (lo, addr)})
        for part in data.replace(",", " ").split():
            sec, _, start = part.partition(":")
            if sec not in f.sections or sec == ".text":
                raise NetworkError(f"{rel} has no {sec} part to split (it has {', '.join(f.sections)})")
            a, b = f.sections[sec]
            cut = int(start, 16)
            if not a <= cut <= b:
                raise NetworkError(f"{sec}:{start} is outside {rel}'s {sec} (0x{a:X}-0x{b:X})")
            moved_sections[sec] = (cut, b)
            kept[sec] = (a, cut)
        kept = {k: v for k, v in kept.items() if v[1] > v[0]}

        old_path, new_path = fp.root / src / name, fp.root / src / new
        conf = fp.root / "configure.py"
        unit = fp.units_for(rel)[0]
        rows = self.net.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND unit=?", proj["id"], unit.name)
        with self._tree(proj).exclusive():  # no other build runs meanwhile
            self._put_back_config(proj, fp)  # (a try's leftover isn't committed with this change)
            text = old_path.read_text(errors="replace", encoding="utf-8") if old_path.exists() else ""
            going = self._going_symbols(rows, syms, addr, hi)
            new_text, rest, moved = self._divide(text, rows, going)
            scores_before = self._baseline(proj, fp, unit, text)[0] or {}
            saved = {conf: conf.read_text(encoding="utf-8"), mod.splits: mod.splits.read_text(encoding="utf-8"), old_path: text}
            protected = {n for n, pct in scores_before.items() if pct is not None and pct >= 100}
            program_before = self._built_before(fp)
            try:
                f.sections = kept
                sp.files.append(dtksplits.FileSplit(new, moved_sections))
                mod.splits.write_text(sp.render(), encoding="utf-8")
                ctext = saved[conf]
                states = dtksplits.libs(ctext)
                entry = next(((s0, e0) for lib in states for p_, s0, e0 in lib.objects if p_ == name), None)
                if entry is None:
                    raise ForkError(f"{name} isn't in configure.py")
                old_entry = ctext[entry[0]:entry[1]]
                new_entry = re.sub(r'^(Object\(\s*)\w+(\s*,\s*)"[^"]+"', lambda mm: f'{mm.group(1)}NonMatching{mm.group(2)}"{new}"',
                                   old_entry, count=1)
                indent = dtksplits.indent_of(ctext, entry[0])
                conf.write_text(ctext[:entry[1]] + f",\n{indent}{new_entry}" + ctext[entry[1]:], encoding="utf-8")
                new_path.parent.mkdir(parents=True, exist_ok=True)
                new_path.write_text(new_text, encoding="utf-8")
                old_path.write_text(rest, encoding="utf-8")
                ok, out = self._still_builds(fp, program_before)
                if not ok:
                    raise ForkError(f"the game didn't build as it did with the files divided there:\n{_tail(out)}")
                after_units = [u for u in fp.units() if u.source in (rel, f"{src}/{new}")]
                now: dict[str, float | None] = {}
                for u in after_units:
                    built, log_ = fp.build_unit(u)
                    if not built:
                        raise ForkError(f"{u.source} doesn't compile after the split (move the declarations it needs with "
                                        f"edit_file first):\n{_tail(log_)}")
                    now.update(fp.diff(u, None).unit_scores)
                lost = sorted(n for n in protected if (now.get(n) or 0) < 100)
                if lost:
                    raise ForkError(f"these functions would stop matching: {', '.join(lost[:8])}")
            except (ForkError, ObjdiffError, OSError, ValueError) as e:
                for p_, old in saved.items():
                    p_.write_text(old, encoding="utf-8")
                new_path.unlink(missing_ok=True)
                fp.verify()
                for u in fp.units_for(rel):
                    fp.build_unit(u)
                raise NetworkError(f"not split, nothing changed: {e}") from None
            fp.build_all()
            rep = fp.report()
            self._commit_paths(proj, fp, [str(p_.relative_to(fp.root)) for p_ in saved] + [str(new_path.relative_to(fp.root))],
                               f"Split {Path(name).name} at 0x{addr:X}: {Path(new).name}\n\n"
                               f"Divided by {agent.name if agent else 'decompdecomp'} with decompdecomp; the game still builds "
                               "byte for byte.")
            self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
            self.sync(slug, log=lambda *_: None, rep=rep)
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id if agent else None, "split", f"{rel} → {src}/{new}")
        moved_text = ", ".join(f"{k} 0x{a:X}-0x{b:X}" for k, (a, b) in moved_sections.items())
        return (f"✅ {rel} is divided: {src}/{new} now holds {moved_text} ({moved} function definitions moved with "
                "it); the game still builds byte for byte and every match still matches.")

    def _divide(self, text: str, rows, going: set[str]) -> tuple[str, str, int]:
        """(the new file's C, the old file's, how many definitions moved) when the functions `going` (by symbol)
        leave a source file: each file keeps the original's order, with every declaration where it stood (a DS game's
        moved function used data declared just before it, far below the file's top), and where a definition went to
        the other file, its prototype. A GameCube game's file declared `s32 Thing_Init();` at the top and
        `s32 Thing_Init(void *);` far below, after the calls the first allowed, and called `strstr` below its
        definition: with the declarations lifted to the top and no prototype for what left, four of its files
        didn't compile once cut."""
        spans = {}
        for r in rows:
            if (span := self._defined(text, self._names(self._meta(r), r))):
                spans[span] = (self._meta(r).get("symbol") or r["name"]) in going

        def prototype(a: int, b: int) -> str:
            """A definition's declaration (`s32 f(void *p);`), or "" where one could say something else: a static or
            inline function (no other file can call it), an old-style definition (`int f(a) int a; {`)."""
            head = text[a:b]
            head = head[:head.find("{")].strip() if "{" in head else ""
            # (nor a C++ method's, `s32 Num::f(s32);`: outside its class a member can't be declared again)
            if not head or ";" in head or "#" in head or "::" in head or \
                    re.search(r"\b(static|inline|__inline)\b", head):
                return ""
            return head + ";"

        def leaving(gone):
            out = text
            for a, b in sorted(gone, reverse=True):
                proto = prototype(a, b)
                out = out[:a].rstrip("\n") + "\n\n" + (proto + "\n\n" if proto else "") + out[b:].lstrip("\n")
            return out.strip() + "\n"

        # #300: the moving definitions are the file's tail (as an address-ordered file's are): the new file is the
        # text before the cut, staying definitions cut to their prototypes, then the tail as it is; the old file is
        # the text before the cut, with the moved definitions' prototypes where they stood. Pragmas and data after
        # the tail go only where they stood.
        order = sorted(spans)
        first = next((i for i, span in enumerate(order) if spans[span]), None)
        if first is not None and all(spans[span] for span in order[first:]):
            cut = order[first][0]
            head = text[:cut]
            for a, b in sorted(order[:first], reverse=True):
                proto = prototype(a, b)
                head = head[:a].rstrip("\n") + "\n\n" + (proto + "\n\n" if proto else "") + head[b:].lstrip("\n")
            head = head.strip()
            protos = [proto for a, b in order[first:] if (proto := prototype(a, b))]
            kept = text[:cut].rstrip("\n") + "\n" + ("\n" + "\n".join(protos) + "\n" if protos else "")
            return (head + "\n\n" if head else "") + text[cut:].lstrip("\n"), kept, len(order) - first
        moving = [s for s, g in spans.items() if g]
        staying = [s for s, g in spans.items() if not g]
        return leaving(staying), leaving(moving), len(moving)

    def _split_source(self, agent: Agent | None, slug: str, console, path: str, at: str, new_name: str) -> str:
        """split_file for a console that divides source files in its config (Console.split_source: DS's delinks.txt):
        the function `at` and those after it in the file go to a new one, with their C and the file's compiler. Kept
        only if the game still builds as it did (byte for byte, where the console checks) and every match holds. On a
        DS game agents found a function built by another CodeWarrior version than its file's other functions: in a
        file of its own, it can have its own (try_compiler)."""
        proj, fp, cfg = self.get(slug)
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        rel = path.strip().lstrip("./")
        if not fp.units_for(rel):
            try:  # a function: its file
                rel = fp.unit(self._fn(slug, path)["unit"]).source or ""
            except (NetworkError, ForkError):
                raise NetworkError(f"{path} isn't a source file (or a function) of this project") from None
        units = fp.units_for(rel)
        if not units:
            raise NetworkError(f"{path} isn't a source file of this project")
        unit = units[0]
        fn = self._fn(slug, at)
        if fn["unit"] != unit.name:
            raise NetworkError(f"`{at}` isn't a function of {rel}: give the name of the first one the new file gets")
        sym = self._meta(fn).get("symbol") or fn["name"]
        try:  # the file's functions in the order of their code, from its target object
            order = fp.diff(unit, None).order
        except (ObjdiffError, ForkError) as e:
            raise NetworkError(f"objdiff couldn't read {rel}'s functions: {e}") from None
        if sym not in order or order.index(sym) == 0:
            raise NetworkError(f"{fn['name']} is {rel}'s first function (or not in it): split at one after it")
        going = set(order[order.index(sym):])
        rows = [r for r in self.net.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND unit=? AND "
                                              "status != 'nosource'", proj["id"], unit.name)]
        stem = re.sub(r"_[0-9A-Fa-f]{8,16}$", "", Path(rel).stem)
        # (a PC function: @func_0041B470@8; a 64-bit one's address has 9 digits or more, func_140001000)
        tail = re.search(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{8,16})(?:@\d+)?$", sym)
        new = new_name.strip().lstrip("./") or (Path(rel).parent / f"{stem}_{(tail.group(1) if tail else sym).upper()}"
                                                f"{Path(rel).suffix}").as_posix()
        # a bare name is the file's folder's, and its kind: agents gave text_00401AA0 and were told they "may only
        # edit C/C++ source", four times on a PC game, and gave up on the split
        if "/" not in new:
            new = (Path(rel).parent / new).as_posix()
        if not Path(new).suffix:
            new += Path(rel).suffix
        old_path, new_path = fp.root / rel, fp.root / new
        if not fp.safe_path(new, write=True) or new_path.exists() or fp.units_for(new):
            raise NetworkError(f"{new} exists already: pick another new_name")
        text = old_path.read_text(errors="replace", encoding="utf-8") if old_path.exists() else ""
        new_text, rest, moved = self._divide(text, rows, going)
        protected = {n for n, pct in (self._baseline(proj, fp, unit, text)[0] or {}).items() if pct is not None and pct >= 100}
        checks = consoles.REBUILD_CHECK in console.features
        with self._tree(proj).exclusive(), self._build_lock(proj):
            self._put_back_config(proj, fp)  # (a try's leftover isn't committed with this change)
            before = (fp.manifest or {}).get("rebuild") or {}
            saved = {old_path: text}
            try:
                saved.update(console.split_source(fp, version, rel, sym, new))
                new_path.write_text(new_text, encoding="utf-8")
                old_path.write_text(rest, encoding="utf-8")
                for cmd in fp.setup_commands(version):
                    ok, out = fp.run(cmd, log=lambda *_: None)
                    if not ok:  # (dsd's warnings drown what failed)
                        said = "\n".join(ln for ln in out.splitlines() if not ln.lstrip().startswith("[WARN"))
                        raise ForkError(f"the project didn't build with the files divided there (the moved C may need "
                                        f"declarations the file before has: move them with edit_file first):\n{_tail(said)}")
                if checks and before.get("identical") and not console.check_rebuild(fp, version).get("identical"):
                    raise ForkError("the game no longer rebuilt byte for byte with the files divided there")
                now: dict[str, float | None] = {}
                for u in [u for u in fp.units() if u.source in (rel, new)]:
                    built, log_ = fp.build_unit(u)
                    if not built:
                        raise ForkError(f"{u.source} doesn't compile after the split (move the declarations it needs "
                                        f"with edit_file first):\n{_tail(log_)}")
                    now.update(fp.diff(u, None).unit_scores)
                if lost := sorted(n for n in protected if (now.get(n) or 0) < 100):
                    raise ForkError(f"these functions would stop matching: {', '.join(lost[:8])}")
            except (ForkError, RomError, ObjdiffError, OSError, ValueError) as e:
                for p_, old in saved.items():
                    p_.write_text(old, encoding="utf-8")
                new_path.unlink(missing_ok=True)
                for cmd in fp.setup_commands(version):
                    fp.run(cmd, log=lambda *_: None)
                raise NetworkError(f"not split, nothing changed: {e}") from None
            self._commit_paths(proj, fp, [str(p_.relative_to(fp.root)) for p_ in saved] + [new],
                               f"Split {Path(rel).name} at {fn['name']}: {Path(new).name}\n\nDivided by "
                               f"{agent.name if agent else 'decompdecomp'} with decompdecomp; the game still builds as "
                               "it did and every match still matches.")
        self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
        self.sync(slug, log=lambda *_: None)
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], agent.id if agent else None, "split", f"{rel} → {new}")
        return (f"✅ {rel} is divided: {new} now holds {fn['name']} and what follows it ({moved} function "
                "definitions moved with them), with the file's compiler (try_compiler switches the new file's); the "
                "game still builds as it did and every match still matches.")

    def set_file_language(self, agent: Agent | None, slug: str, path: str, language: str) -> str:
        """A source file built as C (its name .c) or as C++ (.cpp), where decompdecomp made the project's files
        (Console.rename_source): RSA's MD5 in a 6.0 game was C built by Visual C++ 4.2, and its .cpp file's C++ front
        end ordered operands otherwise; a function's conversion stayed C++'s whatever its C said. Kept only if the
        game still builds as it did and every match holds."""
        if self.net.links.get(slug) is not None:
            raise NetworkError("in a room, the host's project decides its files: set_file_language works there")
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if not console.splits_sources:
            raise NetworkError("this project's files are its build's own: set_file_language works where decompdecomp "
                               "made it")
        suffix = {"c": ".c", "c++": ".cpp", "cpp": ".cpp"}.get(language.strip().lower())
        if suffix is None:
            raise NetworkError("language: \"c\" or \"c++\"")
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        rel = path.strip().lstrip("./")
        if not fp.units_for(rel):
            try:  # a function: its file
                rel = fp.unit(self._fn(slug, path)["unit"]).source or ""
            except (NetworkError, ForkError):
                raise NetworkError(f"{path} isn't a source file (or a function) of this project") from None
        units = fp.units_for(rel)
        if not units:
            raise NetworkError(f"{path} isn't a source file of this project")
        new = Path(rel).with_suffix(suffix).as_posix()
        if new == rel:
            raise NetworkError(f"{rel} is built as {'C' if suffix == '.c' else 'C++'} already")
        old_path, new_path = fp.root / rel, fp.root / new
        if new_path.exists():
            raise NetworkError(f"{new} exists already")
        text = old_path.read_text(errors="replace", encoding="utf-8")
        protected = {n for n, pct in (self._baseline(proj, fp, units[0], text)[0] or {}).items()
                     if pct is not None and pct >= 100}
        checks = consoles.REBUILD_CHECK in console.features
        with self._tree(proj).exclusive(), self._build_lock(proj):
            self._put_back_config(proj, fp)  # (a try's leftover isn't committed with this change)
            before = (fp.manifest or {}).get("rebuild") or {}
            saved: dict = {}
            try:
                old_path.rename(new_path)
                saved.update(console.rename_source(fp, version, rel, new))
                for cmd in fp.setup_commands(version):
                    ok, out = fp.run(cmd, log=lambda *_: None)
                    if not ok:  # (the compiler's own lines say why: ninja's last line only names the object)
                        said = [ln for ln in out.splitlines() if re.search(r"\berror\b|: error|fatal", ln, re.I)]
                        raise ForkError(f"the project didn't build with {new} (a header with what only C++ has, "
                                        "`class`, a `static` method, a reference: put it in `#ifdef __cplusplus`):\n"
                                        + ("\n".join(said[:8]) if said else _tail(out)))
                if checks and before.get("identical") and not console.check_rebuild(fp, version).get("identical"):
                    raise ForkError(f"the game no longer rebuilt byte for byte with {new}")
                now: dict[str, float | None] = {}
                for u in fp.units_for(new):
                    built, log_ = fp.build_unit(u)
                    if not built:
                        raise ForkError(f"{new} doesn't compile as {'C' if suffix == '.c' else 'C++'} (what C++ "
                                        f"alone has: references, classes, overloads, `extern \"C\"`):\n{_tail(log_)}")
                    now.update(fp.diff(u, None).unit_scores)
                if lost := sorted(n for n in protected if (now.get(n) or 0) < 100):
                    raise ForkError(f"these functions would stop matching: {', '.join(lost[:8])}")
            except (ForkError, RomError, ObjdiffError, OSError, ValueError) as e:
                if new_path.exists() and not old_path.exists():
                    new_path.rename(old_path)
                for p_, old in saved.items():
                    p_.write_text(old, encoding="utf-8")
                for cmd in fp.setup_commands(version):
                    fp.run(cmd, log=lambda *_: None)
                raise NetworkError(f"not changed: {e}") from None
            self._commit_paths(proj, fp, [rel, new, *(str(p_.relative_to(fp.root)) for p_ in saved)],
                               f"Build {Path(rel).name} as {'C' if suffix == '.c' else 'C++'}: {Path(new).name}\n\n"
                               f"Changed by {agent.name if agent else 'decompdecomp'} with decompdecomp; the game "
                               "still builds as it did and every match still matches.")
        self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
        self.sync(slug, log=lambda *_: None)
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], agent.id if agent else None, "split", f"{rel} → {new}")
        return (f"✅ {rel} is {new}: built as {'C' if suffix == '.c' else 'C++'} from now on, with its compiler and "
                "flags; the game still builds as it did and every match still matches.")

    def join_files(self, agent: Agent | None, slug: str, path: str, with_path: str) -> str:
        """Make two neighbouring source files one (Console.join_sources): the later one's C after the earlier one's,
        its functions the earlier file's. Kept only if the game still builds as it did (byte for byte, where the
        console checks) and every match holds. Visual C++ 7 gives a file's static functions a convention of their own
        (an argument in edx, edi...): a helper and its callers, cut into two files by the project's 4 KiB files, could
        never match until they were one file again (a 2003 PC game had 51 such helpers one file from their callers)."""
        if agent is not None and (link := self.net.links.get(slug)) is not None:  # the host joins them; this copy follows
            text = link.call("/collab/join_files", agent, path=path, with_path=with_path)
            if text.startswith("✅"):
                text += link.follow()
            return text
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if not console.splits_sources:
            raise NetworkError("this project's files are its build's own: join_files works where decompdecomp made it")
        version = (fp.manifest or {}).get("version") or cfg.get("version")

        def source_of(what: str) -> str:
            rel = what.strip().lstrip("./")
            if fp.units_for(rel):
                return rel
            try:  # a function: its file
                return fp.unit(self._fn(slug, what)["unit"]).source or ""
            except (NetworkError, ForkError):
                raise NetworkError(f"{what} isn't a source file (or a function) of this project") from None
        a, b = source_of(path), source_of(with_path)
        if a == b:
            raise NetworkError(f"{a} is one file already")
        order = [u.source for u in fp.units()]
        first, second = sorted((a, b), key=lambda s_: order.index(s_) if s_ in order else -1)
        units = [u for u in fp.units() if u.source in (first, second)]
        texts = {p_: (fp.root / p_).read_text(errors="replace", encoding="utf-8") if (fp.root / p_).exists() else ""
                 for p_ in (first, second)}
        protected = set()
        for u in units:
            protected |= {n for n, pct in (self._baseline(proj, fp, u, texts[u.source])[0] or {}).items()
                          if pct is not None and pct >= 100}
        # the later file's C after the earlier one's; what both include is said once
        seen = {ln.strip() for ln in texts[first].splitlines() if ln.strip().startswith("#include")}
        rest = "\n".join(ln for ln in texts[second].splitlines()
                         if not (ln.strip().startswith("#include") and ln.strip() in seen))
        joined = texts[first].rstrip("\n") + f"\n\n/* the functions of {Path(second).name}, joined to this file */\n" + rest + "\n"
        checks = consoles.REBUILD_CHECK in console.features
        # files built with different flags (search_flags gave one /GS): the joined file tries each file's in turn,
        # and keeps the first under which every match holds (Visual C++ 7 makes /GS's cookie only for local arrays)
        own = [console.file_flags(fp, p_) for p_ in (first, second)]
        choices = [None] if own[0] == own[1] else [f for f in own if f is not None]
        why = ""
        with self._tree(proj).exclusive(), self._build_lock(proj):
            self._put_back_config(proj, fp)  # (a try's leftover isn't committed with this change)
            before = (fp.manifest or {}).get("rebuild") or {}
            for flags in choices:
                saved = {fp.root / p_: t for p_, t in texts.items()}
                try:
                    saved.update(console.join_sources(fp, version, first, second, flags))
                    (fp.root / first).write_text(joined, encoding="utf-8")
                    (fp.root / second).unlink(missing_ok=True)
                    for cmd in fp.setup_commands(version):
                        ok, out = fp.run(cmd, log=lambda *_: None)
                        if not ok:
                            raise ForkError("the project didn't build with the files joined (two definitions of one "
                                            f"type or name? make them agree with edit_file first):\n{_tail(out)}")
                    if checks and before.get("identical") and not console.check_rebuild(fp, version).get("identical"):
                        raise ForkError("the game no longer rebuilt byte for byte with the files joined")
                    unit = next(u for u in fp.units() if u.source == first)
                    built, log_ = fp.build_unit(unit)
                    if not built:
                        raise ForkError(f"{first} doesn't compile with the files joined (two definitions of one type "
                                        f"or name? make them agree with edit_file first):\n{_tail(log_)}")
                    now = fp.diff(unit, None).unit_scores
                    if lost := sorted(n for n in protected if (now.get(n) or 0) < 100):
                        raise ForkError(f"these functions would stop matching"
                                        f"{f' with {' '.join(flags)}' if flags else ''}: {', '.join(lost[:8])}")
                except (ForkError, RomError, ObjdiffError, OSError, ValueError) as e:
                    for p_, old in saved.items():
                        p_.write_text(old, encoding="utf-8")
                    for cmd in fp.setup_commands(version):
                        fp.run(cmd, log=lambda *_: None)
                    why = str(e)
                    continue
                self._commit_paths(proj, fp, [str(p_.relative_to(fp.root)) for p_ in saved],
                                   f"Join {Path(second).name} to {Path(first).name}\n\nJoined by "
                                   f"{agent.name if agent else 'decompdecomp'} with decompdecomp; the game still builds "
                                   "as it did and every match still matches.")
                break
            else:
                raise NetworkError(f"not joined, nothing changed: {why}")
        self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
        self.sync(slug, log=lambda *_: None)
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], agent.id if agent else None, "join_files", f"{second} → {first}")
        return (f"✅ {second} is part of {first} now, its C after the file's own: a helper only its callers there use "
                "can be written `static` (Visual C++ then gives it the register convention its code shows); the game "
                "still builds as it did and every match still matches.")

    SOURCE_SUFFIXES = (".c", ".h", ".cpp", ".hpp", ".cp", ".cc", ".inc")

    def name_instance(self, agent: Agent | None, slug: str, function: str) -> str:
        """The function is an instance of a template the game used (the STL's: std::map's erase), which its source
        file compiles now: what the file compiles to is searched for the function's code (Console.instance_names),
        and the compiled function's name becomes its real name, with each instance it calls that the game has too.
        Kept as rename_symbol is: the project builds, the game rebuilds as it did, every match still matches. On a
        2003 PC game an agent rebuilt std::map's red-black tree by hand to 22%, while <map> compiled it exactly."""
        proj, fp, cfg = self.get(slug)
        if slug in self.net.links:
            raise NetworkError("in a room, the host's project is the one to name functions in: say it in a note")
        fn = self._fn(slug, function)
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} already matches")
        symbol = self._meta(fn).get("symbol") or fn["name"]
        found, now, own = self._name_instances(agent, slug, fn["unit"], [symbol], strict=True)
        source = fp.unit(fn["unit"]).source
        return (f"✅ {len(found)} of the game's functions are instances {source} compiles: "
                + ", ".join(f"{t} ({'matches' if t in now else 'named, not matching yet'})" for t in found) + "."
                + (f" {', '.join(own)} compile{'s' * (len(own) == 1)} as instances too, but {source} defines "
                   f"{'it' if len(own) == 1 else 'them'} by hand: take that out (edit_file) and call name_instance for "
                   f"{'it' if len(own) == 1 else 'each'}." if own else "")
                + " Call claim_function for the next one.")

    def _name_instances(self, agent: Agent | None, slug: str, unit_name: str, symbols: list[str], strict: bool,
                        source_was: str | None = None) -> tuple[dict[str, str], set[str], list[str]]:
        """name_instance for the functions `symbols` of one unit: each found with what it calls (Console.
        instance_names), named, kept only when the project builds, the game rebuilds as it did and every match still
        matches; else all is put back, the unit's source too where `source_was` is what it held before (autopilot
        added an instantiation). `strict`: a function not found or defined by hand in the file raises (an agent asked
        for it); else it's left out. Returns the names given {game symbol: compiled symbol}, those matching now, and
        the instances found but defined by hand in the file."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        unit = fp.unit(unit_name)
        checks = consoles.REBUILD_CHECK in console.features
        path = fp.root / unit.source

        def put_back() -> None:
            if source_was is not None:
                path.write_text(source_was, encoding="utf-8")
                self._build_unit(proj, fp, unit)
        with self._tree(proj).exclusive():
            ok, out = self._build_unit(proj, fp, unit)
            if not ok:
                put_back()
                raise NetworkError(f"{unit.source} doesn't build as it is, so nothing was searched:\n{_tail(out)}")
            found: dict[str, str] = {}
            for symbol in symbols:
                for t, c in console.instance_names(fp, version, unit, symbol, taken=set(found.values())).items():
                    if t not in found and c not in found.values():
                        found[t] = c
                if strict and symbol not in found:
                    put_back()
                    raise NetworkError(
                        f"nothing {unit.source} compiles to is {symbol}'s code. Make the file compile the instance: "
                        "include the template's header (<map>, <vector>, <string>...) and use it with the game's "
                        "types (an explicit instantiation, `template class std::map<std::string, int>;`, compiles all "
                        "of it); the types are right when the layout is (a map node's _Isnil at the offset the code "
                        "tests)")
            text = path.read_text(errors="replace", encoding="utf-8")
            own = [t for t in found if (m := re.search(r"func_([0-9A-Fa-f]{8})", t))
                   and re.search(rf"\bfunc_{m.group(1)}\s*\(", text)]
            if strict and symbols[0] in own:
                put_back()
                raise NetworkError(f"{unit.source} defines {symbols[0]} by hand too: take that out first (edit_file), "
                                   "the compiled instance is the function")
            found = {t: c for t, c in found.items() if t not in own}  # (those it calls: named once theirs are out)
            if not found:
                put_back()
                return {}, set(), own
            matched = {self._meta(r).get("symbol") or r["name"] for r in self.net.store.all(
                "SELECT name, meta FROM functions WHERE project_id=? AND status='matched'", proj["id"])}
            before = (fp.manifest or {}).get("rebuild") or {}
            saved: dict[Path, str] = {}
            with self._build_lock(proj):
                try:
                    for t, c in found.items():
                        saved.update(console.rename_symbol(fp, version, t, c))
                    for cmd in fp.setup_commands(version):
                        ok, out = fp.run(cmd, log=lambda *_: None)
                        if not ok:
                            raise ForkError(f"the project didn't build with the names:\n{_tail(out)}")
                    if checks and before.get("identical") and not console.check_rebuild(fp, version).get("identical"):
                        raise ForkError("the game no longer rebuilt byte for byte with them")
                    rep = fp.report()
                    now = {f["name"] for u in rep.get("units", []) for f in u.get("functions", [])
                           if (f.get("fuzzy_match_percent") or 0) >= 100}
                    if lost := sorted(n for n in matched if n not in now):
                        raise ForkError(f"these functions would stop matching: {', '.join(lost[:8])}")
                except (ForkError, RomError, ObjdiffError, OSError, ValueError) as e:
                    for p, t in saved.items():
                        p.write_text(t, encoding="utf-8")
                    if source_was is not None:
                        path.write_text(source_was, encoding="utf-8")
                    for cmd in fp.setup_commands(version):
                        fp.run(cmd, log=lambda *_: None)
                    raise NetworkError(f"not named, nothing changed: {e}") from None
            with self.net.store.tx() as db:
                for t, c in found.items():
                    self.net._event(db, proj["id"], agent.id if agent else None, "rename", f"{t} → {c}")
            changed = [p.relative_to(fp.root).as_posix() for p in saved] + ([unit.source] if source_was is not None else [])
            self._commit_paths(proj, fp, changed,
                               f"Name {len(found)} template instance{'s' * (len(found) != 1)} {unit.source} "
                               "compiles\n\n"
                               + "\n".join(f"{t}: {c}" for t, c in found.items())
                               + f"\n\nFound by {agent.name if agent else 'decompdecomp'} with decompdecomp.")
        self.sync(slug, log=lambda *_: None, rep=rep)
        return found, {t for t in found if t in now}, own

    def autopilot_instances(self, agent: Agent, slug: str, log=print) -> int:
        """Autopilot's STL pass (Console.stl_matches): each open function that is an instance a common container's
        explicit instantiation compiles with its file's compiler and flags gets that instantiation in its file (with
        the headers), and is named as name_instance names it, file by file; a file whose names don't hold is put back
        as it was. A function defined by hand in its file is left to its agents. Returns how many match now."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        wanted = {self._meta(r).get("symbol") or r["name"] for r in self.net.store.all(
            "SELECT name, meta FROM functions WHERE project_id=? AND status='open'", proj["id"])}
        found = console.stl_matches(fp, version, wanted, log=log)
        matched = 0
        for unit_name, hits in sorted(found.items()):
            unit = fp.unit(unit_name)
            if unit is None or not unit.source:
                continue
            path = fp.root / unit.source
            was = path.read_text(errors="replace", encoding="utf-8")
            lines = [ln for ln in dict.fromkeys(hits.values()) if ln not in was]
            if not lines:
                text = was
            else:
                text = was
                for ln in lines:  # (an agent's `template class` of a facet a probe uses makes its code otherwise)
                    if (spoils := console.instance_spoiler(ln)) is not None:
                        text = spoils.sub("", text)
                head = "".join(h for h in STL_HEADERS if h.strip() not in text and any(
                    h[10:-2] in ln or (h[10:-2] == "string" and "basic_string" in ln) for ln in lines))
                head += "".join(d for d in STL_TYPES if any(d.split()[1] in ln for ln in lines) and d.split()[1] not in text)
                block = head + "\n".join(lines) + "  // (the game's instances of these: autopilot)\n"
                # after the file's includes: its own <map> below common.h came after the line, which didn't build
                last = list(re.finditer(r"^[ \t]*#[ \t]*include\b[^\n]*\n", text, re.M))
                at = last[-1].end() if last else 0
                text = text[:at] + block + text[at:]
                path.write_text(text, encoding="utf-8")
            try:
                _, now, _ = self._name_instances(agent, slug, unit_name, sorted(hits), strict=False,
                                                 source_was=was if text != was else None)
                matched += len(now)
            except NetworkError as e:
                log(f"autopilot: {unit.source}'s STL instances weren't named: {str(e)[:300]}")
        return matched

    def rename_symbol(self, agent: Agent | None, slug: str, old: str, new: str, message: str = "") -> str:
        """Give one of the game's symbols (a function, data) a real name: in the console's config, where its name
        comes from (Console.rename_symbol), and as a whole word in every source and header file. Kept only when the
        project sets up again, the game still rebuilds as it did and every match still matches; else every file is
        put back. Polishing in project mode had local names only: functions and globals stayed func_0205d0f4 and
        data_0222f194. The function's row keeps its history under the new name. Where the report keeps the original's
        symbol (Console.renames_in_report: a PC game's _func_0041B470@8), the row keeps that name too, and the new one
        is the function's real name (Console.real_names), how its source spells it. A project whose compiler names a
        this-adjust thunk (`@48@<mangled override>`) has no C body for it: only the game's symbols take its name
        (#300)."""
        # (`old` as the report gives a PC function: _func_0041B470@8, @func_0041B470@8)
        # #300: MWCC emits a class's this-adjust thunks as local/weak symbols named @N@<mangled override>; no C
        # compiles to a bare tail `b`, so the only way to match the game's thunk is to give its symbol that name.
        thunk = bool(_THUNK_NAME.fullmatch(new))
        if not (re.fullmatch(r"[A-Za-z_]\w*", new) or thunk) or not _OLD_SYMBOL.fullmatch(old) or old == new:
            raise NetworkError("rename_symbol takes two different C names (or, for a CodeWarrior this-adjust thunk, "
                               "@N@<mangled member name>): old and new")
        if (link := self.net.links.get(slug)) is not None:  # the host renames and checks it; this copy follows
            # a GameCube room's guest polishing a function was refused here ("the host's project is the one to rename
            # in"), so `unk0`/`unk18` fields the readability check asks to name could never be named, and the helper
            # gave the function up. ROM rooms always sent it to the host (RomNetwork.rename_symbol).
            text = link.call("/collab/rename", agent, old=old, new=new, message=message)
            if text.startswith("✅"):
                text += link.follow()
            return text
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if thunk and not console.thunk_names:
            raise NetworkError("this project's compiler has no @N@ thunk names: give the function a C name")
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        word, taken = re.compile(console.rename_pattern(old)), re.compile(rf"\b{re.escape(new)}\b")
        checks = consoles.REBUILD_CHECK in console.features
        with self._tree(proj).exclusive(), self._build_lock(proj):
            # read under the lock: eight polishing helpers renamed at once, each wrote back files it had read before
            # the others' renames, and half of an Xbox game's renames were undone in some files and not others
            files = sorted(p for d in ("src", "include") if (fp.root / d).is_dir() for p in (fp.root / d).rglob("*")
                           if p.is_file() and p.suffix in self.SOURCE_SUFFIXES)
            texts = {p: p.read_text(errors="replace", encoding="utf-8") for p in files}
            if not thunk and (used := next((p for p, t in texts.items() if taken.search(t)), None)) is not None:
                # helpers asked for renames made hours before (often their own): on a PC game, 30 in a day, each told
                # only "pick another name"
                if self.net.store.one("SELECT 1 FROM events WHERE project_id=? AND kind='rename' AND detail=?",
                                      proj["id"], f"{old} → {new}"):
                    return f"✅ {old} is {new} already (it was renamed before): call it {new}."
                holder = next((r["name"] for r in self.net.store.all(
                    "SELECT name, meta FROM functions WHERE project_id=? AND (name LIKE ? OR json_extract(meta, "
                    "'$.real')=?)", proj["id"], f"%{new}%", new)
                    if new in (r["name"], self._meta(r).get("real"))), None)
                raise NetworkError(f"{new} is used in the project already ("
                                   + (f"it's the name of the function {holder}" if holder else
                                      f"in {used.relative_to(fp.root).as_posix()}") + "): pick another name")
            matched = {self._meta(r).get("symbol") or r["name"] for r in self.net.store.all(
                "SELECT name, meta FROM functions WHERE project_id=? AND status='matched'", proj["id"])}
            before = (fp.manifest or {}).get("rebuild") or {}
            saved: dict[Path, str] = {}
            try:
                saved.update(console.rename_symbol(fp, version, old, new))
                if not thunk:  # (no source spells a thunk's name: only the game's symbols change)
                    for p, t in texts.items():
                        if word.search(t):
                            saved[p] = t
                            p.write_text(word.sub(new, t), encoding="utf-8")
                for cmd in fp.setup_commands(version):
                    ok, out = fp.run(cmd, log=lambda *_: None)
                    if not ok:
                        raise ForkError(f"the project didn't build with the new name:\n{_tail(out)}")
                if checks and before.get("identical") and not console.check_rebuild(fp, version).get("identical"):
                    raise ForkError("the game no longer rebuilt byte for byte with the new name")
                rep = fp.report()
                now = {f["name"] for u in rep.get("units", []) for f in u.get("functions", [])
                       if (f.get("fuzzy_match_percent") or 0) >= 100}
                renamed = new if console.renames_in_report else old
                if lost := sorted(n for n in matched if (renamed if n == old else n) not in now):
                    raise ForkError(f"these functions would stop matching: {', '.join(lost[:8])}")
            except (ForkError, RomError, ObjdiffError, OSError, ValueError) as e:
                if saved:  # (nothing written, nothing to set up again: a refused rename held both locks for a
                    # whole configure run, and every other compile of the game waited on it)
                    for p, t in saved.items():
                        p.write_text(t, encoding="utf-8")
                    for cmd in fp.setup_commands(version):
                        fp.run(cmd, log=lambda *_: None)
                raise NetworkError(f"not renamed, nothing changed: {e}") from None
            with self.net.store.tx() as db:  # the function keeps its row, its matches and notes, under its new name
                if not thunk:  # (and its stored C: see _with_renames)
                    for r in db.execute("SELECT id, best_source, matched_source FROM functions WHERE project_id=? AND "
                                        "(best_source IS NOT NULL OR matched_source IS NOT NULL)", (proj["id"],)).fetchall():
                        best, done = (word.sub(new, t) if t else t for t in (r["best_source"], r["matched_source"]))
                        if (best, done) != (r["best_source"], r["matched_source"]):
                            db.execute("UPDATE functions SET best_source=?, matched_source=? WHERE id=?",
                                       (best, done, r["id"]))
                if console.renames_in_report:  # (else sync gives it its real name, from the console's config)
                    db.execute("UPDATE functions SET name=?, meta=json_set(COALESCE(meta, '{}'), '$.symbol', ?) WHERE "
                               "project_id=? AND (name=? OR json_extract(meta, '$.symbol')=?)",
                               (new, new, proj["id"], old, old))
                self.net._event(db, proj["id"], agent.id if agent else None, "rename", f"{old} → {new}")
            self._commit_paths(proj, fp, [p.relative_to(fp.root).as_posix() for p in saved],
                               f"Rename {old} to {new}\n\n{message.strip() or 'Named'} by "
                               f"{agent.name if agent else 'decompdecomp'} with decompdecomp; the game still builds as it "
                               "did and every match still matches.")
        self.sync(slug, log=lambda *_: None, rep=rep)
        return f"✅ {old} is {new} now, in the game's symbols and in {len(saved)} file(s); every match still matches."

    def _commit_paths(self, proj, fp: ForkProject, paths: list[str], message: str) -> None:
        """Commit these files, waiting out a locked index (a room's sync, the user's git tools). A commit that failed
        was let go without a word, and the app's start put the uncommitted config back as a try's leftover: a GameCube
        game's linked file and its data step were undone, while the project's record said both were done."""
        said = ""
        if not paths:
            return
        with self._git_lock(proj):
            for attempt in range(COMMIT_TRIES):
                ok, said = fp.git("add", "--", *paths)
                if ok:
                    ok, said = fp.git("commit", "-q", "-m", message, "--", *paths)
                if ok or any(m in said for m in ("nothing to commit", "nothing added to commit", "no changes added")):
                    return
                if "index.lock" not in said:
                    break
                if fp.stale_git_lock():  # (a git that died holding it: it would never let go)
                    logging.getLogger("decompdecomp").warning("%s: removed a git index lock a git that died left",
                                                              proj["slug"])
                    continue
                time.sleep(1 + attempt)
        logging.getLogger("decompdecomp").error("%s: couldn't commit %s: %s", proj["slug"], ", ".join(paths), said)
        raise ForkError(f"the project's change to {', '.join(paths[:3])} couldn't be committed (git: {said[-300:]}); "
                        "it's undone the next time the app starts")

    @staticmethod
    def _count_uncovered(rep: dict) -> dict:
        """Code no source file covers (dtk's auto_..._text units): agents can't reach it until it has a file."""
        autos = [u for u in rep.get("units", []) if (u.get("metadata") or {}).get("auto_generated")
                 and u["name"].endswith("_text") and u.get("functions")]
        big = ForkEngine._big_units(rep)
        return {"stretches": len(autos), "functions": sum(len(u["functions"]) for u in autos),
                "big_files": len(big), "big_functions": sum(len(u["functions"]) for u in big)}

    def uncovered(self, slug: str) -> dict | None:
        """{"stretches", "functions"} without a source file, from the last measurement (a project measured by an
        older decompdecomp: from its saved report)."""
        proj, fp, cfg = self.get(slug)
        if "big_files" in (cfg.get("uncovered") or {}):  # (one counted before files too big were: counted again)
            return cfg["uncovered"]
        try:
            counted = self._count_uncovered(json.loads((fp.root / STATE / "report.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None
        self.net._update_cfg(slug, lambda c: c.update(uncovered=counted))
        return counted

    # ------------------------------------------------------------------ look-alike index

    def _index_of(self, proj, fp: ForkProject) -> dict:
        if proj["id"] not in self._index:
            p = fp.root / STATE / "index.json"
            try:
                self._index[proj["id"]] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
            except ValueError:
                self._index[proj["id"]] = {}
        return self._index[proj["id"]]

    def _save_index(self, proj, fp: ForkProject) -> None:
        """Write index.json, only when something new was indexed: every sync (each pull from a room, each edit)
        ends an indexing pass, and a GameCube game's 11 MB index rewritten five times a second wrote 50 MB/s."""
        with self._ilock:
            if proj["id"] not in self._index_dirty:
                return
            self._index_dirty.discard(proj["id"])
            snapshot = dict(self._index.get(proj["id"], {}))
        try:
            (fp.root / STATE / "index.json").write_text(json.dumps(snapshot), encoding="utf-8")
        except OSError:
            with self._ilock:
                self._index_dirty.add(proj["id"])

    def _remember(self, proj, fp: ForkProject, unit, d) -> None:
        if unit.target is None or not unit.target.exists():
            return
        entry = {"mtime": unit.target.stat().st_mtime, "order": d.order, "ops": d.ops}
        idx = self._index_of(proj, fp)
        with self._ilock:
            if idx.get(unit.name) == entry:  # every compile measures its unit again: mostly nothing new
                return
            idx[unit.name] = entry
            self._index_dirty.add(proj["id"])

    def _unit_index(self, proj, fp: ForkProject, unit, save: bool = True) -> dict | None:
        """Target order and mnemonics of a unit's functions, from its target object only (never races a build)."""
        idx = self._index_of(proj, fp)
        if unit.target is None or not unit.target.exists():
            return None
        hit = idx.get(unit.name)
        if hit and hit.get("mtime") == unit.target.stat().st_mtime:
            return hit
        row = self.net.store.one("SELECT meta FROM functions WHERE project_id=? AND unit=? LIMIT 1", proj["id"], unit.name)
        if row is None:
            return None
        try:
            d = objdiff_diff(fp, unit, self._meta(row).get("symbol"), target_only=True)
        except (ObjdiffError, ForkError, toolchains.ToolchainError):  # (objdiff gone meanwhile: the index waits)
            return None
        self._remember(proj, fp, unit, d)
        if save:
            self._save_index(proj, fp)
        return idx.get(unit.name)

    def start_indexing(self, slug: str) -> None:
        """Index every unit in the background so find_similar covers the whole project."""
        proj, fp, cfg = self.get(slug)
        if proj["id"] in self._indexing or not cfg.get("ready"):
            return
        self._indexing.add(proj["id"])

        def run():
            try:
                for n, unit in enumerate(fp.units()):
                    if self.net.store.one("SELECT 1 FROM projects WHERE id=?", proj["id"]) is None:
                        return
                    self._unit_index(proj, fp, unit, save=False)
                    if n % 50 == 49:
                        self._save_index(proj, fp)
                self._save_index(proj, fp)
            finally:
                self._indexing.discard(proj["id"])
        threading.Thread(target=run, daemon=True, name=f"index-{slug}").start()

    def similar(self, proj, fp: ForkProject, fn, top: int = 5) -> list[tuple[dict, float]]:
        """Functions that look like `fn`, best first: [(row, similarity)]."""
        meta = self._meta(fn)
        unit = fp.unit(fn["unit"])
        own = self._unit_index(proj, fp, unit)
        if not own or meta.get("symbol") not in own["ops"]:
            return []
        target = own["ops"][meta["symbol"]]
        cands = {}
        with self._ilock:
            entries = list(self._index_of(proj, fp).items())
        for uname, entry in entries:
            for sym, ops in entry["ops"].items():
                if (uname, sym) != (fn["unit"], meta.get("symbol")):
                    cands[f"{uname}\0{sym}"] = ops
        out = []
        rows = {(r["unit"], self._meta(r).get("symbol")): r for r in self.net.store.all(
            "SELECT id, name, unit, status, best_score, attempts, meta, n_insns FROM functions WHERE project_id=?",
            proj["id"])}
        for key, sim in similarity.rank(target, cands, top=top * 2):
            uname, sym = key.split("\0", 1)
            if (uname, sym) in rows:
                out.append((rows[(uname, sym)], sim))
        out.sort(key=lambda x: (x[0]["status"] != "matched", -x[1]))
        return out[:top]

    def find_similar(self, slug: str, function: str, limit: int = 5) -> str:
        proj, fp, cfg = self.get(slug)
        fn = self._fn(slug, function)
        hits = self.similar(proj, fp, fn, top=max(1, min(int(limit), 15)))
        covered = len(self._index_of(proj, fp))
        total = len(fp.units())
        note = f"(index covers {covered} of {total} source files{'; still indexing' if proj['id'] in self._indexing else ''})"
        if not hits:
            return f"No look-alikes found for {fn['name']} {note}."
        lines = [f"Functions that look like {fn['name']} {note}:"]
        for r, sim in hits:
            lines.append(f"- {r['name']}  {sim * 100:.0f}% similar  {state_text(r)}  ({r['unit']}, {r['n_insns']} insns)")
        best = next((r for r, _ in hits if r["status"] == "matched"), None)
        if best is not None:
            src = self._current_source(fp, best)
            if src:
                lines += ["", f"Source of {best['name']} (matched):", "```c", src.strip()[:4000], "```"]
        return "\n".join(lines)

    def _current_source(self, fp: ForkProject, fn, comment: bool = False) -> str | None:
        """fn's definition as its file has it now, also when the file gets it by including another source file.
        `comment`: with the comment right above it (polishing's brief shows it)."""
        unit = fp.unit(fn["unit"])
        if not unit.source or not (fp.root / unit.source).exists():
            return None
        names = self._names(self._meta(fn), fn)
        todo, seen = [fp.root / unit.source], set()
        while todo and len(seen) < 6:
            path = todo.pop(0)
            if path in seen:
                continue
            seen.add(path)
            try:
                text = path.read_text(errors="replace", encoding="utf-8")
            except OSError:
                continue
            _, span = self._find(text, names)
            if span:
                return text[csource.comment_above(text, span[0]) if comment else span[0]:span[1]]
            for inc in _SOURCE_INCLUDE.findall(text):
                todo += [p for p in (fp.root / inc, fp.root / "src" / inc, path.parent / inc) if p.is_file()][:1]
        return None

    def twin_source(self, proj, a, b, names: dict[str, str], includes: bool = False, theirs=None) -> str | None:
        """a's matched definition, from its source file, written for its twin b: names swapped (see app/twins.py),
        with the includes and declarations it relies on from a's file that b's file doesn't have (compile_and_diff
        places those in b's file). None for a definition in assembly (then b is assembly too). `theirs`: a is that
        project's (twins across games): its declarations come along, never its includes (its headers aren't b's)."""
        from . import twins

        fp = ForkProject(Path(proj["root"]))
        fa = ForkProject(Path(theirs["root"])) if theirs is not None else fp
        ua, ub = fa.unit(a["unit"]), fp.unit(b["unit"])
        if not ua.source or not ub.source:
            return None
        includes = includes and theirs is None
        try:
            text_a = (fa.root / ua.source).read_text(errors="replace", encoding="utf-8")
            text_b = (fp.root / ub.source).read_text(errors="replace", encoding="utf-8") if (fp.root / ub.source).exists() else ""
        except OSError:
            return None
        _, span = self._find(text_a, self._names(self._meta(a), a))
        if span is None or _ASM_DEF.match(text_a[span[0]:span[1]]):
            return None
        code = twins.apply(text_a[span[0]:span[1]], names)
        used = set(re.findall(r"\b\w+\b", code))
        lines_b = {ln.strip() for ln in text_b.splitlines()}
        clean_b = csource._blank(text_b)
        declared_b = {m.group(1) for ln in text_b.splitlines() if drafts._DECL.match(ln.strip())
                      for m in [re.search(r"(\w+)\s*(?:\(|\[|;)", ln)] if m}
        head, seen = [], set()
        if includes:  # only the headers that define a name b's file doesn't know (more can clash with b's own)
            wanted = {n for n in used if not re.search(rf"\b{re.escape(n)}\b", clean_b)}
            head += _headers_defining(fp, ua.source, [ln for ln in _file_scope_lines(text_a)
                                                      if _INCLUDE_LINE.match(ln) and ln not in lines_b], wanted)
        for line in _file_scope_lines(text_a[:span[0]] + "\n" + text_a[span[1]:]):
            if _INCLUDE_LINE.match(line):
                continue
            if not drafts._DECL.match(line) or line.startswith("#"):
                continue
            renamed = twins.apply(line, names)
            name = re.search(r"(\w+)\s*(?:\(|\[|;)", renamed)
            if name and name.group(1) in used and name.group(1) not in declared_b and name.group(1) not in seen \
                    and renamed not in lines_b and not re.search(rf"\b{re.escape(name.group(1))}\b", clean_b):
                seen.add(name.group(1))
                head.append(renamed)
        if self._find(code, self._names(self._meta(b), b))[1] is None:
            return None  # a's definition isn't written under its symbol (a macro, another spelling): can't rename it
        return "\n".join(head) + ("\n" if head else "") + code

    def c_linkage(self, proj, a, b, source: str) -> str | None:
        """a's code made into b's, given C linkage (`extern "C"` on its definition and prototypes) when it goes
        from a C file into a C++ one: there its names would be mangled (fn_1_BB34 becomes fn_1_BB34__Fis), so
        the build has no fn_1_BB34 at all (0%). None when that isn't the case."""
        fp = ForkProject(Path(proj["root"]))
        src_a, src_b = fp.unit(a["unit"]).source or "", fp.unit(b["unit"]).source or ""
        cpp = (".cpp", ".cp", ".cc", ".cxx")
        sym = self._meta(b).get("symbol") or b["name"]
        if not src_b.endswith(cpp) or src_a.endswith(cpp) or "__" in sym.strip("_"):
            return None
        _, span = self._find(source, self._names(self._meta(b), b))
        if span is None or re.match(r"\s*(?:static|inline)\b", source[span[0]:span[1]]):
            return None
        head = []
        for line in source[:span[0]].splitlines():
            if drafts._DECL.match(line.strip()) and "(" in line and 'extern "C"' not in line:
                line = 'extern "C" ' + re.sub(r"^\s*extern\s+", "", line.strip())
            head.append(line)
        return "".join(line + "\n" for line in head) + 'extern "C" ' + source[span[0]:]

    def twin_declaration(self, proj, a, b, missing: str, names: dict[str, str]) -> str | None:
        """A declaration of `missing`, a name the code made from a's for b uses where b's file doesn't declare it yet
        (the compiler's "undefined identifier"): b's file's own (its prototype, or the head of its definition, both
        may come further down), else a's file's for the same name, renamed. Data only as extern: b's file keeps the
        data it defines."""
        from . import twins

        fp = ForkProject(Path(proj["root"]))
        ua, ub = fp.unit(a["unit"]), fp.unit(b["unit"])
        try:
            text_a = (fp.root / ua.source).read_text(errors="replace", encoding="utf-8")
            text_b = (fp.root / ub.source).read_text(errors="replace", encoding="utf-8") if (fp.root / ub.source).exists() else ""
        except (OSError, TypeError):
            return None
        a_name = {v: k for k, v in names.items()}.get(missing, missing)

        def declared(text: str, name: str) -> str | None:
            for line in _file_scope_lines(text):
                if line.startswith("#") or not re.search(rf"(?<![\w:]){re.escape(name)}\s*[(\[;=]", line):
                    continue
                if "(" in line.split("=", 1)[0] and line.endswith(";"):
                    return line  # a prototype
                if drafts._DECL.match(line) or "=" in line:  # data: refer to it, never define it again
                    left = re.sub(r"\bstatic\s+", "", line.split("=", 1)[0].rstrip(" ;"))
                    return left + ";" if left.startswith("extern") else f"extern {left};"
            span = csource.find(text, name)
            if span is not None:
                head = text[span[0]:span[1]].split("{", 1)[0].strip()
                if "(" in head:
                    return head + ";"
            return None

        if (own := declared(text_b, missing)) is not None:
            return own
        theirs = declared(text_a, a_name)
        if theirs is None:
            return None
        return re.sub(r"^(?:static\s+|inline\s+)+", "", twins.apply(theirs, names))  # b's file doesn't define it

    def twin_types(self, proj, a, b, source: str) -> str:
        """The file-scope type definitions (struct, union, enum, typedef) of a's file that `source` (a's code made
        into b's) relies on and b's file doesn't have, in a's order: for code that uses a type a's file defines."""
        fp = ForkProject(Path(proj["root"]))
        ua, ub = fp.unit(a["unit"]), fp.unit(b["unit"])
        try:
            text_a = (fp.root / ua.source).read_text(errors="replace", encoding="utf-8")
            text_b = (fp.root / ub.source).read_text(errors="replace", encoding="utf-8") if (fp.root / ub.source).exists() else ""
        except (OSError, TypeError):
            return ""
        blocks = _type_blocks(text_a)
        clean_b = csource._blank(text_b)
        want, out = set(re.findall(r"\b\w+\b", source)), []
        for _ in range(4):  # types used by the types taken
            added = False
            for names, block in blocks:
                if block in out or not names & want or any(re.search(rf"\b{re.escape(n)}\b", clean_b) for n in names):
                    continue
                out.append(block)
                want |= set(re.findall(r"\b\w+\b", block))
                added = True
            if not added:
                break
        return "\n".join(b for _, b in blocks if b in out)

    def one_definition(self, slug: str, source: str, name: str, others: list[str]) -> str:
        """A source holding several functions' definitions, with the definitions of `others` (and the #pragma lines
        right around them) taken out: what compile_and_diff for `name` alone gets."""
        for other in others:
            try:
                fn = self._fn(slug, other)
            except NetworkError:
                continue
            _, span = self._find(source, self._names(self._meta(fn), fn))
            if span:
                lo, hi = _pragmas_around(source, *span)
                source = source[:lo] + source[hi:]
        return source

    def is_asm(self, proj, fn) -> bool:
        """Whether a matched function's definition in its file is hand-written assembly (an asm function)."""
        src = self._current_source(ForkProject(Path(proj["root"])), fn)
        return bool(src and _ASM_DEF.match(src))

    def mark_asm(self, fn, twin_name: str | None = None, reason: str | None = None) -> None:
        """fn's code is a matched assembly function's (runtime helpers each module links its own copy of), or code
        no compiler makes (`reason`: Console.asm_reason, arch/): agents can't write it in C, so it's out of their way."""
        meta = self._meta(fn)
        if meta.get("reopened"):  # the user gave it back to the agents (Network.reopen)
            return
        if twin_name:
            meta["asm_twin"] = twin_name
        if reason:
            meta["asm_code"] = reason
        with self.net.store.tx() as db:
            if db.execute("UPDATE functions SET status='asm', meta=? WHERE id=? AND status='open'",
                          (json.dumps(meta), fn["id"])).rowcount:
                db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))  # out of the queue, and its claim

    # ------------------------------------------------------------------ for agents

    def info(self, slug: str) -> str:
        proj, fp, cfg = self.get(slug)
        m = cfg.get("measures") or {}
        units = fp.units() if cfg.get("ready") else []
        scratch = next((u.scratch for u in units if u.scratch), None) or {}
        platform = consoles.name(cfg.get("platform")) or "unknown platform"
        console = consoles.get(cfg.get("platform"))
        # the project's own compilers (review of #138: a 32-bit PC game's session was told of MSVC/14.16-x64 too)
        per_file = (f"each source file can have its own compiler (try_compiler switches it, \"all\" tries each); "
                    f"this project's: {', '.join(c.id for c in console.project_compilers(fp))}\n"
                    if console.file_compiler(fp, "") else "")
        what = ("started from scratch from your copy of the game" if cfg.get("origin") == "scratch"
                else f"a fork of {cfg['repo_url']}")
        return (f"{proj['name']}: {what} ({platform}{', ' + cfg['version'] if cfg.get('version') else ''})\n"
                f"progress: {m.get('matched_functions', '?')}/{m.get('total_functions', '?')} functions, "
                f"{float(m.get('matched_code_percent', 0) or 0):.2f}% of code, in {len(units)} source files\n"
                f"compiler: {scratch.get('compiler', 'set by the project build')} {scratch.get('c_flags', '')}\n"
                + per_file +
                "You work in the project's real source tree. claim_function, then compile_and_diff writes your function "
                "into its source file, builds that file with the project's build system and diffs it with objdiff. "
                "read_file and search_code show how the codebase is written; edit_file changes headers and file-level "
                "declarations (undone if it breaks any match). Guides: guide()."
                + "".join(f"\nThe project has notes for contributors: read_file(\"{n}\") before you start."
                          for n in ("AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md") if (fp.root / n).exists())[:400])

    def _fn(self, slug: str, name: str):
        return self.net._function(name, slug)

    @staticmethod
    def _names(meta: dict, fn) -> list[str]:
        """Ways the function may be spelled in source: its real name (a PC game's, Console.real_names), full C++
        name, Class::method, then the plain symbol."""
        out = [meta["real"]] if meta.get("real") else []
        dem = (meta.get("demangled") or "").split("(", 1)[0].strip()
        if dem:
            dem = dem.split(" ")[-1] if " " in dem and "operator" not in dem else dem
            out.append(dem)
            parts = dem.split("::")
            if len(parts) > 2:
                out.append("::".join(parts[-2:]))
            if len(parts) > 1:
                out.append(parts[-1])
        out.append(meta.get("symbol") or fn["name"].split("@")[0])
        if (c := _MSVC_C.fullmatch(meta.get("symbol") or "")):  # _f, _f@8 (__stdcall), @f@8 (__fastcall): f in C
            out.append(c.group(1))
        if not dem and re.fullmatch(r"[A-Za-z_]\w*", out[-1]):
            # a class named after the function, and its destructor (func_004D9DD0::~func_004D9DD0): a PC game's
            # build pairs it by the address in its name; its constructor is func_004D9DD0::func_004D9DD0 already
            out.append(f"{out[-1]}::~{out[-1]}")
        return list(dict.fromkeys(out))

    def _find(self, text: str, names: list[str]):
        for n in names:
            span = csource.find(text, n)
            if span:
                return n, span
        return None, None

    @staticmethod
    def _defined(text: str, names: list[str]) -> tuple[int, int] | None:
        """The span of the definition of the first of `names` the file defines, only one at file scope that opens its
        body: find() takes a call followed by a block for one (`} else if (f(p) != 0 && ...) {`), and split_file,
        moving that "definition", cut the function holding the call in two (a DS game: every split of one file
        failed with "declaration syntax error")."""
        for n in names:
            at = 0
            while (found := csource.find(text[at:], n)) is not None:
                span = (at + found[0], at + found[1])
                if csource.at_file_scope(text, span[0]) and csource.opens_body(text, span, n):
                    return span
                at = span[1]
        return None

    @classmethod
    def _seen_beside(cls, fp: ForkProject, text: str, span: tuple[int, int], hit: str,
                     names: list[str]) -> tuple[int, int] | None:
        """The definition the build sees after one an `#if` hides at `span`, or None: found by `hit`, then by the
        function's other `names`. Only one at file scope counts: a call in another function's body followed by a
        block reads as a definition (`y = f(x) * 2.0;` then `if (y) {`), and taken for it, that function was cut from
        the call on and the try put inside it."""
        for look in dict.fromkeys([hit, *names]):
            at = span
            while (later := csource.find(text[at[1]:], look)) is not None:
                at = (at[1] + later[0], at[1] + later[1])
                # (and only one that surely is a definition: at file scope too, find() takes a call for one, `static
                # double bias = f(2.0) * 2.0;` up to the next definition's `{`, and the code between was replaced;
                # and only one the build surely compiles: of `#ifdef _WIN32` and its `#else`, a macro the app can't
                # tell, the try went into the first, maybe the branch the build leaves out, and never matched)
                if csource.at_file_scope(text, at[0]) and csource.opens_body(text, at, look) and \
                        cls._surely_compiled(fp, text, at[0]):
                    return at
        return None

    @staticmethod
    def _surely_compiled(fp: ForkProject, text: str, at: int) -> bool:
        """Whether the code at `at` is compiled whatever the macros the project may define are (csource.
        surely_compiled with the project's never-defined ones, _hidden's)."""
        names = {n for n in csource.condition_names(text, at) if project_macro(n)}
        return csource.surely_compiled(text, at, fp.never_defined(names) if names else set())

    @staticmethod
    def _hidden(fp: ForkProject, text: str, at: int) -> tuple[int, str] | None:
        """(line, directive) of the `#if` branch that leaves the code at `at` of a source out of the build. The search
        for definitions (a second or so in a big project) runs only when the code would be hidden with every macro
        that may be the project's own undefined: knowing more macros undefined only ever hides more."""
        names = {n for n in csource.condition_names(text, at) if project_macro(n)}
        if csource.hidden_by(text, at, names) is None:
            return None
        return csource.hidden_by(text, at, fp.never_defined(names))

    def _held(self, proj, unit: str, text: str | None = None) -> set[str]:
        """Functions of a unit whose source is still the very text judged to load the wrong constants: objdiff's
        progress rules count them, decompdecomp doesn't (see forks/literals.py)."""
        rows = self.net.store.all("SELECT name, meta FROM functions WHERE project_id=? AND unit=? AND meta LIKE ?",
                                  proj["id"], unit, '%"held"%')
        if not rows:
            return set()
        if text is None:
            try:
                u = ForkProject(Path(proj["root"])).unit(unit)
                text = (Path(proj["root"]) / u.source).read_text(errors="replace", encoding="utf-8") if u.source else ""
            except (ForkError, OSError):
                return set()
        out = set()
        for r in rows:
            meta = self._meta(r)
            _, span = self._find(text, self._names(meta, r))
            if span and _digest(text[span[0]:span[1]]) == meta.get("held"):
                out.add(meta.get("symbol"))
        return out

    def recheck_matches(self, slug: str, log=print) -> int:
        """Matched functions checked again by literals.mismatches, as compile_and_diff checks a new match: one judged
        before a check existed (ARM's references to other symbols than the original's) is held, with a note on what
        differs, and goes back to open. Returns how many."""
        from ..forks import literals

        proj, fp, _ = self.get(slug)
        rows = self.net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
        found = []
        for r in rows:
            meta = self._meta(r)
            try:
                u = fp.unit(r["unit"])
            except ForkError:
                continue
            if not (u.target and u.base and u.source):
                continue
            paths = [p if Path(p).is_absolute() else Path(fp.root) / p for p in (u.target, u.base)]
            if not all(p.exists() for p in paths):
                continue
            wrong = literals.mismatches(*paths, meta.get("symbol") or r["name"], [])
            if not wrong:
                continue
            try:
                text = (Path(fp.root) / u.source).read_text(errors="replace", encoding="utf-8")
            except OSError:
                continue
            _, span = self._find(text, self._names(meta, r))
            if span is None:
                continue
            self._hold(r, text[span[0]:span[1]])
            found.append((r, wrong))
        if found:
            agent, _ = self.net.local_agent("decompdecomp")
            for r, wrong in found:
                listing = "; ".join(m.describe() for m in wrong[:4])
                try:
                    self.net.add_note(agent, slug, f"Not a match after all (checked again by decompdecomp): every "
                                                   f"instruction is the original's, but {listing}.", r["name"])
                except NetworkError:
                    pass
            self.sync(slug, log=log)
        return len(found)

    def _hold(self, fn, code: str | None) -> None:
        """Remember (code) or forget (None) that this text of the function loads constants the original doesn't."""
        meta = self._meta(fn)
        if code is None and "held" not in meta:
            return
        if code is None:
            meta.pop("held", None)
        else:
            meta["held"] = _digest(code)
        with self.net.store.tx() as db:
            db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), fn["id"]))

    def _reopened(self, db, proj, r, via: str, pct: float | None, held: bool = False) -> None:
        """Record a matched function going back to open, with what measured it and how (`via`: a unit's diff, the
        full report...), so a function that keeps flipping shows why in the events."""
        why = ("matches but is held (its constants or references differ)" if held else
               "isn't in the build's object" if pct is None else f"{pct:.2f}%")
        self.net._event(db, proj["id"], None, "reopen", f"{r['name']} ({via}: {why})")

    @staticmethod
    def _missing_note(unit, fn) -> str:
        """What to tell an agent whose compile built, but whose unit's object has no such function: with what the
        build said about its address (an LTCG harness's <object>.ltcg.json `problems`). It names the symbol, not the
        row: a name made unique with a trailing "'" sent agents after a symbol no C could make."""
        at = f"0x{fn['vram']:08X}" if "vram" in fn.keys() and fn["vram"] else None
        said = [p for p in objdiff.ltcg_problems(unit.base) if at and at.lower() in p.lower()]
        sym = ForkEngine._meta(fn).get("symbol") or fn["name"]
        note = (f"\n\nNOT IN YOUR BUILD: {unit.name} compiled, but its object doesn't define {sym}, so there "
                "is nothing to compare yet")
        if not said:
            return note + "."
        return (note + ":\n" + "\n".join(f"- {p}" for p in said[:4]) + "\nIf a helper sits between the function's "
                "`// FUNCTION:` annotation and its definition, move the helper above the annotation (edit_file).")

    def _program(self, fp: ForkProject):
        """The original program and its functions, for a project built with link-time code generation (None: not
        one, or it can't be read: a heuristic never stands between an agent and the function)."""
        manifest = fp.manifest or {}
        if not manifest.get("ltcg"):
            return None
        try:
            return convention.load(fp.root, manifest)
        except (OSError, KeyError, ValueError, ForkError):
            return None

    def _ltcg_brief(self, fp: ForkProject, meta: dict, fn, unit) -> list[str]:
        """For a brief, in an LTCG project (forks/ltcg.py): how the original passes the function its arguments
        (forks/convention.py), which the driver and stand-ins in harness/ must reproduce, and whether this unit's
        compile already goes through a harness."""
        if (prog := self._program(fp)) is None:
            return []
        try:
            addr = prog.find(meta.get("symbol") or fn["name"])
            found = convention.evidence(prog, addr) if addr is not None else []
        except Exception:  # a heuristic: it never stands between an agent and the function
            logging.getLogger("decompdecomp").exception("reading the function's convention failed")
            return []
        if not found:
            return []
        name = unit.name
        if ltcg.has_entry(fp.root, name):
            mode = [f"- Your compile already goes through the harness: {name} is built with /GL and linked with /LTCG "
                    f"with harness/{name}.drv.cpp, whose calls make the linker pick these registers. Write the "
                    "function as ordinary C/C++ and compile it: the convention is not a reason to release it. If "
                    "what differs is the convention itself, make the driver's call (or a stand-in) look like the "
                    "original's call site below. Functions are found in the link by func_<address> in their names, or "
                    "by `// FUNCTION: 0x<address>` right above the definition (for a method or an operator: add the "
                    "map symbol's substring after the address)."]
        else:
            mode = [f"- {name} builds plain, without /GL: harness/{name}.drv.cpp doesn't define HarnessEntry yet. "
                    "That is right for code the game built without link-time code generation (a library piece, a "
                    "file built /O2): write it as plain C. If this function's callers pass it registers (below), the "
                    f"unit needs a driver first: standins_for(\"{name}\") writes a starting point (stand-ins "
                    "for what the unit uses elsewhere, a HarnessEntry); put it in with edit_file."]
        return ["", "### Calling convention in the original (link-time code generation: the linker picked it for its "
                "callers; harness/ must call it the same way)", *mode,
                *[f"- {line}" if not line.startswith("  ") else line for line in found]]

    def _convention_warning(self, fp: ForkProject, meta: dict, fn, unit) -> list[str]:
        """For an attempt's result in an LTCG project: when the function the harness link made differs in convention
        from the original's, say so. A helper or driver call adds a call site, which can change what the linker picks
        for the callee, and then the bytes differ for a reason the C doesn't show."""
        if unit.base is None or (prog := self._program(fp)) is None:
            return []
        try:
            symbol = meta.get("symbol") or fn["name"]
            addr = prog.find(symbol)
            if addr is None or not unit.base.exists():
                return []
            code = next((c for owner, c, _ in coffobj.sections(unit.base.read_bytes())
                         if owner == symbol or coffobj.c_name(owner) == fn["name"]), None)
            if not code:
                return []
            found = convention.differences(convention.analyse(prog.code(addr), addr), convention.analyse(code, addr))
        except Exception:  # a heuristic: it never stands between an agent and the result
            logging.getLogger("decompdecomp").exception("comparing the compiled convention failed")
            return []
        if not found:
            return []
        return ["", "The linker gave your function another convention than the original's (" + "; ".join(found) + "). "
                "Under LTCG the callers decide it: keep the original's number of call sites (a helper, a stand-in or "
                "a second driver call adds one), and check that the driver's calls load what the brief's call sites "
                "load. The brief's convention evidence is the target."]

    def _method_brief(self, fp: ForkProject, cfg: dict, meta: dict, fn) -> list[str]:
        """For a brief, in an LTCG project: whether the function looks like a member function, of which struct, its
        fields and the declaration to write (forks/methods.py: `this` can arrive in any register under LTCG, which the
        ECX-only readers of structs.py and the RTTI classes miss). When RTTI already named the function's class
        (`_class_brief`), only the register is added: the class's name is the game's own."""
        if (prog := self._program(fp)) is None:
            return []
        try:
            addr = prog.find(meta.get("symbol") or fn["name"])
            if addr is None:
                return []
            objs = methods.recover(prog, True)
            lines = methods.brief(prog, objs, addr, True, meta.get("demangled"))
            if self._class_of(fp, cfg, fn)[1] is not None and addr in objs.of:
                return ["", f"- `this` arrives in {objs.of[addr].methods[addr]} (the linker's choice under link-time "
                            "code generation): a member function of the class above still matches"]
            if lines and lines[1].startswith("### Looks like a member function"):
                lines += ["```cpp", methods.declaration(prog, objs.of[addr]), "```"]
            return lines
        except Exception:  # a heuristic: it never stands between an agent and the function
            logging.getLogger("decompdecomp").exception("finding member functions failed")
            return []

    def _unresolved_lines(self, fp: ForkProject, meta: dict, fn, unit, code: str | None,
                          only_mattering: bool = False) -> list[str]:
        """For a brief, a compile result or a release: the names the unit's last harness link left unresolved that
        this function's code uses, which of them can change its code (forks/unresolved.py) and which are harmless.
        A bare list read as a to-do, and agents released functions for references that change nothing."""
        if unit.base is None or not (missing := ltcg_unresolved(unit.base)):
            return []
        prog = self._program(fp)
        caller, library = None, set()
        if prog is not None:
            caller = prog.find(meta.get("symbol") or fn["name"])
            library = {prog.by_name[x] for x in _set_aside(fp) if x in prog.by_name}
        used = unresolved.used_by(code, missing) if code else []
        found = [unresolved.classify(prog, caller, x, library) for x in used]
        if only_mattering:
            found = [u for u in found if u.matters is not False]
            return unresolved.summary(found, unit.name) if found else []
        return unresolved.summary(found, unit.name, len(missing) - len(used))

    def standins_for(self, agent: Agent | None, slug: str, what: str) -> str:
        """Stand-in and driver skeletons for a unit of an LTCG project (forks/standins.py): a unit, its source file
        or one of its functions. What agents write into harness/."""
        _, fp, _ = self.get(slug)
        if (prog := self._program(fp)) is None:
            raise NetworkError("standins_for is for projects of games built with link-time code generation (harness/ "
                               "files): this project isn't one")
        name = what.strip()
        units = {f["unit"] for f in prog.functions.values()}
        unit = next((u for u in (name, name.rsplit("/", 1)[-1], Path(name).stem) if u in units), None)
        if unit is None and (addr := prog.find(name)) is not None:
            unit = prog.functions[addr]["unit"]
        if unit is None:
            try:
                row = self._fn(slug, name)
            except NetworkError:
                raise NetworkError(f"{what!r} isn't a unit, source file or function of this project") from None
            if (addr := prog.find(self._meta(row).get("symbol") or row["name"])) is None:
                raise NetworkError(f"{what!r} isn't in this project's functions.json")
            unit = prog.functions[addr]["unit"]
        return standins.render(prog, unit)

    def _apply_scores(self, proj, unit: str, scores: dict[str, float | None], skip: int | None = None,
                      agent: Agent | None = None, text: str | None = None, via: str = "unit diff") -> None:
        """Bring every function of a unit up to date with a fresh diff (cheaper than a full report). A function
        that matches now is a match like any other, whichever change made it: `agent` (whose edit it was) is
        credited, and `text` (the unit's source) gives the matching code. `via` says which measure it was, for the
        reopen events."""
        rows = self.net.store.all("SELECT id, name, status, n_insns, best_score, best_source, meta FROM functions "
                                  "WHERE project_id=? AND unit=?", proj["id"], unit)
        held = self._held(proj, unit, text)
        with self.net.store.tx() as db:
            for r in rows:
                sym = self._meta(r).get("symbol")
                if r["id"] == skip or sym not in scores or r["status"] == "nosource":
                    continue
                pct = scores[sym]
                if pct is not None and pct >= 100 and sym not in held:
                    if r["status"] != "matched":
                        self._matched(db, proj, r, agent, text)
                elif r["status"] == "matched":  # no longer matches: its best is what it scores now, not 0 (identical)
                    db.execute("UPDATE functions SET status='open', best_score=? WHERE id=?",
                               (None if pct is None else scaled(pct, r["n_insns"]), r["id"]))
                    self._reopened(db, proj, r, via, pct, held=pct is not None and pct >= 100)
                elif pct is not None and r["best_score"] == 0:  # reopened before this was fixed: still says identical
                    db.execute("UPDATE functions SET best_score=? WHERE id=?", (scaled(pct, r["n_insns"]), r["id"]))
                elif pct is not None and not r["best_source"] and r["best_score"] != scaled(pct, r["n_insns"]):
                    score = scaled(pct, r["n_insns"])
                    improved = (score < r["n_insns"] * 100
                                and (r["best_score"] is None or score < r["best_score"]))
                    db.execute("UPDATE functions SET best_score=?, "
                               "last_improved=CASE WHEN ? THEN ? ELSE last_improved END WHERE id=?",
                               (score, improved, time.time(), r["id"]))

    def _matched(self, db, proj, r, agent: Agent | None, text: str | None) -> None:
        """Record a function that matches now (outside compile_and_diff, which records its own)."""
        source = None
        if text:
            _, span = self._find(text, self._names(self._meta(r), r))
            source = text[span[0]:span[1]] if span else None
        db.execute("UPDATE functions SET status='matched', best_score=0, matched_at=?, matched_agent_id=?, "
                   "matched_source=COALESCE(?, matched_source, best_source) WHERE id=?",
                   (time.time(), agent.id if agent else None, source, r["id"]))
        db.execute("DELETE FROM claims WHERE function_id=?", (r["id"],))
        self.net._event(db, proj["id"], agent.id if agent else None, "match", r["name"])
        self.net.on_match(proj, r["id"], agent)

    DATA_LISTED = 12  # data symbols a brief describes

    def permuter_name(self, slug: str, function: str, source: str) -> str:
        """The name the function's definition has in `source`, which decomp-permuter looks it up by: a PC or Xbox
        game's function is its mangled symbol (`?Update@@YAXH@Z`), which no C spells, so every turn on one ended
        with "Function ... not found in base.c". The symbol itself when no spelling of it (_names) is defined. The
        definition's own spelling, class and all: a method found by its bare name (`Func_E46D0`) may be defined on
        a class the source calls something else than its symbol does (`C_vt_003AB500::Func_E46D0`), and the
        bare name isn't the definition's (6 of 8 an Xbox game's turns lost that way)."""
        fn = self._fn(slug, function)
        names = [n for n in self._names(self._meta(fn), fn) if re.fullmatch(r"[\w:~]+", n)]
        name, span = self._find(source, names)
        if name is None:
            return function
        own = re.search(rf"(?<![\w:~])((?:[A-Za-z_]\w*\s*::\s*)*~?{re.escape(name.split('::')[-1])})\s*\(",
                        source[span[0]:span[1]])
        return re.sub(r"\s+", "", own.group(1)) if own else name

    def permuter_header(self, slug: str, function: str) -> str:
        """What decomp-permuter must read before a function of a fork: the headers its source file includes, then
        the file's own declarations. It got none, so it refused every DS function ("Syntax error in base.c": `u16`
        was no type it knew) and only the simple rewrites ran, there and in every fork."""
        _, fp, _ = self.get(slug)
        unit = fp.unit(self._fn(slug, function)["unit"])
        if not unit.source or not (fp.root / unit.source).is_file():
            return ""
        seen: set[Path] = set()

        def headers(text: str, folder: Path) -> list[str]:  # what `text` includes, each header after its own
            out = []
            for name in _QUOTED_INCLUDE.findall(text):
                for base in (fp.root / "include", folder, fp.root / "src", fp.root):
                    h = (base / name).resolve()
                    if h.is_file():
                        if h not in seen and len(seen) < MAX_HEADERS and h.is_relative_to(fp.root.resolve()):
                            seen.add(h)
                            own = h.read_text(errors="replace", encoding="utf-8")
                            out += [*headers(own, h.parent), own]
                        break
            return out
        source = (fp.root / unit.source).read_text(errors="replace", encoding="utf-8")
        return "\n".join([*headers(source, (fp.root / unit.source).parent), _without_bodies(source)])

    def _data_used(self, proj, refs: list[str]) -> list[str]:
        """A from-scratch project's brief: the data the function uses, where it is and how big, with how to declare
        it. Its headers start empty, and on a DS game a model looked for that in config/symbols.txt for minutes."""
        if not refs:
            return []
        marks = ",".join("?" * len(refs))
        funcs = {r["name"] for r in self.net.store.all(
            f"SELECT name FROM functions WHERE project_id=? AND name IN ({marks})", proj["id"], *refs)}
        out = []
        for name in [r for r in refs if r not in funcs][:self.DATA_LISTED]:
            try:
                said = self.read_data(None, proj["slug"], name, 4).split("\n", 1)[0]
            except NetworkError:
                said = ""
            m = re.search(r", (\.?[\w.]+)\+0x[0-9A-Fa-f]+, (\S+) bytes\)", said)
            out.append(f"- {name}: {m.group(1)}, {m.group(2)} bytes" if m else f"- {name}")
        if not out:
            return []
        return ["", "### Data it uses", *out,
                "Declare what isn't declared yet once, with edit_file at the top of the source file: `extern` and the "
                "type its loads and stores use (2 bytes: `extern u16 name;`; bigger ones: an array, or a struct whose "
                "fields are the offsets the code uses). That's all there is to know about them: nothing in config/ "
                "says more."]

    def brief(self, fn, agent: Agent | None, header: str) -> str:
        proj = self.net.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        _, fp, cfg = self.get(proj["slug"])
        meta = self._meta(fn)
        unit = fp.unit(fn["unit"])
        lines = [f"## {header}: {fn['name']}  ({proj['name']})", f"unit {unit.name}, {fn['size']} bytes"]
        if fn["status"] != "matched":
            lines.append(move_on_brief(fn, self.net.stall_after(fn, agent)))
            lines += tried_brief(fn)
            lines += self.net.tried_at_best(fn)
        if (reg := meta.get("static_register_arg")) and fn["status"] != "matched":
            lines.append(f"its code reads {reg} before it sets it: an argument in {reg}, from callers all in its own "
                         f"source file. Visual C++ gives a static function a convention of its own (arguments in "
                         f"registers it picks): write it `static`, with ordinary parameters, above its callers in the "
                         f"file, and call it plainly; never __fastcall with an unused argument (its callers then set "
                         f"ecx, which the game's don't)")
        if (beside := meta.get("join_for_static")) and fn["status"] != "matched":
            lines.append(f"its code reads {meta.get('register_arg') or 'a register'} before it sets it, and every call "
                         f"to it is in {beside}, the file next to its own: the game's file was one, cut in two by the "
                         f"project. Visual C++ gives a static function a convention of its own (arguments in registers "
                         f"it picks), so call join_files(\"{fn['name']}\", \"{beside}\") first, then write it `static`, "
                         f"with ordinary parameters, above its callers")
        if (callees := meta.get("static_callees")) and fn["status"] != "matched":
            shown = ", ".join(c.lstrip("_@").split("@")[0] for c in callees)
            lines.append(f"it calls {shown}, which take{'s' * (len(callees) == 1)} an argument in a register from "
                         f"callers all in this file: a static function's convention, not link-time code. Write "
                         f"{'it' if len(callees) == 1 else 'them'} `static` above this function in the file, with "
                         f"ordinary parameters, and call {'it' if len(callees) == 1 else 'them'} plainly: this "
                         f"function's own calls then load the registers the game's do")
        if (reg := meta.get("register_arg")) and fn["status"] != "matched" and not meta.get("join_for_static"):
            lines.append(f"its code reads {reg} before it sets it: an argument in {reg}, a convention link-time code "
                         f"generation (/GL /LTCG) gives functions whose callers it all sees. No C declaration of one "
                         f"file passes an argument in {reg}: once your C's body matches and only its entry and exit "
                         f"differ, say so (release_function with not_c) instead of trying more")
        if meta.get("demangled"):
            lines.append(f"C++ name: {meta['demangled']}")
        if unit.scratch:
            lines.append(f"compiler: {unit.scratch.get('compiler', '?')} {unit.scratch.get('c_flags', '')}")
        src_text = None
        if unit.source:
            lines.append(f"source file: {unit.source}")
            if own := consoles.get(cfg.get("platform")).file_compiler(fp, unit.source):
                lines.append(f"this file's compiler: {own} (try_compiler(\"{fn['name']}\", \"all\") tries the others)")
                lines += self.net.filecompilers.brief(proj["slug"], fn, unit.source)
            p = fp.root / unit.source
            src_text = p.read_text(errors="replace", encoding="utf-8") if p.exists() else None
        else:
            lines.append("this unit has no source file yet, so it can't be decompiled from here")
        asm_block: list[str] = []
        diff_block: list[str] = []
        diff_rows = 0
        source_block: list[str] = []
        best_block: list[str] = []
        said = ""
        try:
            d = fp.diff(unit, meta.get("symbol") or fn["name"])
            pct = ("not in your build yet" if d.match_percent is None else
                   d.why_not() if d.literals else
                   f"{percent_text(d.match_percent)} match")
            asm, said = asm_page(d.target_asm().splitlines(), 1, fn["name"])
            lines.append(f"current state: {pct}")
            asm_block = ["", "### Target assembly", *([said] if said else []), "```asm", *asm, "```"]
            if cfg.get("origin") == "scratch":
                lines += self._data_used(proj, d.refs)
            if d.literals:
                lines += ["", d.literals_note()]
            elif d.match_percent is not None and not d.matched:
                d.rows = with_constant_values(d.rows, consoles.get(cfg.get("platform")), fp)
                diff_block = ["", "### Diff against the current build", d.render(), *_observed(cfg, d)]
                diff_rows = len(d.rows)
                if agent is not None:  # (last_diff shows it, where a long brief leaves it out)
                    self.net.keep_diff(agent.id, fn["id"], d.rows, objdiff.LEGEND)
        except (ObjdiffError, ForkError) as e:
            lines.append(f"(objdiff couldn't diff this function: {e})")
        _, span = self._find(src_text, self._names(meta, fn)) if src_text else (None, None)
        shown_source = (1 + src_text.count("\n", 0, span[0]), src_text.count("\n", 0, span[1]) + 1) if span else None
        hidden_lines: list[str] = []
        if span:
            source_block = ["", "### Current source", "```c", src_text[span[0]:span[1]].strip(), "```"]
            if hidden := self._hidden(fp, src_text, span[0]):
                hidden_lines = [f"⚠️ It's inside `{hidden[1]}` (line {hidden[0]} of {unit.source}), which the build "
                                "leaves out: the state above is not this code's. compile_and_diff compiles yours where "
                                "the build sees it, without that copy; kept, the function is visible from then on."]
        else:
            source_block = ["", f"### Not in {unit.source or 'the source'} yet: compile_and_diff adds it at the end."]
        if fn["best_source"] and fn["status"] != "matched":
            best_block = ["", f"### Best attempt so far (score {fn['best_score']})", "```c",
                          self._with_renames(proj["slug"], fn, fn["best_source"]).strip(), "```"]
        elif fn["status"] != "matched" and (span is None or csource.is_stub(src_text[span[0]:span[1]])):
            seed = self._draft(proj, fp, cfg, fn, unit)
            made = self._compilable(proj, fp, cfg, fn, unit) if seed else None
            if made is not None:  # (as the headers are now: it follows them, and redraft adds an agent's)
                best_block = ["", "### Machine draft (Ghidra's, made to compile here; often wrong in types and details; "
                                  "redraft(function, context) makes it again with your declarations)", "```cpp",
                              (made[0] + "\n" if made[0] else "") + made[1].strip(), "```"]
            elif seed:
                best_block = ["", "### Machine draft: a starting point, often wrong in types and details", "```c",
                              self._method_draft(fp, cfg, fn, seed).strip(), "```"]
        head = lines
        lines = []
        lines += self._class_brief(fp, cfg, fn) + self._struct_brief(fp, cfg, fn)
        lines += self._debug_brief(fp, cfg, fn)
        lines += self._ltcg_brief(fp, meta, fn, unit)
        lines += self._method_brief(fp, cfg, meta, fn)
        if found := self._unresolved_lines(fp, meta, fn, unit, src_text[span[0]:span[1]] if span else None):
            lines += ["", f"### Unresolved in {unit.name}'s harness link (nothing in it defines them yet)", *found]
        twin = self._twin_brief(proj, fn) if fn["status"] != "matched" else []
        lines += twin
        try:
            alike = [] if twin else [(r, sim) for r, sim in self.similar(proj, fp, fn, top=3) if r["status"] == "matched"]
        except (ObjdiffError, ForkError):
            alike = []
        if alike:
            r, sim = alike[0]
            src = self._current_source(fp, r)
            lines += ["", f"### Looks like {r['name']} ({sim * 100:.0f}% similar, already matched)"]
            if src and len(src) < 3000:
                lines += ["```c", src.strip(), "```"]
            if len(alike) > 1:
                lines.append("also similar and matched: " + ", ".join(f"{x['name']} ({s * 100:.0f}%)" for x, s in alike[1:]))
        done = self.net.store.all("SELECT name FROM functions WHERE project_id=? AND unit=? AND status='matched' "
                                  "AND id != ? ORDER BY n_insns DESC LIMIT 12", fn["project_id"], fn["unit"], fn["id"])
        if done:
            lines += ["", "Already matched in this file (read them for the codebase's style): "
                      + ", ".join(r["name"] for r in done)]
        why = self.link_failures(fp.root, cfg).get(unit.source or "")
        if why and not unit.complete:
            lines += ["", f"### {unit.source} didn't link yet (file_status shows its data)", why]
        lines += self.net.dependency_brief(fn)
        best = fn["best_score"] if fn["status"] != "matched" else None
        best_text = (f"{percent_text(max(0.0, 100.0 * (1 - best / (fn['n_insns'] * 100))))} (score {best})"
                     if best is not None and fn["n_insns"] else "")
        notes = self.net.notes_for_brief(fn, best_text, show=6, when=False)
        if notes:
            lines += ["", "### Notes", *notes]
        tail = ["", "Send compile_and_diff the complete function definition (same name and signature as the original), "
                    "with any #include \"...\", prototypes or #pragma lines it needs. Structs, globals and helper "
                    "functions go in with edit_file."]
        whole = [*head, *asm_block, *diff_block, *source_block, *hidden_lines, *best_block, *lines, *tail]
        if sum(len(line) + 1 for line in whole) <= BRIEF_CHARS:
            return "\n".join(whole)
        # too long to be read (a 1,422-instruction function's: 62,000 characters): the best attempt and the notes
        # first, and the diff, the file's copy and the assembly behind the calls that show them, in that order
        name = fn["name"]
        why = "left out here: this brief would be too long to read"
        best_pointer = ["", f"### Best attempt so far: score {fn['best_score']}, {len(fn['best_source'] or '')} "
                            f"characters: get_function(\"{name}\", show=\"best\") shows it — start from it ({why})"]
        asm_pointer = ["", f"### Target assembly: get_function(\"{name}\", show=\"asm\") shows it, {ASM_PAGE} lines "
                           f"at a time ({why})"]
        source_pointer = (["", f"### Current source: lines {shown_source[0]}-{shown_source[1]} of {unit.source}: "
                               f"read_file(\"{unit.source}\", start={shown_source[0]}, "
                               f"count={shown_source[1] - shown_source[0] + 1}) shows it ({why})"]
                          if shown_source else None)
        diff_pointer = ["", f"### Diff against the current build: {diff_rows} rows; last_diff(\"{name}\") shows "
                            f"every differing one ({why})"]
        return "\n".join(fit_brief([
            (head, None), (best_block, best_pointer if fn["best_source"] and fn["status"] != "matched" else None),
            (hidden_lines, None), (lines, None), (asm_block, asm_pointer), (source_block, source_pointer),
            (diff_block, diff_pointer if diff_block else None), (tail, None)], BRIEF_CHARS))

    def _twin_brief(self, proj, fn) -> list[str]:
        """For a brief: the matched function with the same code (relocations aside), and its code made into this
        one's when the names can be swapped."""
        try:
            twin_id = self.net.twins.twin_of(proj, fn["id"])
        except Exception:
            return []
        if twin_id is None:
            return []
        a = self.net.store.one("SELECT * FROM functions WHERE id=?", twin_id)
        try:
            source = self.net.twins.source_for(proj, a, fn, includes=True)
        except (NetworkError, ForkError, OSError, ValueError):
            source = None
        out = ["", f"### Identical code: {a['name']} ({a['unit']}) is the same machine code and already matches"]
        if source and len(source) < 6000:
            why = self.net.twins.miss_why(fn["id"])
            out += ["Its code with this function's names: start from it. "
                    + (f"decompdecomp tried it as is: {why}. Fix that (this file lacks something the other one has: a "
                       "type, a declaration, an include, or declares a callee differently)." if why else
                       "If it doesn't build or match as is, this file lacks something that one has (a type, a "
                       "declaration, an include)."), "```c", source.strip(), "```"]
        elif self.is_asm(proj, a):
            out.append("It's hand-written assembly there, so this one is too: release it with a note saying so.")
        else:
            src = self._current_source(ForkProject(Path(proj["root"])), a)
            if src and len(src) < 4000:
                out += ["Its source (its names differ from this one's: use the ones in this function's assembly):",
                        "```c", src.strip(), "```"]
        return out

    def _draft(self, proj, fp: ForkProject, cfg: dict, fn, unit) -> str | None:
        """m2c draft from the project's assembly for this function (Ghidra's from its target object where m2c can't
        read the code), cached in the database. A console with drafts of its own (Ghidra's: PC) keys it by the unit's
        target object: a join, a split or a repair of the analysis changes that, and the draft is made again."""
        key = self._draft_key(cfg, unit)
        if seeds.drafted(fn["seed"], fn["seed_key"], key):
            return fn["seed"] or None
        hint = (unit.scratch or {}).get("compiler", "") or json.dumps(fp.needs(cfg.get("version")))
        meta = self._meta(fn)
        try:
            text = drafts.draft(fp.root, cfg.get("platform") or "", unit.name, meta.get("symbol") or fn["name"],
                                unit.source, compiler_hint=hint)
            text = text and "/* m2c */\n" + text
            if not text and unit.target is not None and unit.target.exists() and ghidra.available():
                found = ghidra.decompile_object(unit.target, fp.root / STATE / "ghidra")
                names = [meta.get("symbol") or fn["name"], *self._names(meta, fn)]
                body = next((found[n] for n in names if n in found), None)
                text = body and "/* Ghidra */\n" + consoles.get(cfg.get("platform") or "").adapt_draft(body.strip())
        except OSError:
            text = None
        with self.net.store.tx() as db:
            db.execute("UPDATE functions SET seed=?, seed_key=? WHERE id=?",
                       (text or "", seeds.draft_key(key, text), fn["id"]))
        return text

    @staticmethod
    def _draft_key(cfg: dict, unit) -> str | None:
        """What a function's machine draft is made from, where that changes (Console.own_drafts: its unit's target
        object, which Ghidra drafts): None elsewhere, a draft made once."""
        if not consoles.get(cfg.get("platform")).own_drafts or unit.target is None:
            return None
        try:
            return hashlib.sha1(unit.target.read_bytes()).hexdigest()[:16]
        except OSError:
            return None

    # ------------------------------------------------------------------ drafts in the background (app/drafts.py)

    def can_draft(self, proj) -> bool:
        """Whether the background drafter makes this project's drafts: a game started from scratch on a console with
        drafts of its own (PC), with Ghidra installed (its exact drafts need nothing, and are made as autopilot
        tries them)."""
        cfg = json.loads(proj["config"])
        return (cfg.get("origin") == "scratch" and bool(cfg.get("ready"))
                and consoles.get(cfg.get("platform")).own_drafts and ghidra.available())

    def stale_drafts(self, proj) -> list[int]:
        """Open functions whose machine draft is missing or was made from another target object, a unit after
        another (Ghidra drafts a whole unit at once); then the open ones autopilot tried, whose drafts the headers
        may have changed (each is tried again only if its draft did: autopilot_one skips what it judged)."""
        _, fp, cfg = self.get(proj["slug"])
        rows = self.net.store.all("SELECT id, unit, seed, seed_key FROM functions WHERE project_id=? AND "
                                  "status='open' ORDER BY unit, n_insns", proj["id"])
        keys = {}
        for r in rows:
            if r["unit"] not in keys:
                try:
                    keys[r["unit"]] = self._draft_key(cfg, fp.unit(r["unit"]))
                except (ForkError, KeyError):
                    keys[r["unit"]] = None
        stale = [r["id"] for r in rows if not seeds.drafted(r["seed"], r["seed_key"], keys[r["unit"]])]
        agent, _ = self.net.local_agent("autopilot")
        tried = {r["function_id"] for r in self.net.store.all(
            "SELECT DISTINCT a.function_id FROM attempts a JOIN functions f ON f.id=a.function_id WHERE "
            "f.project_id=? AND f.status='open' AND a.agent_id=?", proj["id"], agent.id)}
        return stale + [r["id"] for r in rows if r["id"] in tried and r["id"] not in set(stale)]

    def draft_mark(self, proj) -> tuple:
        """What drafts are made from, summed up: the headers (declarations, classes) and functions.json (names, the
        analysis) as they are on disk."""
        root = Path(proj["root"])
        files = [*sorted((root / "include").rglob("*.h")), *sorted((root / "config").rglob("functions.json"))]
        return tuple((p.name, p.stat().st_mtime_ns) for p in files if p.is_file())

    def background_draft(self, proj, fn) -> str | None:
        """One function's machine draft, made for the background drafter (and cached, as when a brief asks)."""
        _, fp, cfg = self.get(proj["slug"])
        unit = fp.unit(fn["unit"])
        return self._draft(proj, fp, cfg, fn, unit) if unit.source else None

    def redraft(self, slug: str, function: str, context: str) -> str:
        """redraft in a game whose console has drafts of its own (PC): Ghidra's draft made compilable again with an
        agent's declarations (a class that declares the function, a callee's prototype, a global's type) on top of the
        project's headers. Recorded nowhere."""
        proj, fp, cfg = self.get(slug)
        if not consoles.get(cfg.get("platform")).own_drafts:
            raise NetworkError("redraft makes the machine drafts of ROM projects (m2c) and PC games (Ghidra's): in "
                               "this project, write from the brief's draft")
        if not context.strip():
            raise NetworkError("pass the declarations to draft with in `context` (a class, a prototype, an extern)")
        if not ghidra.available():
            raise NetworkError("redraft needs Ghidra, which makes PC games' drafts: the user can install it in Setup")
        fn = self._fn(slug, function)
        unit = fp.unit(fn["unit"])
        made = self._compilable(proj, fp, cfg, fn, unit, context)
        if made is None:
            raise NetworkError(f"Ghidra's draft of {fn['name']} can't be made into C that compiles (it reads registers "
                               "or stack no C names): write from the brief's draft")
        prelude, code = made
        return (f"Ghidra's draft of {fn['name']} with your declarations, as C that compiles in {unit.source}. Recorded "
                "nowhere: try it with compile_and_diff (with your declarations in a header: edit_file), and keep what "
                "helped in the project's headers, so every draft and agent gets it.\n```cpp\n"
                + (prelude + "\n" if prelude else "") + code.strip() + "\n```")

    def _classes(self, fp: ForkProject, cfg: dict) -> classes.Classes | None:
        """The C++ classes the console reads from the project's program (Console.classes), or None."""
        try:
            return consoles.get(cfg.get("platform")).classes(fp)
        except Exception:  # a reading of the program: it never stands between an agent and the function
            logging.getLogger("decompdecomp").exception("reading the C++ classes failed")
            return None

    def _class_of(self, fp: ForkProject, cfg: dict, fn) -> tuple[classes.Classes | None, int | None]:
        """The project's classes and the function's address in them (None: no classes, or not one of theirs)."""
        found = self._classes(fp, cfg)
        return found, found.symbols.get(self._meta(fn).get("symbol") or fn["name"]) if found else None

    def _class_brief(self, fp: ForkProject, cfg: dict, fn) -> list[str]:
        """get_function's lines on the class of a virtual function, constructor or destructor (classes.brief_lines)."""
        found, addr = self._class_of(fp, cfg, fn)
        return classes.brief_lines(found, addr, self._class_label(found)) if addr is not None else []

    def _debug_brief(self, fp: ForkProject, cfg: dict, fn) -> list[str]:
        """What the game's own debug information says about the function (Console.debug_of), when it has any."""
        console = consoles.get(cfg.get("platform"))
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        known = console.debug_of(fp, version, self._meta(fn).get("symbol") or fn["name"]) if version else None
        return console.debug_brief(known) if known else []

    @staticmethod
    def _struct_label(found: structs.Structs):
        """A function's or global's name as agents know it: a global without a real name is D_<address>, as the
        project's sources name it."""
        return lambda addr: found.labels.get(addr, f"D_{addr:08X}")

    @staticmethod
    def _class_label(found: classes.Classes):
        return lambda addr: found.labels.get(addr, f"0x{addr:08X}")

    def _method_draft(self, fp: ForkProject, cfg: dict, fn, draft: str) -> str:
        """The machine draft as the brief shows it: where the function is surely a method of one class
        (classes.owner), as `Class::name(...)` with `this` (the processor's Arch.method_draft); else as made."""
        rewrite = arch.get(consoles.get(cfg.get("platform")).arch).method_draft
        if rewrite is None:
            return draft
        try:
            found, addr = self._class_of(fp, cfg, fn)
            cls, role = classes.owner(found, addr) if addr is not None else (None, "")
            if cls is None:
                return draft
            label = self._class_label(found)
            symbol = self._meta(fn).get("symbol") or fn["name"]
            word = re.sub(r"@.*$", "", symbol.lstrip("_@?"))  # the name inside a decorated symbol: the draft's holds it
            return rewrite(draft, word, label(cls.vtable), label(addr), role, found.found_from) or draft
        except Exception:  # a way of showing the draft: it never stands between an agent and it
            logging.getLogger("decompdecomp").exception("showing a draft as a C++ method failed")
            return draft

    def get_class(self, slug: str, what: str = "") -> str:
        """get_class in a project: the classes the console reads from its program (PC: RTTI and code), by name, vtable
        address or one of their functions (as the report, func_<address> or a real name spells it)."""
        _, fp, cfg = self.get(slug)
        found = self._classes(fp, cfg)
        if found is None:
            raise NetworkError(classes.WHERE)
        label = self._class_label(found)
        what = what.strip()
        if not what or not found.by_vtable:
            return classes.listing(found, label)
        addr = found.symbols.get(what, next((vt for vt, name in found.names.items() if name == what), None))
        if addr is None and (m := re.fullmatch(r"(?:0x)?([0-9A-Fa-f]{6,8})", what)):
            addr = int(m.group(1), 16)
        if addr is None:
            try:
                fn = self._fn(slug, what)
                addr = found.symbols.get(self._meta(fn).get("symbol") or fn["name"])
            except NetworkError:
                pass
        hits = found.find(addr) if addr is not None else []
        if not hits:
            raise NetworkError(f"`{what}` isn't a class, a vtable, or a virtual function, constructor or destructor of "
                               f"one of the {len(found.by_vtable)} classes found in this game: get_class() lists them")
        return "\n\n".join(classes.describe(c, found, label, focus=addr) for c in hits[:3])

    def _structs(self, fp: ForkProject, cfg: dict) -> structs.Structs | None:
        """The struct layouts the console guesses from the project's code (Console.structs), or None."""
        try:
            return consoles.get(cfg.get("platform")).structs(fp)
        except Exception:  # a reading of the program: it never stands between an agent and the function
            logging.getLogger("decompdecomp").exception("guessing struct layouts failed")
            return None

    def guess_struct(self, slug: str, function: str, argument: str = "arg0") -> str:
        """guess_struct in a project: the layout behind one of a function's pointers (`this`, arg0-arg3 on the
        stack, what it returns, or a global by its D_<address>), as layouts.guess_text says it."""
        from .engine import layouts

        _, fp, cfg = self.get(slug)
        found = self._structs(fp, cfg)
        if found is None:
            raise NetworkError(f"{layouts.where_read()}, not this project's")
        name = function.strip()
        addr = found.symbols.get(name)  # (the report's symbol, func_<address> or a real name)
        if addr is None:
            fn = self._fn(slug, function)
            name, addr = fn["name"], found.symbols.get(self._meta(fn).get("symbol") or fn["name"])
        if addr is None:
            raise NetworkError(f"{name} isn't one of the functions read from the program")
        base, path, n = layouts.parse_argument(argument)
        if n == structs.RETURN:
            key, what = (structs.RETURN, addr), "what it returns"
        elif n is not None:
            key, what = (structs.ARGUMENT, addr, n), structs.argument_name(n)
        else:
            m = re.fullmatch(r"_?(?:D_|0x)?([0-9A-Fa-f]{8,16})", base)
            at = int(m.group(1), 16) if m else next((a for a, name in found.labels.items() if name == base), None)
            if at is None:
                raise NetworkError(f"`{argument}`: say this, arg0 to arg3, return, or a global's name or D_<address> "
                                   "(and +0x14 to follow the pointer at 0x14)")
            key, what = (structs.GLOBAL, at), f"the global {self._struct_label(found)(at)}"
        label = self._struct_label(found)
        return "\n".join(layouts.guess_text(found, key, path, what, name, argument, label,
                                             "declare what holds in a header the project's sources include"))

    def _struct_brief(self, fp: ForkProject, cfg: dict, fn) -> list[str]:
        """get_function's lines on the function's pointer arguments' likely layouts (layouts.brief_lines)."""
        from .engine import layouts

        found = self._structs(fp, cfg)
        addr = found.symbols.get(self._meta(fn).get("symbol") or fn["name"]) if found else None
        try:
            return layouts.brief_lines(found, addr, fn["name"], self._struct_label(found)) if addr is not None else []
        except Exception:  # a heuristic: it never stands between an agent and the function
            logging.getLogger("decompdecomp").exception("guessing struct layouts failed")
            return []

    def claim(self, agent: Agent, slug: str, function: str | None = None, strategy: str = "easiest") -> str:
        if (link := self.net.links.get(slug)) is not None:
            return self._claim_in_room(link, agent, slug, function, strategy)
        still = self.net.still_holding(agent, function)
        fn, job = self.claim_work(agent, slug, function, strategy, still)
        if job is not None:
            return job
        if fn is not None and still:
            said = self._best_in_file(agent, slug, fn)
            return still + (said + "\n\n" if said else "") + self.brief(self._fn(slug, fn["name"]), agent, "CLAIMED")
        if fn is None:
            left = (self.get(slug)[2].get("uncovered") or {}).get("functions")
            return (self.net.nothing_to_claim(agent, self.net._project(slug), " with a source file")
                    + (f"\n{left} more functions are in code no source file covers yet. The user can give them files "
                       "(the project's overview in decompdecomp: Give them source files); then there's more to claim."
                       if left else ""))
        said = self._best_in_file(agent, slug, fn)
        return (said + "\n\n" if said else "") + self.brief(self._fn(slug, fn["name"]), agent, "CLAIMED")

    def _with_renames(self, slug: str, fn, text: str | None) -> str | None:
        """A function's stored C with the renames made since it was written (rename events after its last_improved).
        rename_symbol renamed in the files but left the stored best: the next claim put it back in its file
        (_best_in_file), and a GameCube function at 99.3% called SoundManager_CreateSource, renamed
        SoundManager_AllocSource hours before. CodeWarrior took the old name as an undeclared function, so it built
        and only its call's relocation was wrong. (Also C stored before this was fixed, and a room member's copy, whose
        renames arrive as the host's events.)"""
        if not text:
            return text
        proj, _, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        for r in self.net.store.all("SELECT detail FROM events WHERE project_id=? AND kind='rename' AND created_at > ? "
                                    "ORDER BY id", proj["id"], fn["last_improved"] or 0):
            old, _, new = (r["detail"] or "").partition(" → ")
            if _OLD_SYMBOL.fullmatch(old) and re.fullmatch(r"[A-Za-z_]\w*", new):  # (a thunk's name: no source has it)
                text = re.sub(console.rename_pattern(old), new, text)
        return text

    def _best_in_file(self, agent: Agent, slug: str, fn) -> str:
        """Put an open function's best attempt in its source file when the file holds another version: the permuter,
        a deep search and autopilot's drafts record a better attempt without writing it there, and on a GameCube game
        the file kept a 95.8% version under a 98.5% best, which two agents then worked from. "" once it's there (or
        nothing needs doing), else what stopped it, for the agent."""
        if fn["status"] != "open" or not fn["best_source"] or slug in self.net.links:
            return ""
        _, fp, _ = self.get(slug)
        meta, unit = self._meta(fn), fp.unit(fn["unit"])
        if not unit.source or not (fp.root / unit.source).is_file():
            return ""
        names = self._names(meta, fn)
        _, span = self._find(text := self._settled_text(slug, fp.root / unit.source), names)
        best = self._with_renames(slug, fn, fn["best_source"])
        _, best_span = self._find(best, names)
        best_code = best[best_span[0]:best_span[1]] if best_span else best
        if span and text[span[0]:span[1]].strip() == best_code.strip():
            return ""
        try:
            res = self.attempt(agent, slug, fn["name"], best)
        except NetworkError as e:
            res = {"text": str(e)}
        if res.get("matched") or (res.get("score") is not None and res["score"] <= (fn["best_score"] or 0)):
            return ""
        why = (res.get("text") or "").strip().splitlines()[0][:300] if res.get("text") else "it didn't build"
        return (f"⚠️ The best attempt (score {fn['best_score']}) isn't what {unit.source} holds, and putting it there "
                f"didn't work: {why}. The file's version is another one: start from the best attempt below.")

    def claim_work(self, agent: Agent, slug: str, function: str | None, strategy: str,
                   still: str | None = None) -> tuple[dict | None, str | None]:
        """(the function claimed, None) or (None, a data job's brief): an agent's claim here, or a room member's
        agent's on the host (/collab/claim). A file whose every function matches and whose data doesn't is the
        closest to linked of all: under the "finish" order (forks' default) it comes first, else once there's no
        function left. Not for a helper the user gave a work selection (functions by size, by score...)."""
        jobs = not function and not self.net.selection(slug, agent.name)
        if jobs and (self.data_jobs.held(agent, slug) or (strategy == "finish" and not still)):
            if (job := self.data_jobs.claim(agent, slug)) is not None:
                return None, job
        fn = self.net.claim_row(agent, slug, function, strategy)
        if fn is None and jobs and (job := self.data_jobs.claim(agent, slug)) is not None:
            return None, job
        return fn, None

    def _claim_in_room(self, link, agent: Agent, slug: str, function: str | None, strategy: str) -> str:
        """A member of a room: the host hands out functions (nobody does one twice); the brief comes from this copy."""
        name, why = link.claim(agent, self._fn(slug, function)["name"] if function else None, strategy,
                               self.net.selection(slug, agent.name))
        if name is None:  # (the host's word: a data job's brief, or what's left and why, as its own agents hear it)
            return why or "Nothing left to claim in this room: every function with a source file matches or someone is on it. 🎉"
        try:
            fn = self.net.claim_row(agent, slug, name, strategy)
        except NetworkError:  # the host has a newer tree (new files, a split): follow it, then claim here
            link.sync()
            self._open_as_the_host_has_it(slug, name)
            fn = self.net.claim_row(agent, slug, name, strategy)
        return self.brief(fn, agent, "CLAIMED")

    def _open_as_the_host_has_it(self, slug: str, name: str) -> None:
        """A function the host handed out is open: the room's statuses are the host's. A member's copy that still had
        it matched (the host measured it again and reopened it) refused the claim with "already matched", while the
        host held it for the agent: a member's agents got only such functions, claim after claim."""
        try:
            fn = self._fn(slug, name)
        except NetworkError:
            return
        if fn["status"] == "matched":
            with self.net.store.tx() as db:
                db.execute("UPDATE functions SET status='open' WHERE id=?", (fn["id"],))

    def get_function(self, agent: Agent | None, slug: str, function: str) -> str:
        return self.brief(self._fn(slug, function), agent, "VIEW")

    def asm_part(self, fn, part: int) -> str:
        """get_function's later parts of a long function's assembly (network.asm_page)."""
        proj = self.net.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        _, fp, _ = self.get(proj["slug"])
        d = fp.diff(fp.unit(fn["unit"]), self._meta(fn).get("symbol") or fn["name"])
        shown, said = asm_page(d.target_asm().splitlines(), part, fn["name"])
        return "\n".join([f"## {fn['name']}: {said or 'its whole assembly'}", "```asm", *shown, "```"])

    def list_functions(self, slug: str, status: str = "open", limit: int = 40) -> str:
        proj, _, _ = self.get(slug)
        where = {"open": "status='open'", "matched": "status='matched'", "all": "1"}.get(status)
        if where is None:
            raise NetworkError("status must be open, matched or all")
        rows = self.net.store.all(f"SELECT name, unit, n_insns, status, best_score FROM functions WHERE project_id=? "
                                  f"AND {where} ORDER BY n_insns LIMIT ?", proj["id"], max(1, min(int(limit), 200)))
        out = [f"{r['name']:<40} {r['unit']:<36} {r['n_insns']:>5} insns  "
               f"{'matched' if r['status'] == 'matched' else 'best ' + str(r['best_score']) if r['best_score'] is not None else 'new'}"
               for r in rows]
        return "\n".join(out) or "none"

    def attempt(self, agent: Agent, slug: str, function: str, source: str, keep: bool = True, prelude: str = "",
                quiet: int | None = None, comment: bool = False, background: bool = False) -> dict:
        """`keep`: whether a version that doesn't match stays in the source file (an agent's work in progress) or
        is undone and kept only as the function's best attempt (autopilot's drafts). `prelude`: (decompdecomp's own
        tries) type definitions the code needs, placed after the file's includes. `quiet`: (the permuter's
        variants) recorded only when better than this score. A try that isn't kept holds the function only while
        it builds (twins' tries come unclaimed: a 30-minute claim each kept agents off them, then counted as given up).
        `comment`: (polishing) the comment right above the definition goes into the file, in place of the file's.
        `background`: (a deep search the user started on one function) a try beside whoever holds the function: no
        claim taken or refused. Never kept, never in a room: the file is put back as it was under the unit's lock, the
        agent's work in progress in it too, and only a better score is recorded."""
        if background and (keep or slug in self.net.links):
            raise NetworkError("a try beside an agent's claim is never kept in the file, and not made in a room")
        if keep:  # (an agent's own work: its work selection's max tries)
            self.net.check_tries(agent, self._fn(slug, function))
        held = None if keep or background else self._hold_for_try(slug, function, agent)
        link = self.net.links.get(slug)
        before = self._fn(slug, function)["best_score"] if link is not None else None
        try:
            res = self._attempt(agent, slug, function, source, keep, prelude, quiet, comment, background)
        finally:
            if held is not None:
                with self.net.store.tx() as db:
                    db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (held, agent.id))
        if link is None or res["score"] is None:
            return res
        name = self._fn(slug, function)["name"]
        if res["matched"]:  # the host builds it in its own tree, against its own copy, and commits it for everyone
            try:  # (with the declarations autopilot's draft needs: without them the host's build failed it)
                verdict = link.attempt(agent, name, source, prelude=prelude)
            except Refused as e:
                res["text"] += f"\n⚠️ The room's host didn't take this match: {e}"
                return res
            except NetworkError as e:
                link.keep_for_later(name, prelude + source if prelude else source)
                res["text"] += (f"\n⚠️ Not shared with the room yet ({e}): it is sent again when the host is back. "
                                "Carry on with another function.")
                return res
            if verdict.get("matched"):
                res["text"] += "\nShared with the room: the host confirmed the match."
                threading.Thread(target=self._follow, args=(link,), daemon=True).start()
            else:
                res["text"] += ("\n⚠️ The room's host could not confirm this match in its tree (score "
                                f"{verdict.get('score')}): it may have changed since; this copy follows the host's.")
        else:
            # (better than before this try: every variant that tied the best was sent, a deep search's by the hundred)
            if before is None or res["score"] < before:
                threading.Thread(target=self._report_best, args=(link, agent, name, source, res["score"]), daemon=True).start()
        return res

    def _hold_for_try(self, slug: str, function: str, agent: Agent) -> int | None:
        """Claim an open function nobody holds for one quick try; its id, or None (held already, or matched)."""
        fn = self._fn(slug, function)
        now = time.time()
        with self.net.store.tx() as db:
            self.net._expire_claims(db)
            # its status read again inside the claim's transaction: one read before it let a try claim a function a
            # helper matched meanwhile
            now_status = db.execute("SELECT status FROM functions WHERE id=?", (fn["id"],)).fetchone()
            if now_status is None or now_status["status"] != "open" or db.execute(
                    "SELECT 1 FROM claims WHERE function_id=?", (fn["id"],)).fetchone():
                return None
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + 300))
        return fn["id"]

    @staticmethod
    def _follow(link) -> None:
        try:
            link.sync()
        except NetworkError:
            pass

    @staticmethod
    def _report_best(link, agent: Agent, name: str, source: str, score: int) -> None:
        try:
            link.call("/collab/best", agent, function=name, source=source, score=score)
        except NetworkError:
            pass

    def _place(self, proj, fp: ForkProject, unit, fn, source: str, names: list[str], comment: bool = False,
               prelude: str = "") -> tuple[str, str, Path, str]:
        """`source`'s definition written into its unit's source file as it is now: (the code, the file after,
        the file, the file before)."""
        _, span = self._find(source, names)
        if span is None:
            raise NetworkError(f"send the complete definition of {names[0]} (with its body)")
        # with the comment right above it (what it does, from polishing): the file kept the definition only
        # Polishing's only: a twin's note or a decompiling agent's scratch comment replaced a forked decomp's own
        # doc comments, and piled up in its files
        if comment:
            span = (csource.comment_above(source, span[0]), span[1])
        code = source[span[0]:span[1]]
        commented = code.lstrip().startswith(("//", "/*"))
        if not unit.source:
            raise NetworkError(f"unit {unit.name} has no source file, so there's nowhere to write it")
        path = fp.safe_path(unit.source, write=True)
        try:
            before = path.read_text(errors="replace", encoding="utf-8")
        except OSError:
            before = ""
        includes, before_lines, after_lines = _around(source, span, before, unit.source)
        hit, old_span = self._find(before, names)
        base, carried = before, ""  # what the new definition goes into; what of the parked copy goes with it
        parked = self._hidden(fp, before, old_span[0]) if old_span else None
        if parked and (seen := self._seen_beside(fp, before, old_span, hit, names)):
            # a draft parked in `#ifdef` before the build's own definition in its `#else`: the one the build sees
            # is the one tried (the parked one taken out, a new one put in, the visible one stayed: defined twice)
            old_span, parked = seen, None
        if parked:
            # parked in an #if branch the build leaves out: written there, the compile was judged on other code,
            # and moved out with edit_file it was refused when it broke a matched neighbour (where whole-program
            # optimisation couples them), so an agent could do nothing with it. It goes where the build sees it,
            # without the parked copy: kept, the function is visible from then on; else the file is undone. Its
            # annotation (`// FUNCTION: 0x...`, often with the notes of earlier tries) comes along, and its
            # comment too unless the agent sent one
            lo = csource.comment_above(before, old_span[0])
            mark = csource.marker_above(before, lo)
            carried = before[mark:lo] + ("" if commented else before[lo:old_span[0]])
            base, old_span = before[:mark] + before[old_span[1]:], None
        pre, post = "".join(ln + "\n" for ln in before_lines), "".join(ln + "\n" for ln in after_lines)
        if old_span:
            lo, hi = old_span
            kept = ""  # the file's comment, when none was sent
            if commented:  # a new comment replaces the old one; without one, the file's stays
                lo = csource.comment_above(before, lo)
            if any(_PRAGMA.match(ln) for ln in before_lines + after_lines):  # a new wrapper replaces the old one
                above = csource.comment_above(before, lo)
                wrapped, hi = _pragmas_around(before, lo, hi)
                if not commented and wrapped < above:
                    kept = before[above:lo]
                lo = wrapped
            after = before[:lo] + pre + kept + code.rstrip("\n") + "\n" + post + before[hi:]
        else:
            placed = pre + carried + code.rstrip("\n") + "\n" + post
            after = self._insert_in_order(proj, fp, unit, fn, base, placed)
            if base is not before and (span := self._find(after, names)[1]) and self._hidden(fp, after, span[0]):
                after = base.rstrip("\n") + "\n\n" + placed  # (its neighbours are parked too: after them all)
        after = _with_includes(after, includes, prelude)
        return code, after, path, before

    def _trial_diff(self, fp: ForkProject, console, unit, symbol: str, text: str, path: Path,
                    protected: set[str]) -> objdiff.FunctionDiff | None:
        """A try that won't be kept, compiled alone: the unit's own compile command (ForkProject.compile_command) run
        on a copy of the file in a folder of its own (Console.trial_command), and measured as fp.diff measures the
        unit. A GameCube game's permuter, search_flags and drafts wrote each try into the file, built it with ninja,
        then wrote the file back and built it again: two runs of the build, and the project's file rewritten, for
        a verdict the compiler alone gives.

        Only a try whose verdict is "not kept" is answered here; None, and the try is written and built as before,
        for whatever else: no command to read (another build, build.ninja about to be written again), a copy that
        doesn't build (the build's own error is what the agent reads), a diff that fails, a match (committed from
        the project's own build) and a neighbour it breaks. tests/test_gc.py checks both ways give the same verdict."""
        if unit.mappings or unit.target is None or (command := fp.compile_command(unit)) is None:
            return None
        with tempfile.TemporaryDirectory(prefix="decomp-try-") as tmp:
            copy = Path(tmp) / path.name
            trial = console.trial_command(command, copy, path.parent, Path(tmp))
            if trial is None:
                return None
            _rewrite(copy, text)
            ok, _ = fp.run(trial[0], log=lambda *_: None, timeout=UNIT_SECONDS)
            if not ok or not trial[1].is_file():
                return None
            try:
                d = fp.diff(unit, symbol, base=trial[1])
            except (ObjdiffError, ForkError):
                return None
        if d.matched or any((d.unit_scores.get(n) or 0) < 100 for n in protected):
            return None
        return d

    def _attempt(self, agent: Agent, slug: str, function: str, source: str, keep: bool = True, prelude: str = "",
                 quiet: int | None = None, comment: bool = False, background: bool = False) -> dict:
        proj, fp, cfg = self.get(slug)
        fn = self._fn(slug, function)
        meta = self._meta(fn)
        if len(source) > 64 * 1024:
            raise NetworkError("source too large")
        if _CHEAT.search(_strip_comments(source)):
            raise NetworkError("inline assembly, asm functions and asm includes aren't allowed: a match has to come from C/C++")
        names = self._names(meta, fn)
        _, span = self._find(source, names)
        console = consoles.get(cfg.get("platform"))
        version = (fp.manifest or {}).get("version") or cfg.get("version")
        structor = None
        if span is None and console.names_structors and not meta.get("demangled") and "::" in (meta.get("real") or "::"):
            # a constructor or destructor of a class the agent named (CFoo::~CFoo for func_004A86D0) becomes the
            # function's real name below, which the build pairs with the original: a class's constructor and
            # destructor are at two addresses, and can't both be named after the class. One named so before (a
            # real name with "::") may be renamed: the agent's class has another name now
            if (structor := csource.structor(source)) is not None:
                given = console.real_names(fp, version).get(meta.get("symbol") or fn["name"])
                names = [structor, *names, *([given] if given else [])]
                _, span = self._find(source, names)
        if span is None:
            raise NetworkError(f"send the complete definition of {names[0]} (with its body)")
        unit = fp.unit(fn["unit"])
        if not unit.source:
            raise NetworkError(f"unit {unit.name} has no source file, so there's nowhere to write it")
        symbol = meta.get("symbol") or fn["name"]
        linked = unit.complete and fp.linkable()  # the game is built from this file: changes must keep it identical
        with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), self._unit_lock(proj, unit.name):
            code, after, path, before = self._place(proj, fp, unit, fn, source, names, comment, prelude)
            with self.net.store.tx() as db:  # claim bookkeeping, as for ROM projects (none for a try in the background)
                self.net._expire_claims(db)
                claim = None if background else db.execute("SELECT agent_id FROM claims WHERE function_id=?",
                                                           (fn["id"],)).fetchone()
                if claim is not None and claim["agent_id"] != agent.id:
                    raise NetworkError(f"{fn['name']} is claimed by {self.net._agent_name(claim['agent_id'])}")
                now = time.time()
                if claim is None and fn["status"] != "matched" and not background:
                    db.execute("INSERT INTO claims VALUES(?,?,?,?)",
                               (fn["id"], agent.id, now, now + self.net.claim_ttl))
                elif claim is not None:
                    db.execute("UPDATE claims SET expires_at=? WHERE function_id=?",
                               (now + self.net.claim_ttl, fn["id"]))
            # What matches in the file as it is now is what this change must keep (not the database's idea of it,
            # which a change outside decompdecomp or a different measurement can leave behind)
            if unit.name not in self._trying_units():
                self._put_back_own_entry(proj, fp, unit)
            scores, builds = self._baseline(proj, fp, unit, before)
            held = self._held(proj, unit.name, before)
            if scores is not None:
                self._apply_scores(proj, unit.name, scores, text=before, via="unit diff before a compile")
                protected = {n for n, pct in scores.items()
                             if n != symbol and n not in held and pct is not None and pct >= 100}
                was_matched = (scores.get(symbol) or 0) >= 100 and symbol not in held
            else:
                protected = {n for n, pct in (self._last_scores(proj, unit) or {}).items()
                             if n != symbol and n not in held and pct is not None and pct >= 100}
                was_matched = fn["status"] == "matched"
            # the same file as an earlier compile of this function made, nothing it depends on changed since: that
            # compile's result, not another build
            agents_try = keep and quiet is None and not was_matched
            # (an LTCG project's driver and stand-ins are part of what the unit builds with: harness/<unit>.*.cpp)
            harness = "".join(p.read_text(errors="replace", encoding="utf-8")
                              for p in sorted((fp.root / "harness").glob(f"{unit.name}.*.cpp")))
            key = self.net.compile_key(fn, unit.name, after, harness)
            if agents_try and (again := self.net.repeat_of(key, agent, fn)) is not None:
                return again
            renamed: dict[Path, str] = {}
            if structor:
                try:
                    with self._build_lock(proj):  # builds read the config
                        renamed = console.rename_symbol(fp, version, fn["name"], structor)
                except ForkError as e:
                    raise NetworkError(f"{structor} can't be {fn['name']}'s name: {e}") from None

            def unname() -> None:
                """The config as it was: a name left behind would keep another function from being that class's
                constructor (an agent's wrong address). Nothing renamed (nearly every try): no wait for the build
                lock, which a run of the project's builds holds; each of the permuter's tries waited for the next
                run here, writing nothing."""
                if not renamed:
                    return
                with self._build_lock(proj):
                    for p, t in renamed.items():
                        p.write_text(t, encoding="utf-8")

            committed = [unit.source, *(p.relative_to(fp.root).as_posix() for p in renamed)]
            # a try that isn't kept, compiled alone where it can be (_trial_diff); the rest is written to the file and
            # built, as a try that ends kept or matching or breaking a neighbour still is
            d = self._trial_diff(fp, console, unit, symbol, after, path, protected) \
                if not keep and not was_matched and not linked and not renamed else None
            written = d is None
            if written:
                _rewrite(path, after)

            def remembered(text: str, score: int | None, kept: bool = True) -> str:
                """A result as repeat_of gives it back later (agents' tries only), plus the note when this variant
                only reproduces an earlier score of the claim."""
                if not agents_try:
                    return text
                if kept:
                    self.net.remember_compile(key, agent, fn, text, score)
                return (text + self.net.same_score_note(fn["id"], agent.id, score, code)
                        + self.net.judged_at_best_note(fn["id"], score, code))

            def undo() -> None:
                if not written:  # (compiled alone: the file and its object are as they were)
                    return
                _rewrite(path, before)
                unname()
                if (proj["id"], unit.name) in self._trials and scores is not None and not renamed:
                    self._trials[(proj["id"], unit.name)] = True  # (a run of tries: built once, at its end)
                    return
                if self._build_unit(proj, fp, unit)[0] and scores is not None:
                    self._keep_scores(proj, unit, before, scores)

            ok, log = self._build_unit(proj, fp, unit) if written else (True, "")
            if not ok and (broken := fp.build_problem()) is not None:
                # the build itself is broken, not the agent's code: nothing recorded or counted, and the project
                # is set up again in the background (one project spent five compiles on a build.ninja whose python
                # was in another home, then the sessions quit)
                _rewrite(path, before)
                unname()
                threading.Thread(target=self.preflight, args=(slug,), daemon=True, name=f"preflight-{slug}").start()
                return {"text": f"❌ The project's build is broken, not your code: {broken}. Your change was undone, "
                                "and nothing was recorded or counted. decompdecomp is setting the project up again; "
                                "don't compile until it's fixed: end your session here.", "score": None,
                        "matched": False}
            if not ok:
                undo()
                if quiet is None:
                    self.net._record(fn, agent, None, code, 0)
                why = "" if builds else ("\n(The file didn't build before your change either, so the error may be in "
                                         "other code of the file: fix that with edit_file.)")
                stall = self.net.stall_note(fn["id"], agent.id) if quiet is None else ""  # (it counted too)
                return {"text": f"❌ BUILD ERROR (your change was undone){why}\n{log[-3000:]}{stall}", "score": None,
                        "matched": False}
            try:
                d = fp.diff(unit, symbol) if written else d
            except (ObjdiffError, ForkError) as e:
                undo()
                return {"text": f"❌ objdiff couldn't compare (your change was undone): {e}", "score": None, "matched": False}
            if quiet is None:
                d.rows = with_constant_values(d.rows, consoles.get(cfg.get("platform")), fp)
                self.net.keep_diff(agent.id, fn["id"], d.rows, objdiff.LEGEND)
            broken = sorted(n for n in protected if n and (d.unit_scores.get(n) or 0) < 100)
            if broken:
                undo()
                # the function's own result still counts: where whole-program optimisation (or inlining) makes a
                # function's code change how its neighbours compile, a draft short of exact breaks them, and without
                # its score an x86 game's agents parked drafts behind #if flags and rebuilt by hand to measure them
                own = None
                if d.match_percent is not None:
                    own = max(1, len(d.literals)) if d.literals else scaled(d.match_percent, fn["n_insns"])
                if quiet is None:  # an attempt, never the best: release puts the best back in the file
                    self.net._record(fn, agent, own, code, 0, compiled=True, best=False, mismatch_rows=d.rows)
                listed = ", ".join(broken[:8])
                if own is None:
                    text = (f"❌ REJECTED and undone: your change breaks matched function(s) {listed}. Check you "
                            "replaced the right definition (overloads?) and didn't change shared code.")
                elif d.matched:
                    text = (f"❌ REJECTED and undone: your change breaks matched function(s) {listed}, though "
                            f"{fn['name']} itself matches. What changed them is how it's declared or what else you "
                            "sent (its calling convention, static or inline, a shared declaration): check you "
                            "replaced the right definition (overloads?).")
                else:
                    text = (f"❌ REJECTED and undone: your change breaks matched function(s) {listed}. {fn['name']} "
                            f"itself came out at {percent_text(d.match_percent)} (score {own}): recorded as an "
                            f"attempt, not kept in {unit.source}. If they changed only because of how {fn['name']} "
                            "compiles into them (inlined, or whole-program optimisation choosing registers across "
                            f"functions), they match again once {fn['name']} matches exactly: work from the diff "
                            "below. Otherwise check you replaced the right definition (overloads?) and didn't change "
                            f"shared code.\n{d.render()}")
                stall = self.net.stall_note(fn["id"], agent.id) if quiet is None else ""
                return {"text": remembered(text, own) + stall, "score": None, "held_score": own, "matched": False,
                        "broken": broken, "alone": bool(d.matched)}
            if linked and d.matched and not (ok := self._verify(proj, fp))[0]:
                undo()
                if quiet is None:
                    self.net._record(fn, agent, None, code, 0, compiled=True)
                stall = self.net.stall_note(fn["id"], agent.id) if quiet is None else ""
                return {"text": f"❌ REJECTED and undone: {unit.source} is linked into the game, and with your change "
                                f"the game no longer builds byte for byte:\n{_tail(ok[1])}{stall}", "score": None,
                        "matched": False}
            pct = d.match_percent if d.match_percent is not None else 0.0
            score = max(1, len(d.literals)) if d.literals else scaled(pct, fn["n_insns"])
            matched = d.matched
            if not matched and not keep and not was_matched:  # tried, not kept: the file stays as it was
                undo()
                if quiet is None or score < quiet:
                    self.net._record(fn, agent, score, code, 0, compiled=True, mismatch_rows=d.rows)
                return {"text": f"{percent_text(pct)} match (score {score}); not kept in {unit.source}", "score": score,
                        "matched": False, "percent": pct}
            best = fn["best_score"]
            if (not matched and not was_matched and d.match_percent is not None and best is not None
                    and fn["best_source"] and score > best):
                # worse than the best so far: the file keeps what it had, so it never ends on a worse variant than
                # the one the notes and the brief call the best (an agent found its 91.8% try there, not its 92.3%)
                undo()
                if quiet is None:
                    self.net._record(fn, agent, score, code, 0, compiled=True, mismatch_rows=d.rows)
                stall = self.net.stall_note(fn["id"], agent.id)
                text = remembered(f"{percent_text(pct)} match (score {score}), worse than the best so far (score "
                                  f"{best}), so {unit.source} keeps what it had; your attempt is recorded.\n"
                                  f"{d.render()}" + "\n".join(_observed(cfg, d)), score)
                return {"text": text + stall, "score": score, "matched": False, "percent": pct}
            self._keep_scores(proj, unit, after, d.unit_scores)
            self._hold(fn, code if d.literals else None)
            if was_matched:  # a rewrite of a matched function must keep matching
                if quiet is None:  # a polishing helper's compiles count too (not as a match)
                    self.net._record(fn, agent, score, code, 0)
                if not matched:
                    undo()
                    why = f"isn't a match ({d.why_not()})" if d.literals else f"is {percent_text(pct)}"
                    return {"text": f"❌ {fn['name']} already matches; your version {why}, so the matching one was "
                                    "kept. Call claim_function for a function that still needs work.",
                            "score": score, "matched": False}
                self._commit_paths(proj, fp, committed, f"Tidy {meta.get('demangled') or symbol} (still matches)\n\n"
                                                        f"Edited by {agent.name} with decompdecomp.")
                return {"text": f"✅ {fn['name']} still matches; your tidier version is committed.{_renamed_note(d)}",
                        "score": 0, "matched": True}
            self.net._record(fn, agent, score, code, 0, matched=matched, mismatch_rows=d.rows)
            self._apply_scores(proj, fn["unit"], d.unit_scores, skip=fn["id"], agent=agent, text=after,
                               via=f"unit diff after a compile of {fn['name']}")
            self._remember(proj, fp, unit, d)
            if matched:
                self._commit_paths(proj, fp, committed, f"Match {meta.get('demangled') or symbol}\n\n"
                                                        f"Decompiled by {agent.name} with decompdecomp.")
                return {"text": f"✅ MATCH! {fn['name']} is 100% identical to the original. Committed to git in the "
                                f"project. Call claim_function for the next one.{_renamed_note(d)}"
                                f"{self.net.dependents_note(fn['id'])}"
                                f"{self._file_done(slug, proj, fp, unit, d.unit_scores, agent)}", "score": 0,
                        "matched": True}
        stall = self.net.stall_note(fn["id"], agent.id)
        found = self._unresolved_lines(fp, meta, fn, unit, code) + self._convention_warning(fp, meta, fn, unit)
        missing = ((self._missing_note(unit, fn) if d.match_percent is None else "")
                   + ("\n\n" + "\n".join(found) if found else ""))
        if d.literals:
            text = f"score {score} (0 = identical). {d.literals_note()}{missing}"
        else:
            observed = "\n".join(_observed(cfg, d))
            text = f"{percent_text(pct)} match (score {score}; 0 = identical).\n{d.render()}{observed}{missing}"
        return {"text": remembered(text, score) + stall, "score": score, "matched": False}

    def try_compiler(self, agent: Agent, slug: str, function: str, compiler: str, flags: str = "",
                     source: str = "") -> str:
        """A function's C built with another of its console's compilers, where the project lets each source file have
        its own (Console.file_compiler: a DS game mixes CodeWarrior versions, issue #23). Judged as an attempt that
        isn't kept: a version it matches with stays the file's, committed, and only when the file's other matched
        functions still match (the attempt's own rule); otherwise the file keeps its compiler and nothing is
        recorded. "all": the file's own compiler first (C that matches with it needs no switch), then the others,
        nearest versions first, until one matches or TRY_ALL_SECONDS pass (on the DS demo, C that matched with its
        own 2.0sp1p5 moved its file to 2.0/base when the own one was skipped and the oldest went first)."""
        if agent is not None and (link := self.net.links.get(slug)) is not None:
            # a member's tree follows the host's: the host tries it on its copy, keeps the compiler only where the
            # file's matches hold, and this copy follows (refused here, a GameCube room's SDK function whose prologue
            # wanted another CodeWarrior was left for good)
            text = link.call("/collab/try_compiler", agent, function=function, compiler=compiler, flags=flags,
                             source=source)
            if "from now on" in text:
                text += link.follow()
            return text
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        fn = self._fn(slug, function)
        unit = fp.unit(fn["unit"])
        own = console.file_compiler(fp, unit.source) if unit.source else None
        if own is None:
            raise NetworkError("a fork builds with its project's own compilers")
        # flags with the compiler, where each file has flags of its own too (PC): a 6.0 game's RSA MD5 was built /Od by
        # Visual C++ 4.2, and neither half matched alone (try_compiler refused flags, search_flags kept the compiler)
        own_flags = console.file_flags(fp, unit.source) if unit.source else None
        new_flags = flags.split()
        if new_flags and own_flags is None:
            raise NetworkError("this project's flags are its build's own: try_compiler changes only the file's compiler")
        if bad := [f for f in new_flags if not re.fullmatch(r"[/-][A-Za-z][\w+:-]*", f)]:
            raise NetworkError(f"{bad[0]!r} isn't a compiler switch (flags: switches such as /Od /Oy-, nothing else)")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} already matches with {own}")
        known = [c.id for c in console.project_compilers(fp)]  # (a 32-bit game's 32-bit ones, a 64-bit game's 64-bit)
        if compiler.strip().lower() == "all":
            wanted = sorted(known, key=lambda c: abs(known.index(c) - known.index(own))) if own in known else known
            # (the program's own word on what compiled it: "all" tries only those)
            wanted = [c for c in wanted if c == own or console.program_rules_out(fp, c) is None]
        else:
            wanted = [compiler.strip()]
        if wanted[0] not in known:
            raise NetworkError(f"{wanted[0]!r} isn't one of this project's compilers: {', '.join(known)}")
        if wanted[0] != own and (why := console.program_rules_out(fp, wanted[0])):
            raise NetworkError(f"{unit.source} stays with {own}: {why}")
        if wanted == [own] and not new_flags:
            raise NetworkError(f"{unit.source} is built with {own} already")
        source = source.strip() or self.net._source_of(fn) or ""
        if not source:
            raise NetworkError(f"{fn['name']} has no attempt yet: pass the C as source")
        linked = unit.complete and fp.linkable()
        tried, kept, changed = [], None, False
        flags_set = new_flags and new_flags != own_flags
        until = time.monotonic() + TRY_ALL_SECONDS
        held = self._hold_for_try(slug, function, agent)  # a function nobody holds is held only while it's tried
        try:
            with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), self._unit_lock(proj, unit.name):
                try:
                    # what matches with the file's own compiler, measured before it changes: what every try must keep
                    self._baseline(proj, fp, unit, (fp.root / unit.source).read_text(errors="replace", encoding="utf-8"))
                    if flags_set:
                        with self._build_lock(proj):
                            flags_rel = console.set_file_flags(fp, unit.source, new_flags)
                    for c in wanted:
                        if tried and time.monotonic() > until:
                            break
                        if c != own:
                            with self._build_lock(proj):  # (a build reads the map)
                                rel = console.set_file_compiler(fp, unit.source, c)
                            changed = True
                        with self._trying(unit.name):
                            res = self._attempt(agent, slug, function, source, keep=False, quiet=0)
                        if res["matched"] and c == own and not flags_set:
                            return f"{c}: {res['text']}\nThat's {unit.source}'s own compiler: nothing to switch."
                        if res["matched"]:
                            kept = c
                            self.net.bump_generation(proj["id"])  # (earlier compiles of the file aren't repeats)
                            if c != own:
                                self._commit_entry(proj, fp, rel, lambda c=c: console.set_file_compiler(fp, unit.source, c),
                                                   f"Build {unit.source} with {c}\n\n{fn['name']} matches with "
                                                   f"it (found by {agent.name} with decompdecomp).")
                            if flags_set:
                                self._commit_entry(proj, fp, flags_rel,
                                                   lambda: console.set_file_flags(fp, unit.source, new_flags),
                                                   f"Build {unit.source} with {' '.join(new_flags)}\n\n{fn['name']} "
                                                   f"matches with {c} and them (found by {agent.name} with "
                                                   "decompdecomp).")
                            self.net.filecompilers.tried(slug, unit.source, c)  # (the range checks around it)
                            shown = f"{c} {' '.join(new_flags)}" if flags_set else c
                            return f"{shown}: {res['text']}\n{unit.source} is built with {shown} from now on."
                        if res.get("broken"):  # the file's other functions need its own compiler
                            res["text"] = (f"the file's matched {', '.join(res['broken'][:8])} no longer match with it. "
                                           f"If {fn['name']} needs it, give it a file of its own first (split_file)")
                        tried.append(f"{c}: {res['text']}" if len(wanted) == 1 else f"{c}: {res['text'].split(chr(10))[0]}")
                finally:
                    if (changed or flags_set) and kept is None:
                        with self._build_lock(proj):
                            if changed:
                                console.set_file_compiler(fp, unit.source, own)
                            if flags_set:
                                console.set_file_flags(fp, unit.source, own_flags or [])
                        self._build_unit(proj, fp, unit)  # the file's object is its own compiler's again
        finally:
            if held is not None:
                with self.net.store.tx() as db:
                    db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (held, agent.id))
        if len(wanted) == 1:
            return f"{tried[0]}\n{unit.source} stays with {own}."
        left = wanted[len(tried):]
        return (f"No compiler matches {fn['name']}; {unit.source} stays with {own}.\n" + "\n".join(tried)
                + (f"\nNot tried yet (time ran out): {', '.join(left)}. Try them by name." if left else ""))

    def compare_compilers(self, slug: str, function: str, log=lambda line: None, check=lambda: None) -> dict:
        """A function's best C built with each of its console's compilers and, where its file has flags of its own
        (a PC game's), each flag variant: every result's score, ranked, for the user to see which compiler and flags
        come closest. Nothing is recorded; the file keeps its compiler and flags. Should one combination match, it
        stays the file's (committed, when the file's other matched functions still match, as try_compiler and
        search_flags keep one) and the comparison ends there."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        fn = self._fn(slug, function)
        unit = fp.unit(fn["unit"])
        own = console.file_compiler(fp, unit.source) if unit.source else None
        if own is None:
            raise NetworkError("this project builds with its own compilers: there's nothing to compare")
        if self.net.links.get(slug) is not None:
            raise NetworkError("in a room, the host's project decides each file's compiler: compare there")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} already matches")
        source = self.net._source_of(fn) or ""
        if not source:
            raise NetworkError(f"{fn['name']} has no attempt yet: compare once an agent or a draft has written its C")
        own_flags = console.file_flags(fp, unit.source)
        known = [c.id for c in console.compilers]
        order = sorted(known, key=lambda c: abs(known.index(c) - known.index(own))) if own in known else known
        # (the survey's few flag variants: a search_flags sweep is a hundred on PC, for each compiler)
        variants = console.survey_variants(own_flags) if own_flags is not None else [None]
        combos = [(c, f) for c in order for f in variants]
        agent, _ = self.net.local_agent("decompdecomp")
        rows, kept, until = [], None, time.monotonic() + COMPARE_SECONDS
        shown = lambda flags: "" if flags is None else " ".join(flags) or "(the project's flags only)"  # noqa: E731
        linked = unit.complete and fp.linkable()
        held = self._hold_for_try(slug, function, agent)
        try:
            with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), self._unit_lock(proj, unit.name):
                try:
                    self._baseline(proj, fp, unit, (fp.root / unit.source).read_text(errors="replace", encoding="utf-8"))
                    for k, (c, flags) in enumerate(combos, 1):
                        check()
                        if time.monotonic() > until:
                            log(f"time is up: {len(combos) - k + 1} combinations not tried")
                            break
                        with self._build_lock(proj):
                            rel = console.set_file_compiler(fp, unit.source, c)
                            if flags is not None:
                                console.set_file_flags(fp, unit.source, flags)
                        with self._trying(unit.name):
                            res = self._attempt(agent, slug, function, source, keep=False, quiet=0)
                        d = res.get("percent")
                        rows.append({"compiler": c, "flags": shown(flags), "score": res.get("score"), "percent": d,
                                     "exact": bool(res["matched"]), "own": c == own and flags == own_flags,
                                     "breaks": res.get("broken") or []})
                        log(f"{k}/{len(combos)} {c} {shown(flags)}: "
                            + ("MATCH" if res["matched"] else "doesn't build" if res.get("score") is None
                               else f"score {res['score']}"))
                        if res["matched"] and c == own and flags == own_flags:
                            kept = (c, flags)  # (its own: nothing to switch)
                            break
                        if res["matched"]:
                            kept = (c, flags)
                            self.net.bump_generation(proj["id"])

                            def again(c=c, flags=flags):
                                console.set_file_compiler(fp, unit.source, c)
                                if flags is not None:
                                    console.set_file_flags(fp, unit.source, flags)
                            self._commit_entry(proj, fp, rel, again,
                                               f"Build {unit.source} with {c} {shown(flags)}\n\n{fn['name']} matches "
                                               "with them (found by comparing its compilers in decompdecomp).")
                            break
                finally:
                    if kept is None:
                        with self._build_lock(proj):
                            console.set_file_compiler(fp, unit.source, own)
                            if own_flags is not None:
                                console.set_file_flags(fp, unit.source, own_flags)
                        self._build_unit(proj, fp, unit)  # the file's object is its own compiler's again
        finally:
            if held is not None:
                with self.net.store.tx() as db:
                    db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (held, agent.id))
        rows.sort(key=lambda r: (not r["exact"], r["score"] is None or bool(r["breaks"]), r["score"] or 0))
        return {"function": fn["name"], "file": unit.source, "own": f"{own} {shown(own_flags)}".strip(),
                "kept": f"{kept[0]} {shown(kept[1])}".strip() if kept else None, "rows": rows,
                "tried": len(rows), "of": len(combos)}

    def takes_file_flags(self, slug: str) -> bool:
        """Whether this project's build gives a source file flags of its own (Console.file_flags: games started from
        scratch)."""
        try:
            _, fp, cfg = self.get(slug)
        except (ForkError, NetworkError):
            return False
        return consoles.get(cfg.get("platform") or "").file_flags(fp, "x.c") is not None

    def search_flags(self, agent: Agent, slug: str, function: str, compiler: str = "", source: str = "",
                     flags: str = "", divided: bool = False, quick: bool = False) -> str:
        """search_flags where each source file has flags of its own (Console.file_flags: PC's and Xbox's, every
        Visual C++ flag that changes code, consoles/pc/clflags.py; V.Flash's GCC levels): the function's C built with
        each variant of its file's flags (Console.flag_variants: the agent's `flags`, else the console's sweep), judged
        as an attempt that isn't kept, until TRY_ALL_SECONDS pass. A variant it matches with stays the file's,
        committed, when the file's other matched functions still match (the attempt's own rule); otherwise the file
        keeps its flags and nothing is recorded.

        A variant it matches with that breaks other matched functions of the file: the file is likely two of the game's
        (a V.Flash game's held functions matched at -O3, then functions its C matched only at -O1, and agents forced
        registers for days). The file is divided around the function, between it and those (split_file's checks), and
        the search runs again on its part (`divided`).

        `quick`: only the flag survey's few variants (Console.survey_variants), as the background permuter tries them on
        a near miss: a PC sweep is a hundred builds, with the project's tree held."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        fn = self._fn(slug, function)
        unit = fp.unit(fn["unit"])
        own = console.file_flags(fp, unit.source) if unit.source else None
        if own is None:
            raise NetworkError("a fork builds with its project's own compilers and flags")
        if compiler.strip():
            raise NetworkError("search_flags tries the file's flags with its own compiler: try_compiler tries others")
        if self.net.links.get(slug) is not None:
            raise NetworkError("in a room, the host's project decides each file's flags: search_flags works there")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} already matches with {unit.source}'s flags")
        variants = console.survey_variants(own) if quick and not flags.strip() else \
            console.flag_variants(own, fp, unit.source, flags)  # (named ones checked before anything builds)
        if flags.strip() and len(variants) == 1:
            raise NetworkError(f"{unit.source} is built with {flags.strip()} already")
        source = source.strip() or self.net._source_of(fn) or ""
        if not source:
            raise NetworkError(f"{fn['name']} has no attempt yet: pass the C as source")
        shown = lambda flags: " ".join(flags) or "(the project's flags only)"  # noqa: E731
        linked = unit.complete and fp.linkable()
        results, kept, changed, apart, done = [], None, False, None, 0
        until = time.monotonic() + TRY_ALL_SECONDS
        held = self._hold_for_try(slug, function, agent)
        try:
            with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), self._unit_lock(proj, unit.name):
                try:
                    self._baseline(proj, fp, unit, (fp.root / unit.source).read_text(errors="replace", encoding="utf-8"))
                    for variant in variants:
                        if done and time.monotonic() > until:
                            break
                        done += 1
                        if variant != own:
                            with self._build_lock(proj):  # (a build reads the flags)
                                rel = console.set_file_flags(fp, unit.source, variant)
                            changed = True
                        with self._trying(unit.name):  # (its trial flags aren't a leftover to put back)
                            res = self._attempt(agent, slug, function, source, keep=False, quiet=0)
                        if res["matched"] and variant == own:
                            return f"{res['text']}\nThat's with {unit.source}'s own flags: nothing to change."
                        if res["matched"]:
                            kept = variant
                            self.net.bump_generation(proj["id"])  # (earlier compiles of the file aren't repeats)
                            self._commit_entry(proj, fp, rel,
                                               lambda variant=variant: console.set_file_flags(fp, unit.source, variant),
                                               f"Build {unit.source} with {shown(variant)}\n\n{fn['name']} "
                                               f"matches with them (found by {agent.name} with decompdecomp).")
                            return f"{shown(variant)}: {res['text']}\n{unit.source} is built with them from now on."
                        if res.get("broken") and res.get("alone") and apart is None:
                            apart = (variant, res["broken"])
                        why = "breaks the file's matched functions" if res.get("broken") else \
                            "doesn't build" if res["score"] is None else f"score {res['score']}"
                        results.append((res["score"] if res["score"] is not None and not res.get("broken") else None,
                                        variant, why))
                    # none matches, but one is far closer than the file's own and breaks nothing: a V.Flash game's
                    # file was -O0 code built at -O3, the agent's C scored 282 at -O0 and 4064 at -O3, and the file
                    # kept -O3 because nothing matched yet: agents could only say "needs -O0" in a note
                    if (near := _far_closer(results, own)) is not None:
                        ours = next(r[0] for r in results if r[1] == own)
                        with self._build_lock(proj):
                            rel = console.set_file_flags(fp, unit.source, near[1])
                        kept = near[1]
                        self._build_unit(proj, fp, unit)
                        self.net.bump_generation(proj["id"])
                        self._commit_entry(proj, fp, rel, lambda: console.set_file_flags(fp, unit.source, kept),
                                           f"Build {unit.source} with {shown(kept)}\n\n{fn['name']}'s C "
                                                    f"comes {ours / max(near[0], 1):.0f} times closer with them (score "
                                                    f"{near[0]}, {ours} with {shown(own)}; found by {agent.name} with "
                                                    f"decompdecomp).")
                finally:
                    if changed and kept is None:
                        with self._build_lock(proj):
                            console.set_file_flags(fp, unit.source, own)
                        self._build_unit(proj, fp, unit)  # the file's object is its own flags' again
        finally:
            if held is not None:
                with self.net.store.tx() as db:
                    db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (held, agent.id))
        if apart is not None and not divided and console.splits_sources:
            said = self._divide_for_flags(agent, slug, fn, unit, apart[1])
            if said.startswith("✅"):
                return f"{shown(apart[0])} matches {fn['name']} but not {', '.join(apart[1][:4])}: {said}\n" + \
                    self.search_flags(agent, slug, function, source=source, flags=flags, divided=True,
                                      quick=quick)
            results.append((None, apart[0], "matches, but breaks matched functions; " + said))
        results.sort(key=lambda r: (r[0] is None, r[0] or 0))
        lines = [f"- {why:>8}  {shown(variant)}" + ("   <- the file's flags" if variant == own else "")
                 for _, variant, why in results]
        best = results[0] if results else None
        verdict = ("Your C builds with none of them: make it build first (compile_and_diff says why)."
                   if all(r[0] is None for r in results) else
                   "The flags aren't the problem: the file's are as good as any." if best and best[1] == own else
                   "Other flags come closer, but none matches: look at the C again first.")
        if kept is not None:
            verdict = (f"{unit.source} is built with {shown(kept)} from now on: no match broke, and your C comes far "
                       f"closer with them. Work on it with these flags (search_flags again puts others back if a "
                       f"later C says so).")
        # what wasn't tried, as what each adds to the file's flags: the agent names them (flags="...")
        left = [" ".join(f for f in v if f not in own) or f"without {' '.join(f for f in own if f not in v)}"
                for v in variants[done:]]
        return (f"{len(results)} flag variants for {fn['name']} in {unit.source} (lower is better), none matches:\n"
                + "\n".join(lines) + "\n" + verdict
                + (f"\nNot tried yet (time ran out): {', '.join(left)}. Name the ones worth trying: "
                   f"search_flags(function, flags=\"...\")." if left else ""))

    def file_flags_of(self, slug: str, source: str) -> list[str] | None:
        _, fp, cfg = self.get(slug)
        return consoles.get(cfg.get("platform")).file_flags(fp, source)

    def survey_file(self, slug: str, source: str, divided: bool = False) -> str | None:
        """The flag survey of one source file (app/flagsurvey.py): the file as it is, built with each of the variants
        Console.survey_variants gives of its flags. The variant most of its open functions match with becomes the
        file's when every function that matched still does (search_flags' rule, with no agent's C needed: one of a
        V.Flash game's files had four functions that matched at -O1 as they were, while agents forced registers at
        -O3); when it breaks matched ones, the file is divided around the first of those it makes match
        (_divide_for_flags), and its part surveyed again. Returns what changed, as a sentence (None: nothing)."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        own = console.file_flags(fp, source)
        units = fp.units_for(source)
        if own is None or not units or slug in self.net.links:
            return None
        rows = {self._meta(r).get("symbol") or r["name"]: r for u in units for r in self.net.store.all(
            "SELECT id, name, status, unit, meta FROM functions WHERE project_id=? AND unit=?", proj["id"], u.name)}
        if not any(r["status"] == "open" for r in rows.values()):
            return None
        try:
            text = (fp.root / source).read_text(errors="replace", encoding="utf-8")
        except OSError:
            return None
        linked = any(u.complete for u in units) and fp.linkable()
        best: tuple[list[str], list[str], list[str]] | None = None  # (flags, functions it matches, matches it breaks)
        nearer: tuple[list[str], float, dict] | None = None  # (flags, how much closer its open functions came, scores)
        with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), \
                self._units_locked(proj, [u.name for u in units]):
            def measure() -> dict[str, dict]:
                """{unit: {function: match %}} as the file builds now (not _baseline's: its scores don't know the
                file's flags changed), only the units that built."""
                out = {}
                for u in units:
                    if self._build_unit(proj, fp, u)[0]:
                        try:
                            out[u.name] = fp.diff(u, None).unit_scores
                        except (ObjdiffError, ForkError):
                            pass
                return out

            measured = measure()
            before = {n: pct for scores in measured.values() for n, pct in scores.items()}
            if len(measured) < len(units):  # (it doesn't build as it is)
                return None
            changed = False
            try:
                for flags in console.survey_variants(own)[1:]:
                    with self._build_lock(proj):
                        console.set_file_flags(fp, source, flags)
                    changed = True
                    after = {n: pct for scores in measure().values() for n, pct in scores.items()}
                    gained = [n for n, r in rows.items() if r["status"] == "open" and (before.get(n) or 0) < 100
                              and (after.get(n) or 0) >= 100]
                    lost = [n for n, pct in before.items() if (pct or 0) >= 100 and (after.get(n) or 0) < 100]
                    if gained and (best is None or (len(gained), -len(lost)) > (len(best[1]), -len(best[2]))):
                        best = (flags, gained, lost)
                    elif not lost and (gain := _closer(rows, before, after)) and (
                            nearer is None or gain > nearer[1]):
                        nearer = (flags, gain, after)
            finally:
                if changed:
                    with self._build_lock(proj):
                        console.set_file_flags(fp, source, own)
                    for u in units:
                        self._build_unit(proj, fp, u)  # the file's objects are its own flags' again
            if (best is None or best[2]) and nearer is not None:  # none matches yet, all of them come closer
                best = (nearer[0], [], [])
            if best is not None and not best[2]:
                flags, gained, _ = best
                with self._build_lock(proj):
                    rel = console.set_file_flags(fp, source, flags)
                after = measure()
                now = {n: pct for scores in after.values() for n, pct in scores.items()}
                if len(after) < len(units) or any((pct or 0) >= 100 and (now.get(n) or 0) < 100
                                                  for n, pct in before.items()):  # (measured otherwise this time)
                    with self._build_lock(proj):
                        console.set_file_flags(fp, source, own)
                    for u in units:
                        self._build_unit(proj, fp, u)
                    return None
                shown = " ".join(flags) or "the project's flags only"
                if gained:
                    said = (f"{source} is built with {shown}: {len(gained)} of its functions match with them as they "
                            f"are ({', '.join(rows[n]['name'] for n in gained[:6])}), and every match holds")
                else:
                    said = (f"{source} is built with {shown}: its open functions come closer with them (on average "
                            f"{nearer[1]:.0f} points), and every match holds")
                self._commit_entry(proj, fp, rel, lambda: console.set_file_flags(fp, source, flags),
                                   f"Build {source} with {shown}\n\n{said} (decompdecomp's flag survey).")
                self.net.bump_generation(proj["id"])  # (the file's flags: earlier compiles aren't repeats any more)
                for u in units:
                    self._keep_scores(proj, u, text, after[u.name])
                    self._apply_scores(proj, u.name, after[u.name], text=text, via="flag survey")
                with self.net.store.tx() as db:
                    self.net._event(db, proj["id"], None, "analysis", said)
                return said
        if best is None or not best[1] or divided or not console.splits_sources:
            return None
        first = rows[best[1][0]]
        said = self._divide_for_flags(None, slug, first, fp.unit(first["unit"]), best[2])
        if not said.startswith("✅"):
            return None
        part = fp.unit(self._fn(slug, first["name"])["unit"]).source
        return said + (f" Then: {again}" if part and (again := self.survey_file(slug, part, divided=True)) else "")

    def _divide_for_flags(self, agent: Agent | None, slug: str, fn, unit, broken: list[str]) -> str:
        """Split `fn`'s file so that it and the functions between it and those in `broken` (matched functions other
        flags break) are a file of their own: after the last of them before it, and at the first after it. Returns
        what split_file said (✅ when it's done)."""
        _, fp, _ = self.get(slug)
        try:
            order = fp.diff(unit, None).order
        except (ObjdiffError, ForkError) as e:
            return f"objdiff couldn't read {unit.source}'s functions: {e}"
        sym = self._meta(fn).get("symbol") or fn["name"]
        if sym not in order:
            return f"{fn['name']} isn't in {unit.source}'s object"
        at = order.index(sym)
        before = [order.index(b) for b in broken if b in order and order.index(b) < at]
        after = [order.index(b) for b in broken if b in order and order.index(b) > at]
        console = consoles.get(self.get(slug)[2].get("platform"))
        said = []
        # (the later cut first: the earlier one then leaves the function's part in the new file)
        for cut in ([order[min(after)]] if after else []) + ([order[max(before) + 1]] if before else []):
            try:
                said.append(self._split_source(agent, slug, console, unit.source, cut, ""))
            except NetworkError as e:
                said.append(f"{unit.source} couldn't be divided at {cut}: {e}")
                break
        return " ".join(said) if said else "nothing to split around"

    # ------------------------------------------------------------------ autopilot

    def autopilot_prepare(self, slug: str) -> list[int]:
        """The open functions autopilot tries in a game started from scratch, smallest first. Raises NetworkError
        when it can't run here. A console with drafts of its own (Console.own_drafts: PC) needs no m2c: its exact
        drafts come from the code, its others from Ghidra when it's installed."""
        proj, fp, cfg = self.get(slug)
        if cfg.get("origin") != "scratch":
            raise NetworkError("autopilot works on games started from scratch: a public decomp's headers don't have "
                               "what machine drafts need, and its easy functions are done already")
        if not cfg.get("ready"):
            raise NetworkError("finish setting the project up first")
        console = consoles.get(cfg.get("platform"))
        rows = self.net.store.all("SELECT id, name, unit, meta FROM functions WHERE project_id=? AND status='open' "
                                  f"AND NOT {COPY} ORDER BY n_insns, id", proj["id"])  # (a copy: twins match it)
        if console.own_drafts:
            if (rel := console.prepare_drafts(fp)):
                self._commit(proj, fp, rel, "Add the types machine drafts use\n\nWritten by decompdecomp's autopilot.")
        else:
            if not drafts.supported(cfg.get("platform") or ""):
                raise NetworkError("autopilot needs m2c, the draft decompiler: install it in Setup")
            # m2c reads the assembly a project keeps for its undecompiled functions. A ds-decomp project has none: its
            # sources are the delinked code as comments, so every draft would fail and autopilot would still commit
            # the macros (#232). Say so before writing anything, and let the helpers have the project.
            if rows and self._draft_asm(fp, rows) is None:
                raise NetworkError("Autopilot needs machine drafts, and this project keeps no assembly for m2c to read "
                                   "(a ds-decomp project): helpers still work on it.")
            if toolchains.installed("m2c") is None:
                raise NetworkError("autopilot needs m2c, the draft decompiler: install it in Setup")
            if drafts.add_m2c_macros(fp.root / "include" / "common.h"):  # projects made before autopilot ran on them
                self._commit(proj, fp, "include/common.h", "Add the macros machine drafts use\n\nWritten by decompdecomp's autopilot.")
        return [r["id"] for r in rows]

    def _draft_asm(self, fp: ForkProject, rows) -> Path | None:
        """The assembly file of the first of these open functions that has one (forks/drafts.py's lookup), or None
        when the project keeps no assembly for m2c to read."""
        sources: dict[str | None, str | None] = {}
        unit_of = getattr(fp, "unit", None)  # (a project whose objdiff.json isn't there to read yet)
        for fn in rows:
            unit_name, source = fn["unit"], None
            if unit_of is not None:
                try:
                    unit = unit_of(unit_name)
                except ForkError:  # (not in objdiff.json any more: its assembly may still be in asm/)
                    unit = None
                if unit is not None:
                    unit_name, source = unit.name, unit.source
            if source not in sources:
                try:
                    sources[source] = ((fp.root / source).read_text(errors="replace", encoding="utf-8")
                                       if source else None)
                except OSError:
                    sources[source] = None
            if (asm := drafts.find_asm(fp.root, unit_name, self._meta(fn).get("symbol") or fn["name"],
                                       sources[source])) is not None:
                return asm
        return None

    def _known(self, fp: ForkProject, unit) -> str:
        """The project's headers and a unit's source file, as one text: what drafts take declarations from."""
        parts = []
        for path in [*sorted((fp.root / "include").rglob("*.h")), *([fp.root / unit.source] if unit.source else [])]:
            try:
                parts.append(path.read_text(errors="replace", encoding="utf-8"))
            except OSError:
                continue
        return "\n".join(parts)

    def _compilable(self, proj, fp: ForkProject, cfg: dict, fn, unit, context: str = "") -> tuple[str, str] | None:
        """The function's machine draft (Ghidra's) as C that compiles in its file, made with the headers as they are
        now (and `context`, an agent's declarations: redraft), or None (the console has no such drafts, or this one
        can't be)."""
        console = consoles.get(cfg.get("platform"))
        if not console.own_drafts:
            return None
        raw = self._draft(proj, fp, cfg, fn, unit)
        if not raw or not raw.startswith("/* Ghidra */"):
            return None
        meta = self._meta(fn)
        return console.compilable_draft(fp, meta.get("symbol") or fn["name"], raw.removeprefix("/* Ghidra */\n"),
                                        self._known(fp, unit) + "\n" + context)

    def _autopilot_drafts(self, proj, fp: ForkProject, cfg: dict, fn, unit):
        """What autopilot tries for a function, in order, as (prelude, definition with what it includes): a console
        with drafts of its own, its exact drafts, then its machine draft made compilable (made only when no exact
        one matched: Ghidra takes seconds a source file); else m2c's draft."""
        console = consoles.get(cfg.get("platform"))
        meta = self._meta(fn)
        if console.own_drafts:
            yield from console.exact_drafts(fp, meta.get("symbol") or fn["name"], self._known(fp, unit))
            if (made := self._compilable(proj, fp, cfg, fn, unit)) is not None:
                yield made
            return
        try:
            current = (fp.root / unit.source).read_text(errors="replace", encoding="utf-8")
        except OSError:
            current = ""
        if (fp.root / "include" / "common.h").is_file() and not re.search(r'#\s*include\s+"common\.h"', current):
            # a file without the project's header (a library's own source, V.Flash's): a draft's types (s32,
            # M2C_UNK) don't exist there, and every draft failed on them
            return
        hint = (unit.scratch or {}).get("compiler", "") or json.dumps(fp.needs(cfg.get("version")))
        text = drafts.draft(fp.root, cfg.get("platform") or "", unit.name, meta.get("symbol") or fn["name"],
                            unit.source, compiler_hint=hint, valid=True)
        _, span = self._find(text, self._names(meta, fn)) if text else (None, None)
        if span is None:
            return
        yield "", "/* machine draft (m2c), tried by autopilot */\n" + drafts.self_contained(text, span, current)

    def autopilot_one(self, agent: Agent, proj, fid: int) -> str:
        """match | near | far | fail | skip, for one function's drafts, each built and diffed like an agent's, until
        one matches. A draft autopilot already judged as it is now is skipped: autopilot tries a function again when
        its drafts changed (the background drafter asks it to after the headers changed, app/drafts.py)."""
        now = time.time()
        with self.net.store.tx() as db:
            self.net._expire_claims(db)
            fn = db.execute("SELECT * FROM functions WHERE id=?", (fid,)).fetchone()
            if fn is None or fn["status"] != "open" or db.execute("SELECT 1 FROM claims WHERE function_id=?", (fid,)).fetchone():
                return "skip"
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fid, agent.id, now, now + 300))
        try:
            _, fp, cfg = self.get(proj["slug"])
            unit = fp.unit(fn["unit"])
            if not unit.source:
                return "skip"
            names = self._names(self._meta(fn), fn)
            outcomes = []
            for prelude, code in self._autopilot_drafts(proj, fp, cfg, fn, unit):
                _, span = self._find(code, names)
                if span is None or self.net.store.one("SELECT 1 FROM attempts WHERE function_id=? AND agent_id=? AND "
                                                      "source=?", fid, agent.id, code[span[0]:span[1]]):
                    continue
                res = self.attempt(agent, proj["slug"], fn["name"], code, keep=False, prelude=prelude)
                if res["matched"]:
                    return "match"
                if res["score"] is None:
                    why = [ln for ln in res["text"].splitlines() if re.search(r"error|Error", ln) and "ninja" not in ln]
                    logging.getLogger("decompdecomp").info("autopilot: %s's draft didn't build: %s", fn["name"],
                                                         " | ".join(why[:4])[:600] or res["text"][-300:])
                outcomes.append("fail" if res["score"] is None else "near" if (res.get("percent") or 0) >= 90 else "far")
            if not outcomes:
                return "skip" if self.net.store.one("SELECT 1 FROM attempts WHERE function_id=? AND agent_id=?",
                                                    fid, agent.id) else "fail"
            return min(outcomes, key=["near", "far", "fail"].index)
        except (NetworkError, OSError, subprocess.SubprocessError) as e:
            logging.getLogger("decompdecomp").info("autopilot: %s not tried: %s", fn["name"], str(e)[:500])
            return "fail"
        finally:
            with self.net.store.tx() as db:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fid, agent.id))

    def _insert_in_order(self, proj, fp: ForkProject, unit, fn, text: str, code: str) -> str:
        """Place a new function where it was in the original: after the closest earlier function present in the
        file, else before the closest later one, else at the end."""
        code = code.strip("\n") + "\n"
        entry = self._unit_index(proj, fp, unit)
        sym = self._meta(fn).get("symbol")
        order = entry["order"] if entry else []
        if sym in order:
            rows = {self._meta(r).get("symbol"): r for r in self.net.store.all(
                "SELECT name, meta FROM functions WHERE project_id=? AND unit=?", proj["id"], unit.name)}
            k = order.index(sym)
            for other in reversed(order[:k]):
                if other in rows:
                    _, span = self._find(text, self._names(self._meta(rows[other]), rows[other]))
                    if span:
                        return text[:span[1]].rstrip("\n") + "\n\n" + code + "\n" + text[span[1]:].lstrip("\n")
            for other in order[k + 1:]:
                if other in rows:
                    _, span = self._find(text, self._names(self._meta(rows[other]), rows[other]))
                    if span:
                        return text[:span[0]] + code + "\n" + text[span[0]:]
        return text.rstrip("\n") + "\n\n" + code

    def propose_join(self, agent: Agent, slug: str, function: str, with_function: str, reason: str) -> str:
        """An agent says two functions are one the analysis cut (a piece, a switch's cases in the next symbol): what
        the rules (arch/, a console's own) missed. Once NOT_C_AGENTS agents of NOT_C_MODELS models say so of the same
        two, the console joins them (Console.join_functions), checked as an analysis is (reanalyse: the game rebuilt
        byte for byte, else taken back), never touching a matched function; a join that doesn't hold is remembered,
        so it isn't proposed again. What agents joined stays: Check again only ever joins, never splits."""
        if not reason.strip():
            raise NetworkError("say why they're one function (what the code shows): the next agents read it")
        if (link := self.net.links.get(slug)) is not None:  # a room's member: the host counts it with its own agents'
            text = link.call("/collab/join_functions", agent, function=self._fn(slug, function)["name"],
                             with_function=self._fn(slug, with_function)["name"], reason=reason)
            if text.startswith("With yours"):  # (joined there: this copy follows)
                text += link.follow()
            return text
        proj, fp, cfg = self.get(slug)
        a, b = self._fn(slug, function), self._fn(slug, with_function)
        if a["id"] == b["id"]:
            raise NetworkError("name two different functions")
        if any(f["status"] == "matched" for f in (a, b)):
            raise NetworkError(f"{next(f['name'] for f in (a, b) if f['status'] == 'matched')} is matched: a join "
                               "would change it, so it can't be one")
        console = consoles.get(cfg.get("platform"))
        if not console.joins_functions:
            raise NetworkError(f"{console.name or 'This console'} projects can't join functions yet: work on them as "
                               "they are, and say so in a note for the next agent")
        first, last = sorted((a, b), key=lambda f: (f["vram"] or 0, f["id"]))
        key = f"{first['name']}+{last['name']}"
        refused = (cfg.get("joins_refused") or {}).get(key)
        if refused:
            return f"Joining {first['name']} and {last['name']} was tried, and refused: {refused}. Work on them as they are."
        said, models = self._vote(agent, proj, first, "joins", last["name"], reason, "join",
                                  f"{first['name']} + {last['name']}")
        if len(said) < NOT_C_AGENTS or len(models) < NOT_C_MODELS:
            return (f"Your proposal is counted ({len(said)} of {NOT_C_AGENTS} agents, {len(models)} of {NOT_C_MODELS} "
                    f"models): {first['name']} and {last['name']} are joined once enough agree and the game still "
                    "builds byte for byte. Meanwhile, claim another function.")
        matched = {r["name"] for r in self.net.store.all("SELECT name FROM functions WHERE project_id=? AND "
                                                         "status='matched'", proj["id"])}
        why = None

        def step(fp):
            nonlocal why
            try:
                return console.join_functions(fp, self._meta(first).get("symbol") or first["name"],
                                              self._meta(last).get("symbol") or last["name"], matched)
            except (RomError, ForkError) as e:
                why = str(e)
                raise ForkError(why) from None
        done = self.reanalyse(slug, step, log=lambda *_: None)
        if not done:
            why = why or "the game no longer rebuilt byte for byte with it"
            self.net._update_cfg(slug, lambda c: c.setdefault("joins_refused", {}).update({key: why}))
            return f"{len(said)} agents agreed, but joining {first['name']} and {last['name']} was refused: {why}."
        self.net.joined(first["name"], slug)  # (what set it aside was about a piece of it)
        try:
            self.net.add_note(self.net.local_agent("decompdecomp")[0], slug,
                              f"Agents ({', '.join(sorted(said))}) found this was cut by the analysis, and decompdecomp "
                              f"joined it: {done}. It's the whole function now, whatever older notes say.",
                              first["name"])
        except NetworkError:
            pass
        return f"With yours, {len(said)} agents of {len(models)} models agree: {done}. The game still builds byte for byte."

    def _vote(self, agent: Agent, proj, fn, kind: str, key: str, reason: str, event: str, what: str):
        """An agent's say on a change to the project's functions (`kind`: joins, boundaries; `key`: which change),
        kept in the function's meta; returns everyone's say on it and their models. The project's feed counts too
        (each say is an `event` of `what`): what a sync before _KEPT_KEYS had them dropped is counted again."""
        with self.net.store.tx() as db:
            meta = json.loads(db.execute("SELECT meta FROM functions WHERE id=?", (fn["id"],)).fetchone()["meta"] or "{}")
            said = meta.setdefault(kind, {}).setdefault(key, {})
            for r in db.execute("SELECT a.name, e.detail, e.created_at FROM events e JOIN agents a ON a.id=e.agent_id "
                                "WHERE e.project_id=? AND e.kind=? AND substr(e.detail, 1, ?)=?",
                                (proj["id"], event, len(what) + 1, f"{what}:")):
                said.setdefault(r["name"], {"model": model_of(r["name"]), "why": r["detail"][len(what) + 1:].strip(),
                                            "t": r["created_at"]})
            said[agent.name] = {"model": model_of(agent.name), "why": reason.strip()[:2000], "t": time.time()}
            db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), fn["id"]))
            self.net._event(db, proj["id"], agent.id, event, f"{what}: {reason.strip()[:200]}")
        return said, {v["model"] for v in said.values()}

    def report_boundary(self, agent: Agent, slug: str, function: str, end: str, reason: str) -> str:
        """An agent says a function runs on past its end: into data or leftovers, or into another function the
        analysis merged with it. Once NOT_C_AGENTS agents of NOT_C_MODELS models say it of the same address, the
        console cuts it there (Console.cut_function: the rest a function of its own, set aside when it isn't code),
        checked as a join is (reanalyse: the game rebuilt byte for byte, else taken back), never a matched function;
        a cut that doesn't hold is remembered. ROM projects ask the user instead (engine.request_boundary): there the
        rest is always set aside, and the user sees the words it leaves out; here the rebuild check stands behind it."""
        if not reason.strip():
            raise NetworkError("say what follows the end (data, leftovers, another function) and how you can tell")
        if slug in self.net.links:  # a room's member: the host counts it (engine.request_boundary forwards it)
            return self.net.request_boundary(agent, slug, function, end, reason)
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if not console.reports_boundaries:
            raise NetworkError(f"{console.name or 'This console'} projects can't report function ends yet: work on it "
                               "as it is (ROADMAP.md says what's planned)")
        fn = self._fn(slug, function)
        symbol = self._meta(fn).get("symbol") or fn["name"]
        extent = console.function_extent(fp, symbol)
        if extent is None:
            raise NetworkError("this project's functions are its own build's: report_boundary works where decompdecomp "
                               "made the project (a PC game started from scratch)")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} is matched: its end is proven")
        start, size = extent
        text = str(end).strip().lower()
        try:
            at = start + int(text[1:], 16) if text.startswith("+") else int(text, 16)
        except ValueError:
            at = None
        if at is None or not start < at < start + size:
            raise NetworkError(f"`end` is where {fn['name']} really ends: an address inside it (0x{start:08X} to "
                               f"0x{start + size:08X}) or an offset into it (+0x20)")
        key = f"0x{at:08X}"
        refused = (cfg.get("boundaries_refused") or {}).get(f"{symbol}@{key}")
        if refused:
            return f"Ending {fn['name']} at {key} was tried, and refused: {refused}. Work on it as it is."
        said, models = self._vote(agent, proj, fn, "boundaries", key, reason, "boundary", f"{fn['name']} ends at {key}")
        if len(said) < NOT_C_AGENTS or len(models) < NOT_C_MODELS:
            return (f"Your report is counted ({len(said)} of {NOT_C_AGENTS} agents, {len(models)} of {NOT_C_MODELS} "
                    f"models): {fn['name']} ends at {key} once enough agree and the game still builds byte for byte. "
                    "Meanwhile, release it or work on with its current size.")
        matched = {r["name"] for r in self.net.store.all("SELECT name FROM functions WHERE project_id=? AND "
                                                         "status='matched'", proj["id"])}
        why = None
        what = "; ".join(dict.fromkeys(v["why"][:200] for v in said.values()))

        def step(fp):
            nonlocal why
            try:
                return console.cut_function(fp, symbol, at, matched, what)
            except (RomError, ForkError) as e:
                why = str(e)
                raise ForkError(why) from None
        done = self.reanalyse(slug, step, log=lambda *_: None)
        if not done:
            why = why or "the game no longer rebuilt byte for byte with it"
            self.net._update_cfg(slug, lambda c: c.setdefault("boundaries_refused", {}).update({f"{symbol}@{key}": why}))
            return f"{len(said)} agents agreed, but ending {fn['name']} at {key} was refused: {why}."
        self.net.joined(fn["name"], slug)  # (its code changed: what set it aside was about the whole)
        try:
            self.net.add_note(self.net.local_agent("decompdecomp")[0], slug,
                              f"Agents ({', '.join(sorted(said))}) found it ran on past its end, and decompdecomp cut "
                              f"it: {done}. It's the whole function now, whatever older notes say.", fn["name"])
        except NetworkError:
            pass
        return f"With yours, {len(said)} agents of {len(models)} models agree: {done}. The game still builds byte for byte."

    def release(self, agent: Agent, slug: str, function: str, notes: str, not_c: bool = False) -> str:
        fn = self._fn(slug, function)
        if (link := self.net.links.get(slug)) is not None:
            link.call("/collab/release", agent, function=fn["name"], notes=notes, not_c=not_c)
        # leave the file at its best state for the next agent; what stopped that is said, never swallowed (the
        # next claim tries again, and tells its agent)
        said = "" if link is not None else self._best_in_file(agent, slug, fn)
        return Network.release(self.net, agent, function, notes, slug, not_c) + (f"\n{said}" if said else "")

    def release_exempt(self, slug: str, fn) -> str | None:
        """Why compiling can't help with this function (release_function lets such a release through at once), or
        None: its unit has no source file, or its identical twin elsewhere is hand-written assembly."""
        proj, fp, _ = self.get(slug)
        if not fp.unit(fn["unit"]).source:
            return "its unit has no source file"
        try:
            twin = self.net.twins.twin_of(proj, fn["id"])
            if twin is not None and self.is_asm(proj, self.net.store.one("SELECT * FROM functions WHERE id=?", twin)):
                return "its twin is hand-written assembly"
        except Exception:  # a heuristic: never in the way of a release
            return None
        return None

    def release_hints(self, slug: str, fn) -> list[str]:
        """For a release pushed back: what this project knows about what to do next with the function (in an LTCG
        project: the unresolved names that change its code, and that the rest are no reason to stop)."""
        _, fp, _ = self.get(slug)
        if not (fp.manifest or {}).get("ltcg"):
            return []
        unit = fp.unit(fn["unit"])
        if unit.base is None or not ltcg_unresolved(unit.base):
            return []
        found = self._unresolved_lines(fp, self._meta(fn), fn, unit, self._current_source(fp, fn), only_mattering=True)
        return ["Unresolved names in the harness link are no reason to stop: data and callees the original calls with "
                "a standard convention change nothing (the judge writes the original's references in their place).",
                *found]

    def _settled_text(self, slug: str, p: Path) -> str:
        """A source file as it stands between compiles: each compile writes its try into the file, builds it and puts
        the file back under the unit's lock, and a read meanwhile showed another agent's try, whose text the reader's
        edit_file then couldn't find (two agents on a GameCube game's 1,422-instruction function, edit after edit)."""
        proj, fp, _ = self.get(slug)
        rel = Path(os.path.relpath(p, fp.root)).as_posix()
        names = [u.name for u in fp.units_for(rel)]
        if not names:
            return p.read_text(errors="replace", encoding="utf-8")
        with self._tree(proj).shared(), self._units_locked(proj, names):
            return p.read_text(errors="replace", encoding="utf-8")

    def read_file(self, slug: str, path: str, start: int = 1, count: int = 200) -> str:
        _, fp, _ = self.get(slug)
        p = fp.root if path.strip().strip("/") in ("", ".") else fp.safe_path(path)
        if p.is_dir():  # a folder: what's in it (agents look around this way)
            hidden = {".git", "build", STATE, "orig", "__pycache__", "node_modules"}
            items = sorted((x for x in p.iterdir() if x.name not in hidden and not x.name.startswith(".")),
                           key=lambda x: (not x.is_dir(), x.name.lower()))
            listing = [f"  {x.name}/" if x.is_dir() else f"  {x.name}" for x in items[:300]]
            more = f"\n  ... and {len(items) - 300} more" if len(items) > 300 else ""
            return f"{path.strip() or '.'} is a folder ({len(items)} entries):\n" + "\n".join(listing) + more
        if not p.is_file():
            raise NetworkError(f"{path} isn't a file{self._did_you_mean(fp, path)}")
        with open(p, "rb") as f:
            head = f.read(8192)
        if b"\0" in head or p.stat().st_size > 4 * 1024 * 1024:
            raise NetworkError(f"{path} isn't a source or text file")  # never the user's game data
        lines = self._settled_text(slug, p).splitlines()
        start = max(1, int(start))
        chunk = lines[start - 1:start - 1 + max(1, min(int(count), 600))]
        out = [f"{path} (lines {start}-{start + len(chunk) - 1} of {len(lines)})"]
        out += [f"{start + i:5d}  {line}" for i, line in enumerate(chunk)]
        return "\n".join(out)

    def read_data(self, agent: Agent | None, slug: str, what: str, length: int = 64) -> str:
        """A data symbol's bytes in the original game (from the target objects): a string, a table, a constant,
        with the symbols its words point to."""
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection

        proj, fp, _ = self.get(slug)
        name = what.strip().strip("`'\"")
        if (text := consoles.get((fp.manifest or {}).get("platform")).read_data(fp, name, length)) is not None:
            return text  # the console reads it (PC: the program's data isn't in the target objects)
        held = agent and self.net.store.one("SELECT f.unit FROM claims c JOIN functions f ON f.id=c.function_id "
                                            "WHERE c.agent_id=?", agent.id)
        units = [held["unit"]] if held else []
        units += [u for u in self._data_index(proj, fp).get(name, []) if u not in units]
        for uname in units:
            try:
                unit = fp.unit(uname)
            except ForkError:
                continue
            if unit.target is None or not unit.target.exists():
                continue
            with open(unit.target, "rb") as f:
                elf = ELFFile(f)
                symtab = elf.get_section_by_name(".symtab")
                sym = next((x for x in symtab.iter_symbols() if x.name == name and isinstance(x["st_shndx"], int)
                            and x["st_info"]["type"] != "STT_FUNC"), None) if symtab else None
                if sym is None:
                    continue
                sec = elf.get_section(sym["st_shndx"])
                head = f"{name} ({uname}, {sec.name}+0x{sym['st_value']:X}, {sym['st_size'] or '?'} bytes)"
                if sec["sh_type"] == "SHT_NOBITS":
                    return f"{head}: uninitialized data ({sec.name}), zeros at boot."
                n = max(4, min(sym["st_size"] or 512, int(length or 64), 512))
                data = sec.data()[sym["st_value"]:sym["st_value"] + n]
                if n < (sym["st_size"] or 0):
                    head += f"; the first {n} (length up to 512 shows more)"
                ptrs = []
                for rs in elf.iter_sections():
                    if isinstance(rs, RelocationSection) and rs["sh_info"] == sym["st_shndx"]:
                        table = elf.get_section(rs["sh_link"])
                        for r in rs.iter_relocations():
                            at = r["r_offset"] - sym["st_value"]
                            if 0 <= at < n:
                                t = table.get_symbol(r["r_info_sym"])
                                tname = elf.get_section(t["st_shndx"]).name if t["st_info"]["type"] == "STT_SECTION" else t.name
                                addend = r["r_addend"] if r.is_RELA() else 0
                                ptrs.append((at, tname + (f"+0x{addend:X}" if addend else "")))
                out = [head]
                for i in range(0, len(data), 16):
                    chunk = data[i:i + 16]
                    out.append(f"  +0x{i:03X}: {chunk.hex(' '):<47}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}")
                if ptrs:
                    out.append("pointers in it: " + ", ".join(f"+0x{at:X} -> {t}" for at, t in sorted(ptrs)[:24]))
                e = ">" if not elf.little_endian else "<"
                words = [w for (w,) in struct.iter_unpack(e + "I", data[:len(data) // 4 * 4])]
                if words:
                    out += arch.float_lines(data, e == ">")
                text = data.split(b"\0", 1)[0]
                if len(text) >= 3 and all(32 <= c < 127 or c in (9, 10) for c in text):
                    out.append(f"as a string: {json.dumps(text.decode('ascii'))}")
                return "\n".join(out)
        raise NetworkError(f"no data symbol `{name}` in the game's objects (read_file and search_code find it in "
                           "the source; a function is shown by get_function)")

    def _data_index(self, proj, fp: ForkProject) -> dict[str, list[str]]:
        """Data symbol -> units whose target object defines it (built once per objdiff.json)."""
        from elftools.elf.elffile import ELFFile

        key = (proj["id"], (fp.root / "objdiff.json").stat().st_mtime_ns if (fp.root / "objdiff.json").exists() else 0)
        cached = getattr(self, "_data_idx", None)
        if cached and cached[0] == key:
            return cached[1]
        index: dict[str, list[str]] = defaultdict(list)
        for unit in fp.units():
            if unit.target is None or not unit.target.exists():
                continue
            try:
                with open(unit.target, "rb") as f:
                    symtab = ELFFile(f).get_section_by_name(".symtab")
                    for x in symtab.iter_symbols() if symtab else ():
                        if x.name and x["st_info"]["type"] in ("STT_OBJECT", "STT_NOTYPE") and isinstance(x["st_shndx"], int):
                            index[x.name].append(unit.name)
            except Exception:
                continue
        self._data_idx = (key, dict(index))
        return self._data_idx[1]

    @staticmethod
    def _did_you_mean(fp: ForkProject, path: str) -> str:
        """Files of the project with the name the agent guessed a path for."""
        name = Path(path).name
        if not name or not EDITABLE.search(name):
            return ""
        root = fp.root.resolve()
        found = []
        for hit in root.rglob(name):
            rel = hit.relative_to(root)
            if hit.is_file() and not {".git", "build", STATE} & set(rel.parts):
                found.append(rel.as_posix())
                if len(found) >= 5:
                    break
        return ("; did you mean " + " or ".join(found)) if found else ""

    def search(self, slug: str, pattern: str, glob: str = "") -> str:
        _, fp, _ = self.get(slug)
        root = fp.root.resolve()
        # Python owns the pattern: grep -E reads e.g. \\d differently, and capturing its output kept every match
        # in memory before the 80-line cut. Prune build trees before walking and read only as far as that cut.
        excluded = {".git", "build", STATE}

        def sources():
            for folder, dirs, names in os.walk(root):
                dirs[:] = sorted(d for d in dirs if d not in excluded)
                for name in sorted(names):
                    if Path(name).suffix.lower() in (".c", ".cc", ".cpp", ".h", ".hpp", ".inc"):
                        yield Path(folder) / name

        try:
            rx = re.compile(pattern)
        except re.error:  # e.g. "func(": search for the text itself
            rx = re.compile(re.escape(pattern))
        if glob:
            glob = _path_glob(glob)
            try:
                files = sorted(fp.root.glob(glob))
            except ValueError as e:
                raise NetworkError(f"glob {glob!r}: {e} (e.g. src/**/*.cpp, include/*.h)") from None
        else:
            files = sources()
        hits = []
        for p in files:
            rp = p.resolve()
            if root not in rp.parents or not rp.is_file():
                continue
            rel = rp.relative_to(root)
            if excluded & set(rel.parts):
                continue
            with rp.open(errors="replace", encoding="utf-8") as source:
                for i, line in enumerate(source, 1):
                    if rx.search(line):
                        hits.append(f"{rel.as_posix()}:{i}: {line.strip()[:160]}")
                        if len(hits) >= 80:
                            return "\n".join(hits + ["... (more matches; narrow the pattern)"])
        return "\n".join(hits) or "no matches"

    def edit_file(self, agent: Agent, slug: str, path: str, old: str, new: str, message: str = "",
                  sdk: bool = False, more: list | None = None) -> str:
        """`sdk`: the edit is the app's, an SDK inline function taken from the user's copy (sdk_inline), which may
        be assembly as the SDK's header has it; an agent's edit never is. `more`: further {"old", "new"} edits of the
        same file, made with the first one and built and kept or undone with it: a function's return type changes in
        its prototype and its definition together (a GameCube game's two, 2,000 lines apart: either alone doesn't
        compile, so no edit could make the change)."""
        more = [(str(e.get("old", "")), str(e.get("new", ""))) for e in more or [] if isinstance(e, dict)]
        if any(not o for o, _ in more):
            raise NetworkError("each further edit needs its old text: appending is the first edit's (old empty)")
        # without a message the commit says what changed where: agents left it out hundreds of times a night, and
        # each refusal cost a turn
        message = message.strip() or f"Edit {Path(path).as_posix()}"
        if (link := self.net.links.get(slug)) is not None:  # the host makes and checks it; this copy follows
            text = link.call("/collab/edit", agent, path=path, old=old, new=new, message=message,
                             more=[{"old": o, "new": n} for o, n in more])
            if text.startswith(("✅", "⚠️")):
                text += link.follow()
            return text
        proj, fp, cfg = self.get(slug)
        p = fp.safe_path(path, write=True)
        self.net.bump_generation(proj["id"])  # (a header or shared file: compiles may come out differently now)
        if not sdk and any(_CHEAT.search(_strip_comments(n)) for n in [new, *(n for _, n in more)]):
            raise NetworkError("inline assembly, asm functions and asm includes aren't allowed (an SDK inline "
                               "function that is assembly, like OSInitFastCast: sdk_inline puts in the SDK's own)")
        rel = Path(os.path.relpath(p, fp.root)).as_posix()
        units = [u for u in fp.units_for(rel) if u.base is not None]
        edits = [(old, new), *more]
        if units:  # a unit's own source file: only that unit can change
            return self._edit_source(agent, proj, fp, p, rel, units, edits, message)
        return self._edit_shared(agent, proj, fp, slug, p, rel, edits, message)

    def sdk_inline(self, agent: Agent, slug: str, name: str, path: str) -> str:
        """The SDK's own inline function `name`, from the user's copy of their console's kit (kits/inlines.py), put
        in the source file `path` before the first function that calls it, as edit_file puts an edit in (built,
        measured, undone if a match is lost, committed). Some are no C: the Dolphin SDK's OSInitFastCast is four
        GQR writes in an asm block, inlined into a GameCube game's main, which agents set aside as no C makes it."""
        name = name.strip()
        if (link := self.net.links.get(slug)) is not None:  # (the host's SDK copy; this copy follows its commit)
            text = link.call("/collab/sdk_inline", agent, name=name, path=path)
            if text.startswith(("✅", "⚠️")):
                text += link.follow()
            return text
        from .. import kits
        from ..kits import inlines

        _, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if not kits.headers(console.kits):
            raise NetworkError(f"no SDK headers to take {name} from: the user sets up their own copy of the "
                               f"{console.name} SDK in Setup (its folder with include/)")
        found = inlines.find(console.kits, name)
        if found is None:
            raise NetworkError(f"{name} isn't an inline function in the headers of the user's SDK copies (a macro "
                               "isn't one: write what it expands to)")
        body, header = found
        p = fp.safe_path(path, write=True)
        if not p.is_file():
            raise NetworkError(f"{path} isn't a file of this project: give the source file whose function calls {name}")
        text = p.read_text(errors="replace", encoding="utf-8")
        clean = csource._blank(text)
        if re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", clean):
            return f"{path} defines {name} already: use it as it is"
        at = _definition_start(clean, name)
        if at is None:  # (nothing calls it yet: above the file's first function, where every one of them sees it)
            at = _definition_start(clean, "")
        if at is None:
            raise NetworkError(f"{path} has no function to put {name} above: give the source file of the function "
                               "that calls it")
        end = clean.find("{", at)
        old = text[at:end + 1]
        if text.count(old) != 1:
            raise NetworkError(f"{path}'s function calling {name} isn't one of a kind there: edit_file it apart first")
        block = f"/* {name}: the SDK's own, from {header} (your copy), its macros put in */\n{body}\n\n"
        return self.edit_file(agent, slug, path, old, block + old,
                              f"Add the SDK's {name}\n\nFrom {header} in the user's own copy of the SDK.", sdk=True)

    @staticmethod
    def _edited(p: Path, path: str, edits: list[tuple[str, str]]) -> tuple[bool, str, str]:
        """The file before and after its edits, made in order (each `old` found once in the text the ones before
        it left)."""
        existed = p.exists()
        text = updated = p.read_text(errors="replace", encoding="utf-8") if existed else ""
        for old, new in edits:
            if old:
                updated = replace_once(updated, old, new, path)
            else:
                updated = updated.rstrip("\n") + ("\n" if updated else "") + new.strip("\n") + "\n"
        return existed, text, updated

    def _edit_source(self, agent: Agent, proj, fp: ForkProject, p: Path, rel: str, units: list,
                     edits: list[tuple[str, str]], message: str) -> str:
        """Edit a unit's source file: rebuild and measure just that unit, keep everything that matched before."""
        linked = any(u.complete for u in units) and fp.linkable()
        with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), \
                self._units_locked(proj, [u.name for u in units]):
            existed, text, updated = self._edited(p, rel, edits)
            bases = {u.name: self._baseline(proj, fp, u, text) for u in units}
            p.parent.mkdir(parents=True, exist_ok=True)
            _rewrite(p, updated)

            def undo() -> None:
                if existed:
                    _rewrite(p, text)
                else:
                    p.unlink(missing_ok=True)
                for u in units:
                    if self._build_unit(proj, fp, u)[0] and bases[u.name][0] is not None:
                        self._keep_scores(proj, u, text, bases[u.name][0])

            after: dict[str, dict | None] = {}
            for u in units:
                ok, log = self._build_unit(proj, fp, u)
                if not ok:
                    if bases[u.name][1]:
                        undo()
                        return f"❌ {rel} doesn't compile after your edit, so it was undone:\n{log[-2500:]}"
                    after[u.name] = None  # it didn't build before the edit either
                    continue
                try:
                    after[u.name] = fp.diff(u, None).unit_scores
                except (ObjdiffError, ForkError) as e:
                    undo()
                    return f"❌ objdiff couldn't measure {rel} after your edit, so it was undone: {e}"
            lost = []
            for u in units:
                before = bases[u.name][0] if bases[u.name][0] is not None else self._last_scores(proj, u)
                now = after[u.name] or {}
                lost += [n for n, pct in (before or {}).items() if pct is not None and pct >= 100 and (now.get(n) or 0) < 100]
            if lost:
                undo()
                return f"❌ REJECTED and undone: the edit breaks {len(lost)} matched function(s): {', '.join(sorted(lost)[:10])}"
            lower = sorted(f"{n} {pct:.1f}% → {(now.get(n) or 0):.1f}%" for u in units
                           for now in [after[u.name] or {}]
                           for n, pct in ((bases[u.name][0] if bases[u.name][0] is not None
                                           else self._last_scores(proj, u)) or {}).items()
                           if pct is not None and after[u.name] is not None and (now.get(n) or 0) < pct - 0.5)
            if linked and not (ok := self._verify(proj, fp))[0]:
                undo()
                return (f"❌ REJECTED and undone: {rel} is linked into the game, and with your edit the game no longer "
                        f"builds byte for byte:\n{_tail(ok[1])}")
            for u in units:
                if after[u.name] is not None:
                    self._keep_scores(proj, u, updated, after[u.name])
                    self._apply_scores(proj, u.name, after[u.name], agent=agent, text=updated,
                                       via=f"unit diff after an edit of {rel}")
            self._commit(proj, fp, rel, f"{message.strip()}\n\nEdited by {agent.name} with decompdecomp.")
            with self.net.store.tx() as db:
                # "source", not "context": one unit's file changed, not what every function compiles against, so what
                # a model family gave up on stays at the back of its queue (claim_row). As "context", the thousands of
                # unit edits of a night's work put it back in front every few seconds.
                self.net._event(db, proj["id"], agent.id, "source", f"{rel}: {message.strip()[:120]}")
        if any(v is None for v in after.values()):
            return f"⚠️ {rel} updated, but it still doesn't compile (it didn't before your edit either): fix it so its functions can be measured."
        done = "".join(self._file_done(proj["slug"], proj, fp, u, after[u.name] or {}, agent) for u in units[:1])
        dropped = (f"\n⚠️ It lowers {len(lower)} function(s) that weren't matched yet: {', '.join(lower[:8])}"
                   f"{' ...' if len(lower) > 8 else ''}. Kept, as you may be partway through one; put back what "
                   "you didn't mean to change.") if lower else ""
        return (f"✅ {rel} updated; every matched function still matches.{dropped}{done}"
                f"{self.data_jobs.after_edit(agent, proj['slug'], rel)}")

    def _edit_shared(self, agent: Agent, proj, fp: ForkProject, slug: str, p: Path, rel: str,
                     edits: list[tuple[str, str]], message: str) -> str:
        """Edit a header (or any file several units may use): rebuild and measure the whole project."""
        with self._tree(proj).exclusive():
            existed, text, updated = self._edited(p, rel, edits)
            failed_before: list[str] = []
            self._build_all(proj, fp, failed=failed_before)  # what already doesn't build, so it isn't blamed on the edit
            game_ok = fp.linkable() and fp.verify()[0]
            broken_before = fp.failed_units(failed_before)
            protected = {(r["unit"], self._meta(r).get("symbol")) for r in self.net.store.all(
                "SELECT unit, meta FROM functions WHERE project_id=? AND status='matched'", proj["id"])}
            p.parent.mkdir(parents=True, exist_ok=True)
            _rewrite(p, updated)

            def undo() -> None:
                if existed:
                    _rewrite(p, text)
                else:
                    p.unlink(missing_ok=True)
                self._build_all(proj, fp)

            failed_after: list[str] = []
            _, log = self._build_all(proj, fp, failed=failed_after)
            broken_after = fp.failed_units(failed_after)
            newly = sorted(broken_after - broken_before)
            if not newly and game_ok and not (ok := fp.verify())[0]:
                undo()
                return (f"❌ after your edit the game no longer builds byte for byte from its linked files, so it was "
                        f"undone:\n{_tail(ok[1])}")
            if newly:
                undo()
                return (f"❌ after your edit {len(newly)} file(s) no longer compile ({', '.join(newly[:5])}), so it was "
                        f"undone. Build output:\n{log[-2500:]}")
            try:
                rep = fp.report()
            except (ObjdiffError, ForkError) as e:
                undo()
                return f"❌ the project couldn't be measured after your edit, so it was undone: {e}"
            lost = protected - _matched_in(rep, broken_after)
            if lost:  # was each of them really matched before the edit? (the database can be behind the tree)
                undo()
                try:
                    rep_before = fp.report()
                except (ObjdiffError, ForkError) as e:
                    return f"❌ the project couldn't be measured, so the edit was undone: {e}"
                truly = sorted(sym for unit, sym in lost & _matched_in(rep_before, broken_before))
                self.sync(slug, log=lambda *_: None, rep=rep_before, broken=broken_before)
                if truly:
                    return f"❌ REJECTED and undone: the edit breaks {len(truly)} matched function(s): {', '.join(truly[:10])}"
                p.parent.mkdir(parents=True, exist_ok=True)
                _rewrite(p, updated)
                self._build_all(proj, fp)
            self._scores = {k: v for k, v in self._scores.items() if k[0] != proj["id"]}
            self._commit(proj, fp, rel, f"{message.strip()}\n\nEdited by {agent.name} with decompdecomp.")
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id, "context", f"{rel}: {message.strip()[:120]}")
            self.sync(slug, log=lambda *_: None, rep=rep, broken=broken_after, agent=agent)
        if fp.linkable() and self.link_candidates(proj, fp, rep):
            self.link_soon(slug, agent)
        return f"✅ {rel} updated; every matched function still matches."

    # ------------------------------------------------------------------ for the GUI

    def overview(self, slug: str) -> dict:
        proj, fp, cfg = self.get(slug)
        agg = self.net.store.one(f"SELECT {PROGRESS_COLUMNS}, SUM(attempts) AS attempts "
                                 f"FROM functions WHERE project_id=? AND {IN_BUILD}", proj["id"])
        if missing := self.net.project_missing(proj):
            # Nothing here reads the tree (it isn't there): what the database knows, and why it can't be opened.
            return {
                "slug": slug, "title": proj["name"], "description": proj["description"], "kind": "fork",
                **consoles.get(cfg.get("platform")).project_facts(),
                "repo_url": cfg.get("repo_url"), "fork_kind": cfg.get("fork_kind"), "version": cfg.get("version"),
                "origin": cfg.get("origin"), "compiler_name": cfg.get("compiler"), "versions": [],
                "ready": bool(cfg.get("ready")), "needs": None,
                "rom": {"game_code": cfg.get("version") or "", "region": consoles.name(cfg.get("platform")),
                        "title": proj["name"]},
                "compiler": {"toolchain": "project", "name": "Project's own build", "flags": [], "installed": True,
                             "proprietary": False, "supported": True},
                "compilers": [],
                "functions": agg["total"] or 0, "matched": agg["matched"] or 0, "bytes": agg["bytes"] or 0,
                "matched_bytes": agg["matched_bytes"] or 0, "set_aside": agg["set_aside"] or 0,
                "set_aside_bytes": agg["set_aside_bytes"] or 0, "attempts": agg["attempts"] or 0,
                "context_version": 0, "folder": proj["root"], "room": self.net._room_info(slug),
                "measures": cfg.get("measures") or {}, "uncovered": None, "rebuild": None,
                "reimports": cfg.get("origin") == "scratch" and consoles.get(cfg.get("platform")).reimports,
                "build_problem": None, "missing": missing,
            }
        if cfg.get("ready"):
            self._preflight_once(slug)
        m = cfg.get("measures") or {}
        need = fp.needs(cfg.get("version")) if not cfg.get("ready") else None
        return {
            "slug": slug, "title": proj["name"], "description": proj["description"], "kind": "fork",
            **consoles.get(cfg.get("platform")).project_facts(),
            "repo_url": cfg.get("repo_url"), "fork_kind": cfg.get("fork_kind"), "version": cfg.get("version"),
            "origin": cfg.get("origin"),
            # what the header shows: its console's name for it ("Visual C++ 8.0 SP1"; the page put "CodeWarrior" before
            # every id that wasn't a DS one, "CodeWarrior MSVC/8.0SP1" on a PC project)
            "compiler_name": consoles.compiler_name(cfg["compiler"]) if cfg.get("compiler") else None,
            "versions": fp.versions(), "ready": bool(cfg.get("ready")), "needs": need,
            "rom": {"game_code": cfg.get("version") or "", "region": consoles.name(cfg.get("platform")),
                    "title": proj["name"]},
            "compiler": {"toolchain": "project", "name": "Project's own build", "flags": [], "installed": True,
                         "proprietary": False, "supported": True},
            "compilers": [],
            **(self._compiler_facts(fp, cfg) if cfg.get("ready") else {}),
            "functions": agg["total"] or 0, "matched": agg["matched"] or 0, "bytes": agg["bytes"] or 0,
            "matched_bytes": agg["matched_bytes"] or 0, "set_aside": agg["set_aside"] or 0,
            "set_aside_bytes": agg["set_aside_bytes"] or 0, "attempts": agg["attempts"] or 0,
            "context_version": 0, "folder": proj["root"], "room": self.net._room_info(slug),
            "measures": m, "uncovered": self.uncovered(slug) if cfg.get("ready") and fp.linkable() else None,
            "rebuild": (fp.manifest or {}).get("rebuild") if cfg.get("origin") == "scratch" else None,
            "reimports": cfg.get("origin") == "scratch" and consoles.get(cfg.get("platform")).reimports,
            **self._scope_facts(proj, fp, cfg),
            # the programs of the game it analyses and the ones it could (Console.game_parts: V.Flash's modules)
            "game_parts": (consoles.get(cfg.get("platform")).game_parts(fp)
                           if cfg.get("origin") == "scratch" and consoles.get(cfg.get("platform")).chooses_parts else None),
            # why it doesn't build on this computer (preflight; checked once a run when its page first opens)
            "build_problem": cfg.get("build_problem") if cfg.get("ready") else None,
        }

    def _scope_facts(self, proj, fp: ForkProject, cfg: dict) -> dict:
        """What the project covers, for its page and Settings: `scope`, `left_out` (functions its progress leaves
        out now as not the game's own: part of the overview's `set_aside` count), `scope_list` (what its set-aside
        list names: {functions, without_source}, None: nothing) and `unanalysed` (code its import left unanalysed
        that a new analysis can bring in, Console.unanalysed's words).
        (`scope_list`, not `set_aside`: that's the overview's count of every set-aside function, which the pages take
        off the total; named the same, this dict replaced it and every such project showed "NaN functions".)
        (An older import's manifest may say what it left out as `set_aside_unimported`: the console's own check
        replaces it, so it's no longer read.)"""
        manifest = fp.manifest or {}
        left = self.net.store.one(f"SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND NOT ({GAME_CODE})",
                                  proj["id"])["n"]
        return {"scope": fp.scope if manifest else None, "left_out": left or 0, "scope_list": cfg.get("set_aside"),
                "copies": cfg.get("copies"),
                "unanalysed": self._unanalysed(fp, cfg) if cfg.get("origin") == "scratch" else None}

    def _file_parts(self, fp: ForkProject, cfg: dict) -> tuple[str, list[dict]] | None:
        """(the project's own compiler, the parts built with another: one per source file, with its address range),
        for a project whose files each have a compiler (Console.file_compiler: DS); None: its build decides."""
        # the overview goes with every live poll (each second): reading a PC game's 1,300 files' compilers again each
        # time took 300-400 ms. Read again when a file they come from changed (a new source file changes one too)
        console = consoles.get(cfg.get("platform"))
        stamp = _config_stamp(fp.root, console.compiler_config) if console.compiler_config else None
        if stamp is not None and (known := self._parts.get(fp.root)) is not None and known[0] == stamp:
            return known[1]
        own = console.file_compiler(fp, "")
        if own is None:
            self._parts[fp.root] = (stamp, None)
            return None
        ranges = console.file_ranges(fp)
        parts = []
        for source in sorted({u.source for u in fp.units() if u.source}):
            if (c := console.file_compiler(fp, source)) != own:
                for start, end in ranges.get(source) or [(0, 0)]:
                    parts.append({"file": source, "start": start, "end": end, "toolchain": c,
                                  "name": consoles.compiler_name(c), "flags": []})
        self._parts[fp.root] = (stamp, (own, parts))
        return own, parts

    def _compiler_facts(self, fp: ForkProject, cfg: dict) -> dict:
        """The overview's compiler fields, as a ROM project's: the Settings panel and its dropdown work the same.
        Nothing where the project's build decides its compilers (a public decomp): no panel, and a page reading a
        missing `compiler_map` as false says there's no map (steering.js). The map fact the GUI's wording follows is
        the Settings answer's (compiler_answer), which each file having a compiler decides."""
        found = self._file_parts(fp, cfg)
        if found is None:
            return {}
        own, parts = found
        return {"compiler": {"toolchain": own, "name": consoles.compiler_name(own), "flags": [], "installed": True,
                             "proprietary": False, "supported": True},
                "compilers": [c.id for c in consoles.get(cfg.get("platform")).project_compilers(fp)],
                "compiler_ranges": parts}

    def compiler_answer(self, slug: str, *, include_functions: bool = True) -> dict:
        """The Settings panel's answer (engine.compiler_answer's form): the project's compiler and the files built
        with another, each kept because its matched functions match with it."""
        self.net.filecompilers.normalise(slug)  # (#260: a saved "checking" with no run behind it never spins the panel)
        proj, fp, cfg = self.get(slug)
        found = self._file_parts(fp, cfg)
        if found is None:
            raise NetworkError("this project's own build sets its compilers")
        own, parts = found
        files = self.net.filecompilers
        elsewhere = [r for r in files.build(slug).runs if r.differs()]
        survey, state = cfg.get("file_survey") or {}, files.surveys.get(slug) or {}
        checks = cfg.get("file_checks") or []
        fields = "name,vram,status" if include_functions else "vram"
        functions = self.net.store.all(
            f"SELECT {fields} FROM functions WHERE project_id=? AND vram IS NOT NULL ORDER BY vram", proj["id"])
        addresses = [fn["vram"] for fn in functions]
        def part_functions(part):
            first, last = bisect_left(addresses, part["start"]), bisect_left(addresses, part["end"])
            return [dict(fn) for fn in functions[first:last]] if include_functions else last - first
        has_map = files.applies(slug)  # (`mips` is what older pages called this fact)
        return {"compiler": consoles.compiler_name(own), "flags": "", "compiler_map": has_map,
                "mips": has_map, "unit": "source file",
                "elsewhere": [{"start": r.start, "end": r.end, "compiler": consoles.compiler_name(r.label[0]),
                               "functions": r.functions, "confirmed": r.confirmed} for r in elsewhere[:12]],
                "elsewhere_count": len(elsewhere),
                "checking": (state.get("state") == "running" or files.working(slug)
                             or any(c["status"] == "checking" for c in checks)),
                "survey": {"state": state.get("state"), "tried": len(survey.get("tried", {})),
                           "confirmed": len(survey.get("confirmed", {})), "running_tried": state.get("tried", 0),
                           "t": survey.get("t")},
                "checks": [{"id": c["id"], "audit": False, "status": c["status"], "said": c.get("said") or "",
                            "ranges": c["spans"], "compiler": consoles.compiler_name(c["toolchain"])} for c in checks],
                "parts": [{"start": p["start"], "end": p["end"], "compiler": p["name"], "flags": "", "file": p["file"],
                           "toolchain": p["toolchain"], "family": toolchains.compiler_family(p["toolchain"]) or p["toolchain"],
                           **({"function_list": part_functions(p)} if include_functions else {}),
                           "functions": (len(part_functions(p)) if include_functions else part_functions(p))
                           if p["end"] > p["start"] else None,
                           "check": "confirmed", "said": f"{p['file']}: its matched functions match with it"}
                          for p in parts]}

    def set_compiler_ranges(self, slug: str, ranges: list[list[int]], compiler: str | None, force: bool = False) -> str:
        """The Settings panel's "only for these address ranges", where each source file has a compiler: the files
        whose code is in them get `compiler` (None: the project's own again), each only when its matches hold, or
        whatever they cost when the user says so (`force`)."""
        if slug in self.net.links:  # (committed in this tree, the next pull dropped it; its matches stayed here)
            raise NetworkError(ROOM_COMPILER)
        _, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        own = console.file_compiler(fp, "")
        if own is None:
            raise NetworkError("this project's own build sets its compilers")
        files = sorted(f for f, spans in console.file_ranges(fp).items()
                       if any(a < e and s < b for a, b in ranges for s, e in spans))
        if not files:
            raise NetworkError("no source file's code is in those ranges")
        done, stayed = [], []
        for f in files:
            try:
                self.set_file_compiler_by_hand(slug, f, compiler or own, force=force)
                done.append(f)
            except NetworkError as e:
                stayed.append(str(e))
        if not done:
            raise NetworkError("; ".join(stayed[:4]))
        said = f"{len(done)} source file{'s' if len(done) != 1 else ''} built with {consoles.compiler_name(compiler or own)}"
        return said + (f"; {len(stayed)} stay as they were ({stayed[0]})" if stayed else "") + "."

    def set_compiler_everywhere(self, slug: str, compiler: str, log=print) -> dict:
        """The Settings panel's compiler for the whole game, where each source file has one: every file switches,
        one at a time and only when its matches hold (a minute or two: it's a job), and then it's the project's
        own, the files that stayed keeping theirs."""
        if slug in self.net.links:  # (committed in this tree, the next pull dropped it; its matches stayed here)
            raise NetworkError(ROOM_COMPILER)
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        if console.file_compiler(fp, "") is None:
            raise NetworkError("this project's own build sets its compilers")
        if compiler not in {c.id for c in console.project_compilers(fp)}:
            raise NetworkError(f"{compiler!r} isn't one of this project's compilers")
        sources = sorted({u.source for u in fp.units() if u.source})
        stayed = []
        for n, source in enumerate(sources, 1):
            try:
                self.set_file_compiler_by_hand(slug, source, compiler)
            except NetworkError as e:
                stayed.append(str(e))
            if n % 20 == 0 or n == len(sources):
                log(f"{n} of {len(sources)} source files tried, {len(stayed)} kept their compiler")
        with self._tree(proj).exclusive(), self._build_lock(proj):
            changed = console.set_own_compiler(fp, compiler, sources)
        self.net.bump_generation(proj["id"])
        self._commit_paths(proj, fp, changed, f"Build the game with {compiler}\n\nChosen in decompdecomp's project "
                                              f"settings; {len(stayed)} source files keep the compiler they had.")
        self.net._update_cfg(slug, lambda c: c.update(compiler=compiler))
        return {"switched": len(sources) - len(stayed), "stayed": stayed[:20]}

    def file_scores(self, slug: str, source: str, compiler: str) -> tuple[dict[str, float], dict[str, float]]:
        """Every function of a source file, its match % built with the file's own compiler and with `compiler`, the
        file keeping its own: the evidence of the compiler map's survey and range checks (app/filecompilers.py). The
        second is empty when the file doesn't build with it."""
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        own = console.file_compiler(fp, source)
        units = fp.units_for(source)
        if own is None or not units:
            raise NetworkError(f"{source} isn't a source file whose compiler this project lets you choose")
        text = (fp.root / source).read_text(errors="replace", encoding="utf-8")
        with self._tree(proj).exclusive(), self._units_locked(proj, [u.name for u in units]):
            before: dict[str, float] = {}
            for u in units:
                before.update(self._baseline(proj, fp, u, text)[0] or {})
            if compiler == own:
                return before, before
            after: dict[str, float] = {}
            try:
                with self._build_lock(proj):  # (a build reads the map)
                    console.set_file_compiler(fp, source, compiler)
                for u in units:
                    if self._build_unit(proj, fp, u)[0]:
                        try:
                            after.update(fp.diff(u, None).unit_scores)
                        except (ObjdiffError, ForkError):
                            pass
            finally:
                with self._build_lock(proj):
                    console.set_file_compiler(fp, source, own)
                for u in units:
                    self._build_unit(proj, fp, u)  # the file's objects are its own compiler's again
        return before, after

    def set_file_compiler_by_hand(self, slug: str, source: str, compiler: str, force: bool = False,
                                  flags: list[str] | None = None) -> None:
        """The user's choice of a source file's compiler (the project's Settings), kept only when every function of
        the file that matched still matches with it: the rule try_compiler's switches follow. What matches with it
        now is a match like any other. `force`: kept anyway, the user having been told which matches it costs (an
        agent's try_compiler put a 2003 game's file on Visual C++ 8.0 for a line 7.0 couldn't read, and the user
        couldn't take it back): those are open again, their C kept as their best."""
        if slug in self.net.links:  # (committed in this tree, the next pull dropped it; its matches stayed here)
            raise NetworkError(ROOM_COMPILER)
        proj, fp, cfg = self.get(slug)
        console = consoles.get(cfg.get("platform"))
        own = console.file_compiler(fp, source)
        units = fp.units_for(source)
        if own is None or not units:
            raise NetworkError(f"{source} isn't a source file whose compiler this project lets you choose")
        if compiler not in {c.id for c in console.project_compilers(fp)}:
            raise NetworkError(f"{compiler!r} isn't one of this project's compilers")
        # flags with it, where each file has its own (PC: RSA's MD5 in a 6.0 game, Visual C++ 4.2 with /Od)
        own_flags = console.file_flags(fp, source)
        if flags is not None and own_flags is None:
            raise NetworkError("this project's flags are its build's own")
        if bad := [f for f in flags or [] if not re.fullmatch(r"[/-][A-Za-z][\w+:-]*", f)]:
            raise NetworkError(f"{bad[0]!r} isn't a compiler switch")
        flags_set = flags is not None and list(flags) != list(own_flags or [])
        if compiler == own and not flags_set:
            return
        text = (fp.root / source).read_text(errors="replace", encoding="utf-8")
        with self._tree(proj).exclusive(), self._units_locked(proj, [u.name for u in units]):
            before = {u.name: dict(self._baseline(proj, fp, u, text)[0] or {}) for u in units}
            # what the project counts as matched in the file must hold too, whatever the measured scores say: a
            # cached measurement taken as the file was divided read none of its matches, and the switch to 7.1 that
            # broke one was kept (the demo's divided file, now and then)
            for u in units:
                for r in self.net.store.all("SELECT name, meta FROM functions WHERE project_id=? AND unit=? AND "
                                            "status='matched'", proj["id"], u.name):
                    before[u.name][self._meta(r).get("symbol") or r["name"]] = 100.0
            with self._build_lock(proj):
                rel = console.set_file_compiler(fp, source, compiler)
                if flags_set:
                    flags_rel = console.set_file_flags(fp, source, list(flags))
            after, broken = {}, []
            for u in units:
                ok, log = self._build_unit(proj, fp, u)
                try:
                    after[u.name] = fp.diff(u, None).unit_scores if ok else {}
                except (ObjdiffError, ForkError):
                    after[u.name] = {}
                broken += [n for n, pct in before[u.name].items()
                           if (pct or 0) >= 100 and (after[u.name].get(n) or 0) < 100]
            if (broken or not all(after.values())) and not force:
                with self._build_lock(proj):
                    console.set_file_compiler(fp, source, own)
                    if flags_set:
                        console.set_file_flags(fp, source, own_flags or [])
                for u in units:
                    self._build_unit(proj, fp, u)
                why = (f"{', '.join(sorted(broken)[:8])} no longer match with it" if broken
                       else f"the file doesn't build with it:\n{_tail(log)}")
                raise NetworkError(f"{source} stays with {own}: {why}")
            self._commit_entry(proj, fp, rel, lambda: console.set_file_compiler(fp, source, compiler),
                               f"Build {source} with {compiler}\n\nChosen in decompdecomp's project settings.")
            if flags_set:
                self._commit_entry(proj, fp, flags_rel, lambda: console.set_file_flags(fp, source, list(flags)),
                                   f"Build {source} with {' '.join(flags) or 'the project flags alone'}\n\nChosen in "
                                   "decompdecomp's project settings.")
            self.net.bump_generation(proj["id"])  # (the file's compiler: earlier compiles aren't repeats any more)
            for u in units:  # (a file that doesn't build matches nothing: its functions are open again)
                scores = after[u.name] or {n: None for n in before[u.name]}
                self._keep_scores(proj, u, text, scores)
                self._apply_scores(proj, u.name, scores, text=text)
        self.net.filecompilers.settle(slug)  # (a suggestion for the files this one finishes is applied)

    def _best_diff(self, proj, fp: ForkProject, fn) -> dict:
        """objdiff's diff of a function's best attempt: written into its file like a try, built, and undone, so
        neither the source nor the object it built stays changed. Cached by what it was built from."""
        meta = self._meta(fn)
        unit = fp.unit(fn["unit"])
        # (with the renames made since: the old name of a global is undeclared now, and the best "didn't compile")
        source = self._with_renames(proj["slug"], fn, fn["best_source"])
        names = self._names(meta, fn)
        _, span = self._find(source, names)
        if span:  # the definition alone: a polishing comment above it isn't placed again
            source = source[span[0]:span[1]]
        symbol = meta.get("symbol") or fn["name"]
        linked = unit.complete and fp.linkable()
        try:
            with self._tree(proj).exclusive() if linked else self._tree(proj).shared(), \
                    self._unit_lock(proj, unit.name):
                _, after, path, before = self._place(proj, fp, unit, fn, source, names)
                existed = path.exists()
                target = unit.target.stat().st_mtime_ns if unit.target is not None and unit.target.exists() else None
                key = self.net.compile_key(fn, unit.name, source, after, before, str(target))
                if key in self._best_diffs:
                    return dict(self._best_diffs[key])
                _rewrite(path, after)
                try:
                    ok, log = self._build_unit(proj, fp, unit)
                    if not ok:
                        out = {"kind": "best", "rows": None,
                               "error": f"The best attempt didn't compile:\n{_tail(log)}"}
                    else:
                        d = fp.diff(unit, symbol)
                        if d.match_percent is None:
                            out = {"kind": "best", "rows": None}
                        else:
                            problems = [f"{_problem_kind(m)}: {m.describe()}" for m in d.literals]
                            problems += [f"refers to `{mine}` where the original refers to `{orig}`"
                                         for orig, mine in d.renamed]
                            out = {"kind": "best", "rows": [list(r) for r in d.rows], "score": None,
                                   "percent": _floor_pct(d.match_percent, d.matched), "problems": problems}
                finally:
                    if existed:
                        _rewrite(path, before)
                    else:  # a unit with no source file yet: leave none behind
                        path.unlink(missing_ok=True)
                    self._build_unit(proj, fp, unit)  # the file's object is its own source's again
        except NetworkError as e:
            return {"kind": "best", "rows": None, "error": str(e)}
        except (ObjdiffError, ForkError) as e:
            return {"kind": "best", "rows": None, "error": f"objdiff: {e}"}
        if len(self._best_diffs) > 32:
            self._best_diffs.pop(next(iter(self._best_diffs)))
        self._best_diffs[key] = out
        return dict(out)

    def function_diff(self, slug: str, name: str, which: str = "latest") -> dict:
        """objdiff's diff of the function as it is in the source tree now, or of its best attempt (`which`)."""
        proj, fp, cfg = self.get(slug)
        fn = self._fn(slug, name)
        meta = self._meta(fn)
        if which == "best" and fn["status"] != "matched":
            if not fn["best_source"]:
                return {"kind": "best", "rows": None,
                        "message": "There's no best attempt for this function yet."}
            return self._best_diff(proj, fp, fn)
        try:
            d = fp.diff(fp.unit(fn["unit"]), meta.get("symbol") or fn["name"])
        except (ObjdiffError, ForkError) as e:
            return {"kind": None, "rows": None, "error": f"objdiff: {e}"}
        if d.match_percent is None:
            return {"kind": None, "rows": None}
        problems = [f"{'a reference differs' if isinstance(m, MappingConflict) else 'a loaded constant differs'}: "
                    f"{m.describe()}" for m in d.literals]
        problems += [f"refers to `{mine}` where the original refers to `{orig}`" for orig, mine in d.renamed]
        return {"kind": "matched" if fn["status"] == "matched" else "latest", "rows": [list(r) for r in d.rows],
                "score": None, "percent": _floor_pct(d.match_percent, d.matched), "problems": problems}

    def function_detail(self, slug: str, name: str) -> dict:
        proj, fp, cfg = self.get(slug)
        fn = self._fn(slug, name)
        meta = self._meta(fn)
        unit = fp.unit(fn["unit"])
        asm, current, pct = "", None, None
        try:
            d = fp.diff(unit, meta.get("symbol") or fn["name"])
            asm, pct = d.target_asm(), (None if d.match_percent is None else _floor_pct(d.match_percent, d.matched))
        except (ObjdiffError, ForkError) as e:
            asm = f"(objdiff: {e})"
        if unit.source and (fp.root / unit.source).exists():
            text = (fp.root / unit.source).read_text(errors="replace", encoding="utf-8")
            _, span = self._find(text, self._names(meta, fn))
            current = text[span[0]:span[1]] if span else None
        attempts = self.net.store.all("SELECT t.score, t.created_at, a.name AS agent FROM attempts t LEFT JOIN agents a "
                                      "ON a.id=t.agent_id WHERE t.function_id=? ORDER BY t.id", fn["id"])
        notes = self.net.store.all("SELECT n.text, n.created_at, a.name AS agent FROM notes n LEFT JOIN agents a "
                                   "ON a.id=n.agent_id WHERE n.function_id=? ORDER BY n.id DESC LIMIT 10", fn["id"])
        best_source = fn["best_source"]
        best_code = best_source
        if best_source:
            _, span = self._find(best_source, self._names(meta, fn))
            if span:
                best_code = best_source[span[0]:span[1]]
        best_differs = (fn["status"] != "matched" and bool(best_source)
                        and (current is None or _digest(current) != _digest(best_code)))
        return {"name": fn["name"], "vram": fn["vram"] or 0, "rom_offset": 0, "size": fn["size"], "insns": fn["n_insns"],
                "status": fn["status"], "best": fn["best_score"], "best_differs": best_differs, "asm": asm,
                "unit": fn["unit"], **set_aside(fn),
                "source": current or best_source, "source_kind": "matched" if fn["status"] == "matched" else
                ("latest" if current else "best" if best_source else None),
                "match_percent": pct, "scores": [{"score": a["score"], "t": a["created_at"], "agent": a["agent"]} for a in attempts],
                "notes": [dict(n) for n in notes], "calls": [], "called_by": []}
