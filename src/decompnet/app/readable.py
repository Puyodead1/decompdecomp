"""Matched code made readable: real names, types and comments, and still byte for byte.

C that matches is often hard to read: func_002C73A8, arg0, var_v1, casts and odd orders that only exist so the
compiler emits the same bytes. People who port or mod a game need code they understand. So helpers can work on
matched functions too: rename what they can tell (rename_symbol), describe structs and constants in the shared header
(edit_context), and rewrite the function with good names, types and a comment saying what it does. A rewrite counts
only when the function still matches byte for byte; otherwise it's refused and the matching C stays. The project
shows two numbers: matched, and readable.

In project mode (GameCube, Wii, PC, DS, public decomps) the matching C is the project's own source file: a rewrite is
judged as any compile of a matched function is there (ForkEngine.attempt): kept and committed only when it still
matches and the file's other matched functions do too, else the file is put back as it was. The decomp is never left
broken by polishing.

Then each source file is tidied (project mode): once every function of the game's in it is readable, claim_readable
hands the file out with a list (the types it shares with other files in one header, fields and classes named, the
globals it still knows by address named, dead declarations gone, one naming style) and tidy_done says it's done.
Polishing one function at a time left an Xbox game's types as the first guesses were, declared again in three files,
with duplicate and unused declarations around them. Its edits go through edit_file, which keeps every match.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from pathlib import Path

from .. import addresses, cfields, scoring, structcheck, structs, tidy
from ..forks.project import ForkProject
from ..network import GAME_CODE, IN_BUILD, Agent, NetworkError
from .engine import layouts

CLAIM_SECONDS = 30 * 60
# The order polishing takes functions in (starred ones first): SMALL_INSNS to BIG_INSNS biggest first, where the logic
# people want to read is; then bigger ones, smallest first (a readable rewrite of 2,000 instructions is a project of
# its own, and they waited for good behind a ceiling of 400); then small ones, biggest first. Smallest first, polishing
# spent a session on empty functions in Mario Kart 64; a floor of 8 instructions then left 15 of a small Xbox game's 33
# functions with address names, constructors and getters among them, and nothing names a callee from its caller's
# polish. So every size comes, in that order.
SMALL_INSNS, BIG_INSNS = 8, 400
ORDER = (f"boost DESC, CASE WHEN n_insns > {BIG_INSNS} THEN 1 WHEN n_insns < {SMALL_INSNS} THEN 2 ELSE 0 END, "
         f"CASE WHEN n_insns > {BIG_INSNS} THEN n_insns ELSE -n_insns END")
POLISH_TRIES = 3  # a function taken up this often since it was last made readable, and still not readable, is skipped
# what polishing takes (claim) and what a polishing helper's session counts as left (agents.Manager._left): the game's
# own matched code that isn't readable yet and isn't given up on: one no rewrite kept matching was handed out again
# and again, to every helper, being the biggest. (TODO and GIVEN_UP each take one ?, the project's id, after the
# caller's own)
GIVEN_UP = ("SELECT p.detail FROM events p WHERE p.project_id=? AND p.kind='polish' AND p.id > COALESCE((SELECT "
            "MAX(r.id) FROM events r WHERE r.project_id=p.project_id AND r.kind='readable' AND r.detail=p.detail), 0) "
            f"GROUP BY p.detail HAVING COUNT(*) >= {POLISH_TRIES}")
TODO = f"status='matched' AND readable=0 AND {GAME_CODE} AND name NOT IN ({GIVEN_UP})"


ADDRESS_NAMING = 4  # what name_addresses tries (2: generated names too, 3: callbacks' casts, 4: a macro's reads and an address in arithmetic): tried again


def _digest(source: str) -> str:
    import hashlib

    return hashlib.sha1(f"{ADDRESS_NAMING}\n{source}".encode()).hexdigest()[:16]


def _left_as_it_is(name: str, without: str) -> str:
    """What a helper is told of a function or file it held that has had its tries: POLISH_TRIES counts every helper's
    tries, not this one's, so it says it was tried rather than you tried it (#108)."""
    return f"You held {name}; it was tried {POLISH_TRIES} times without {without}, so it's left as it is now.\n\n"


TIDY = """\
TIDY A FILE: {unit} ({source}). Every function of the game's in it is readable now; the file around them isn't
yet. Make it read like code a person wrote, one edit_file at a time: each edit must build and keep every match, or
it's undone. Find what else declares the same things with search_code (headers, other source files, a build's own
driver files) and read_file them.
1. Declarations in headers: the file declares nothing another file defines. Each function and global it uses from
   elsewhere is declared once, in a header in include/ for that part of the game (the one that declares its
   neighbours already, or a new one with an include guard), and the file #includes it; its own extern lines go. A
   struct, enum or class the same: one header, and each copy in other files replaced by an #include of it.{headers}
2. No names made of addresses: a struct C_<address> named for what the object is; fields like f28 or unk_c named for
   what the code does with them (guess_struct shows the layout and which functions use it: one struct per kind of
   object, shared through its header); globals D_... and functions func_... renamed with rename_symbol once
   read_data and read_file show what they are. A person's code has none of them.
3. Numbers that mean something: switch cases, type codes, flags and modes written as an enum (or #define) in the
   header, each named for what it means (`case SCRIPT_PLAY_SOUND:`). The compiler makes the same code for either.
4. Names: parameters and locals named for what they hold; code that is a class's method written as one,
   Class::method, where it still matches (in a C++ game); a function or global whose name doesn't fit what it does
   or holds renamed with rename_symbol. Calls as the callee is declared, with its own convention: no method call on
   a made-up object (`((Dst*)1)->draw(...)`) to put a value in a register.
5. Duplicate declarations, ones nothing uses, stray stubs: gone.
6. One naming style: the one most of the game uses.{language}
Then tidy_done("{unit}", summary): what you changed, in a sentence or two.{data}"""
REVIEW = """\
REVIEW A FILE: {unit} ({source}). It matches and was tidied. A match proves only the bytes: a field named and sized
wrong, an int that holds a float, a case's body under another case's name all compile to the same code. Read it
beside the game's code (get_function shows each function's original assembly) as a reviewer would, and check:
1. Structs: each field's offset, size and type against how this file's functions, and the others that take the same
   object, use it (guess_struct; search_code for the struct's other users). An array's element size against code
   that indexes it with a variable; one struct per kind of object, in one header.
2. Types: float where the code uses the FPU (fld, fstp), signed or unsigned as its compares and shifts say, a pointer
   where it's dereferenced, a struct pointer rather than an int.
3. Switches and conditions: each case's value and its body belong together, named (an enum) for what that body does.
4. Names and comments: each says what the code really does; a wrong one is worse than none.
5. Calls: the convention and the arguments each callee really takes; no tricks to put a value in a register (a method
   call on a made-up object, a number cast to a pointer).
Fix what's wrong with edit_file and rename_symbol (each edit must keep every match, or it's undone). Then
review_done("{unit}", findings, fixed): what you found and fixed (fixed=true), or that it all holds (fixed=false)."""
SELF_REVIEW = 30 * 60  # a file is reviewed by the helper that last tidied or reviewed it only this long after
# (seconds): a helper handed its own tidy back reviewed it 5 seconds later, with the same context, and found it fine
REVIEWS = 2  # reviews a file gets at most in a round: one that fixed something is reviewed once more, by another helper
# A call through a made-up object to put a value in ecx: `((Dst*)0x379)->draw_ui_quad(...)` (a PC game built with /Gr
# whose project wasn't: the function was __fastcall with that value as its first argument)
FAKE_THIS = re.compile(r"\(\s*\(\s*\w+\s*\*\s*\)\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*->\s*\w+\s*\(")

# The globals a file declares, read for its tidy brief: helpers named two getters of class-name strings "static
# data" though read_data was in their brief, and in the tidy's; what each one holds, given up front, can't be missed
EXTERN_DATA = re.compile(r"^[ \t]*extern\s+(?!\"C\")[^;(){}=]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;", re.M)
DATA_READ, DATA_SHOWN = 32, 40  # bytes read of each, globals listed at most


# A name made of an address, which no person writes: a struct C_0046C950 for the object a function takes, fields
# f28 and unk_c, globals D_06880AC8, functions func_0046C250 (Ghidra's FUN_/DAT_ too). A PC game's files were all
# "tidy" with them throughout (770 of 1,869 files), as the tidy job asked only for what was clear
PLACEHOLDER = re.compile(r"\b(?:[CD]_[0-9A-Fa-f]{8}|_?func_[0-9A-Fa-f]{8}|(?:FUN|DAT|PTR|LAB)_[0-9A-Fa-f]{6,8})\b"
                         r"|(?:->|(?<=[\w\])])\.)\s*(?:f|field_?|unk_?)(?:0x)?(?:[0-9a-f]*[0-9][0-9a-f]*|[0-9a-f])\b")
# (a field's hex has a digit, or is one letter: f28 and fc, not fade or feed)
EXTERN_LINE = re.compile(r"^[ \t]*extern\b(?!\s*\"C\"\s*\{)[^\n]*", re.M)  # a declaration a header should make
TIDY_ROUND = 2  # the version of the tidy job, in the project's config: files tidied before it are tidied again
# (2: headers instead of each file's externs, no names made of addresses, enums for the numbers, C for a game written
# in C: a PC game's 1,739 files were all "tidy" with none of that)


def placeholders(source: str) -> list[str]:
    """The names made of addresses in `source` (PLACEHOLDER), each once, in order."""
    return list(dict.fromkeys(m.group(0).lstrip("->.").strip() for m in PLACEHOLDER.finditer(source)))


# memory read through a cast and an offset: `*(unsigned int *)(tex + 0x2c)`, `*(short *)((char *)e + 8)`
OFFSET_READ = re.compile(r"\*\s*\(\s*[\w\s]+\*+\s*\)\s*\(\s*(?:\(\s*[\w\s]+\*+\s*\)\s*)?\w+\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)")
UNTYPED_READING = 4  # the version of reopen_untyped's reading, in the project's config (2: reads the header names,
# 3: through parameters the debug information types, 4: every read through an offset, types known or not)
# (4: a PC game with no debug information was "polished" through and through and still read `*(int*)(self + 0x58)`
# in every function: an agent can tell what a struct is from the code that uses it, as a person would)
EVERY_OFFSET = 4
LAYOUT_FUNCTIONS = 2  # functions whose code a guessed layout comes from, for reopen_untyped to polish again for it


class Readability:
    def reopen_untyped(self, slug: str, log=print, guesses: bool = False, dry: bool = False) -> int:
        """Matched functions made readable before polishing showed their types (the game's debug information, its
        callees' prototypes, the struct layouts the code says) whose C still reads memory through casts and offsets
        where there are types to use: polished again. On a 2000s Linux game 99 of the first 545 polished did,
        `*(unsigned int *)(tex + 0x2c)` for `Tex->flags` among them. Once per project (UNTYPED_READING), for the
        debug information's types: the layouts the code shows are guesses (about 4 in 5 of their fields fall in a
        real one, on a game whose debug information says), and a PC game had 239 of its 692 readable functions with
        one, so polishing those again (`guesses`) was the user's to ask for. Since EVERY_OFFSET every one still
        reading through an offset is, once, types known or not: the job asks for the structs the code shows."""
        proj = self.net.project_row(slug)
        done = self.net.cfg(proj).get("untyped_reading", 0)
        if (not guesses and done >= UNTYPED_READING) or self.net._link(slug):
            return 0
        fork = not self.net.is_rom(proj)
        rows = self.net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched' AND readable=1",
                                  proj["id"])
        again = []
        for fn in rows:
            try:
                source = self._matching_c(proj, fn)
            except (OSError, NetworkError):
                continue
            if not source or not OFFSET_READ.search(source):
                continue
            # (2: the reads the header names, which polishing now lists; the rest were polished again under 1 and
            # would only be again)
            if done < EVERY_OFFSET or self._named_reads(proj, fn, source) or (
                    guesses and self._worth_polishing_again(proj, fn, fork, guesses)):
                again.append(fn["id"])
        if dry:  # (how many: what the Polish launcher offers)
            return len(again)
        if again:
            with self.net.store.tx() as db:
                db.executemany("UPDATE functions SET readable=0 WHERE id=?", [(i,) for i in again])
        if not guesses:
            self.net._update_cfg(slug, lambda c: c.update(untyped_reading=UNTYPED_READING))
        if again:
            log(f"{slug}: {len(again)} readable functions read memory through casts and offsets where their types "
                "are known (the game's debug information, or the struct layouts its code shows): they're on the "
                "polishing list again")
        return len(again)

    def name_addresses(self, slug: str, log=print, only: set[str] | None = None) -> int:
        """Matched functions whose C writes addresses as numbers (`printf((char *)0x80aa0c0)`) given what the game
        holds there instead, each change kept only where the function still matches (addresses.py says why). ROM
        mode: a project-mode judge (objdiff) compares relocations by symbol, so its C can't match through a number.
        Each function's C is tried once (the project's config remembers what was left), so a start doesn't judge
        the same C again. `only`: these functions (an export). Returns how many functions changed."""
        proj = self.net.project_row(slug)
        if not self.net.is_rom(proj) or self.net._link(slug):
            return 0
        cfg = self.net.cfg(proj)
        tried = dict(cfg.get("addresses_tried") or {})
        rows = [r for r in self.net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched' AND "
                                              "matched_source IS NOT NULL", proj["id"])
                if (only is None or r["name"] in only) and addresses.numbers(r["matched_source"])
                and tried.get(r["name"]) != _digest(r["matched_source"])]
        if not rows:
            return 0
        program = self._program(proj)
        units = self.net._unit_contexts(proj["id"])
        changed = 0
        for fn in rows:
            header = self.net._context(proj["id"], self.net._effective_unit(fn, units))["header"]
            program.header = header
            try:
                source = self._named_addresses(proj, fn, header, program)
            except Exception:  # one function's trouble never stops the rest
                logging.getLogger(__name__).exception("naming %s's addresses failed", fn["name"])
                source = None
            if source is not None:
                with self.net.progress._project_lock(slug), self.net.store.tx() as db:
                    # (only if it's still the C it was: a helper may have polished it meanwhile)
                    cur = db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=? AND "
                                     "matched_source=?", (source, source, fn["id"], fn["matched_source"]))
                changed += cur.rowcount
            final = source or fn["matched_source"]
            if addresses.numbers(final):
                tried[fn["name"]] = _digest(final)
            else:
                tried.pop(fn["name"], None)
        self.net._update_cfg(slug, lambda c: c.update(addresses_tried=tried))
        if changed:
            log(f"{slug}: {changed} matched functions write the strings, constants, globals and functions they used "
                "as addresses by name now, and still match")
        return changed

    def repair_renamed(self, slug: str, log=print) -> list[str]:
        """Matched functions whose C still defines a name a rename gave up (a make_readable saved alongside the rename,
        before write_renamed): the rename applied to their C, kept where it matches. A Linux game's
        shmdRenderScrolledTex defined shmdRender__was and showed as no longer matching. Returns their names."""
        proj = self.net.project_row(slug)
        if not self.net.is_rom(proj) or self.net._link(slug):
            return []
        renames: dict[str, list[str]] = {}
        for e in self.net.store.all("SELECT detail FROM events WHERE project_id=? AND kind='rename' ORDER BY id",
                                    proj["id"]):
            m = re.fullmatch(r"(\w+) → (\w+)", e["detail"] or "")
            if m:
                renames.setdefault(m.group(2), []).append(m.group(1))
        fixed = []
        units = self.net._unit_contexts(proj["id"])
        for fn in self.net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched' AND "
                                     "matched_source IS NOT NULL", proj["id"]):
            source, name = fn["matched_source"], fn["name"]
            if name not in renames or re.search(rf"\b{re.escape(name)}\s*\(", source):
                continue
            old = next((o for o in reversed(renames[name]) if re.search(rf"\b{re.escape(o)}\s*\(", source)), None)
            if old is None:
                continue
            renamed = re.sub(rf"\b{re.escape(old)}\b", name, source)
            header = self.net._context(proj["id"], self.net._effective_unit(fn, units))["header"]
            if not self._still_matches(proj, fn, header, renamed):
                continue
            with self.net.progress._project_lock(slug), self.net.store.tx() as db:
                if db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=? AND matched_source=?",
                              (renamed, renamed, fn["id"], source)).rowcount:
                    fixed.append(name)
        if fixed:
            log(f"{slug}: {', '.join(fixed)} defined the name a rename gave up; renamed in their C too, and they match")
        return fixed

    def tidy_declarations(self, slug: str, log=print) -> dict:
        """ROM mode's tidy: the declarations matched functions make for themselves (a callee's prototype, a
        global's extern, a struct), moved into the shared header once (tidy.py says which), every function judged
        again with the new header and C. What a function then no longer matches with stays its own, and the plan is
        made again without it, until every one matches. Project mode tidies a file with a helper (TIDY A FILE);
        here every function's C is judged alone after one header, so the move is mechanical. Returns the counts."""
        proj = self.net.project_row(slug)
        if not self.net.is_rom(proj) or self.net._link(slug) or self.net._unit_contexts(proj["id"]):
            # (a project whose source files have headers of their own is left to them: which one a declaration
            # belongs in is the helpers' call)
            return {}
        for _ in range(3):  # (a helper's edit_context meanwhile: made again on top of it)
            ctx = self.net._context(proj["id"])
            rows = self.net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched' AND "
                                      "matched_source IS NOT NULL ORDER BY vram", proj["id"])
            # (the names a function needed its own copy of last time stay where they are: no round finds them again)
            keep: set[str] = set(self.net.cfg(proj).get("tidy_keep") or [])
            if not tidy.plan([dict(r) for r in rows], ctx["header"], keep).sources:
                return {}
            # (what doesn't match before is no tidy's doing: judged once, and left out)
            failing = {name for name, _ in self.net.regression_test(proj, ctx["header"], only=rows)}
            rows = [r for r in rows if r["name"] not in failing]
            functions = [dict(r) for r in rows]
            before = sum(len(tidy.items(f["matched_source"])) for f in functions)
            for _ in range(20):
                plan = tidy.plan(functions, ctx["header"], keep)
                if not plan.sources:
                    return {"declarations": before, "moved": 0, "left": before}
                header = plan.header(ctx["header"])
                broken = self.net.regression_test(proj, header, sources=plan.sources, only=rows)
                if not broken:
                    break
                names = {n for n, _ in broken}
                moved = {name for _, item in plan.moved for name in item.names}
                kept = len(keep)
                said = {name: set(re.findall(r"(?:conflicting types for|redefinition of|redeclaration of|previous "
                                             r"declaration of) [`']([\w ]+)'", why)) for name, why in broken}
                for f in functions:  # what the compiler names (a callee's prototype the callers agreed on, which its
                    if f["name"] in names:  # own definition contradicts); else what it declares itself, if it moved;
                        named = {n for n in moved if n in said.get(f["name"], ()) or n.split()[-1] in said.get(f["name"], ())}
                        own = {name for item in tidy.items(f["matched_source"]) for name in item.names} & moved
                        used = {n for n in moved if re.search(rf"\b{re.escape(n.split()[-1])}\b", f["matched_source"])}
                        keep |= named or own or used  # else what it uses that moved (a prototype it now sees)
                if len(keep) == kept:  # (nothing to put back: the header alone broke them)
                    keep |= moved
            else:
                return {}
            with self.net.progress._project_lock(slug), self.net.store.tx() as db:
                if self.net._latest_version(db, proj["id"], "") != ctx["version"]:
                    continue
                version = self.net._next_version(db, proj["id"])
                message = f"tidy: {len(plan.moved)} declarations the functions made for themselves, gathered here"
                db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                           "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, header, None, message, time.time(), ""))
                for f in functions:
                    if f["id"] in plan.sources:
                        db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=? AND "
                                   "matched_source=?", (plan.sources[f["id"]], plan.sources[f["id"]], f["id"],
                                                        f["matched_source"]))
                self.net._event(db, proj["id"], None, "context", f"v{version}: {message}")
            kept_names = sorted(keep)
            self.net._update_cfg(slug, lambda c, k=kept_names: c.update(tidy_keep=k))
            left = sum(len(tidy.items(plan.sources.get(f["id"], f["matched_source"]))) for f in functions)
            log(f"{slug}: {len(plan.moved)} declarations matched functions made for themselves are in the shared "
                f"header now ({before} before, {left} left in the functions' files), and every function still matches")
            return {"declarations": before, "moved": len(plan.moved), "left": left, "functions": len(plan.sources)}
        return {}

    def _program(self, proj):
        segments = self.net._rom(proj)[1]

        symbols = self.net.symbols(proj["id"])
        # uninitialised data has no bytes in the image, so no segment: its symbols say where it is
        bss = [(s.address, s.address + max(s.size, 1)) for s in symbols.by_name.values() if s.kind == "bss"]
        lo, hi = (min(a for a, _ in bss), max(b for _, b in bss)) if bss else (0, 0)

        def section(address: int) -> str | None:
            found = next((s.name for s in segments if s.contains(address)), None)
            return found or (".bss" if lo <= address < hi else None)
        return addresses.Program(self.net.reader(proj), section, symbols, "",
                                 bool(self.net.cfg(proj).get("big_endian", True)))

    def _named_addresses(self, proj, fn, header: str, program) -> str | None:
        """`fn`'s matched C with what of its addresses still matches named, or None (none did)."""
        source = fn["matched_source"]
        found = addresses.proposals(source, program)
        if not found:
            return None
        matches = lambda chosen: self._still_matches(proj, fn, header, addresses.apply(source, chosen))
        if matches(found):
            return addresses.apply(source, found)
        kept: list = []
        for p in found:  # one at a time, each on top of those kept (a folded constant, a merged string's order),
            for choice in (p, p.fallback):  # else as its generated name
                if choice is not None and matches(kept + [choice]):
                    kept.append(choice)
                    break
        return addresses.apply(source, kept) if kept else None

    def _still_matches(self, proj, fn, header: str, source: str) -> bool:
        result = self.net._compile(proj, header, source, fn)
        if not result.ok:
            return False
        cand, verdict, _ = self.net._evaluate(fn, proj, result.obj)
        if cand is None:
            return False
        return scoring.diff(self.net._target_obj(fn, proj), cand).bytes_match if verdict is None else bool(verdict)

    def __init__(self, net):
        self.net = net
        self._tidying: dict[tuple[int, str], tuple[int, float]] = {}  # (project, unit) -> (agent, until)
        self._tidy_lock = threading.Lock()  # (helpers claim at once: one file, one helper)
        self._named_asked: set[int] = set()  # functions whose rewrite was sent back once for reads the header names
        self._offsets_asked: set[int] = set()  # ... and once for reads through offsets no header names yet
        self._placeholders_asked: set[int] = set()  # ... and once for names made of addresses
        self._tidy_asked: set[tuple[int, str]] = set()  # files whose tidy_done was sent back once for what's left
        self._reviewing: dict[tuple[int, str], tuple[int, float]] = {}  # (project, unit) -> (agent, until)

    def _untidy(self, proj) -> list[str]:
        """The project's source files (units) to tidy, most functions first: every function of the game's in them
        readable, none tidied yet, and not given up on (POLISH_TRIES tidy jobs without tidy_done). Project mode only:
        a ROM project's C is the database's, one function at a time."""
        if self.net.is_rom(proj):
            return []
        since = self._tidy_since(proj)
        rows = self.net.store.all(
            "SELECT unit, COUNT(*) AS n FROM functions WHERE project_id=? AND unit != '' AND "
            f"{GAME_CODE} AND {IN_BUILD} GROUP BY unit HAVING SUM(status='matched' AND readable=1) = COUNT(*) "
            "AND unit NOT IN (SELECT detail FROM events WHERE project_id=? AND kind='tidied' AND created_at >= ?) "
            "AND unit NOT IN (SELECT detail FROM events WHERE project_id=? AND kind='tidy' AND created_at >= ? "
            f"GROUP BY detail HAVING COUNT(*) >= {POLISH_TRIES}) ORDER BY n DESC, unit",
            proj["id"], proj["id"], since, proj["id"], since)
        return [r["unit"] for r in rows]

    def _tidy_since(self, proj) -> float:
        """When this round of tidying began (retidy): files tidied before it are tidied again."""
        # (the project's row as it is now: a row read before retidy began the round has the old config)
        return float(self.net.cfg(self.net.project_row(proj["slug"])).get("tidy_since") or 0)

    def retidy(self, slug: str, log=print) -> bool:
        """Every file tidied before the tidy job asked what it asks now (TIDY_ROUND) on the tidying list again, once
        per project: a PC game's files were all "tidy" with each declaring its own externs, structs named C_<address>
        with fields f28, and D_/func_ names throughout. Project mode only (ROM mode tidies declarations itself)."""
        proj = self.net.project_row(slug)
        if self.net.is_rom(proj) or self.net._link(slug):
            return False
        if self.net.cfg(proj).get("tidy_round", 0) >= TIDY_ROUND:
            return False
        tidied = self.net.store.one("SELECT COUNT(DISTINCT detail) AS n FROM events WHERE project_id=? AND "
                                    "kind='tidied'", proj["id"])["n"]
        now = time.time()
        self.net._update_cfg(slug, lambda c: c.update(tidy_round=TIDY_ROUND, tidy_since=now))
        if tidied:
            log(f"{slug}: the {tidied} files tidied so far are on the tidying list again: headers instead of each "
                "file's own declarations, names for what was still known by address, enums for the numbers that "
                "mean something")
        return bool(tidied)

    def _file_given_up(self, proj, unit: str) -> bool:
        """Whether a file was handed out POLISH_TRIES times without being tidied (rather than tidied while held)."""
        row = self.net.store.one(
            "SELECT SUM(kind='tidy') AS tried, SUM(kind='tidied') AS tidied FROM events "
            "WHERE project_id=? AND detail=? AND kind IN ('tidy', 'tidied') AND created_at >= ?", proj["id"], unit,
            self._tidy_since(proj))
        return (row["tried"] or 0) >= POLISH_TRIES and not row["tidied"]

    def _matching_c(self, proj, fn) -> str:
        """The C a matched function matches with: the database's in a ROM project, its source file's in a fork."""
        if self.net.is_rom(proj):
            return fn["matched_source"] or ""
        return (self.net.forks._current_source(ForkProject(Path(proj["root"])), fn, comment=True)
                or fn["matched_source"] or "")

    def counts(self, proj) -> dict:
        """The game's own code only (GAME_CODE): library code set aside is out of progress, so out of polishing too."""
        row = self.net.store.one("SELECT SUM(status='matched') AS matched, SUM(status='matched' AND readable=1) AS readable "
                                 f"FROM functions WHERE project_id=? AND {GAME_CODE}", proj["id"])
        return {"matched": row["matched"] or 0, "readable": row["readable"] or 0}

    def left(self, proj) -> int:
        """How many functions polishing can still take, held ones included, and files to tidy: a polishing helper
        stops at none (a game with nothing left to decompile stopped its polishing helpers before they began)."""
        return self.net.store.one(f"SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND {TODO}",
                                  proj["id"], proj["id"])["n"] + len(self._untidy(proj)) + len(self._unreviewed(proj))

    def _tidy_job(self, agent: Agent, proj) -> tuple[str | None, str | None]:
        """A file to tidy for this agent (the one it holds, or the next nobody does), and the file it held that was let
        go, if any."""
        now = time.time()
        left = None
        with self._tidy_lock:
            self._tidying = {k: v for k, v in self._tidying.items() if v[1] > now}
            mine = next((u for (pid, u), (who, _) in self._tidying.items() if pid == proj["id"] and who == agent.id),
                        None)
            untidy = self._untidy(proj)
            if mine is not None and mine not in untidy:
                # its tries are up, or it was tidied while held: the next file, as a function given up on or made
                # readable while held is let go (#108)
                del self._tidying[(proj["id"], mine)]
                left = mine if self._file_given_up(proj, mine) else None
                mine = None
            if mine is None:
                held = {u for (pid, u) in self._tidying if pid == proj["id"]}
                mine = next((u for u in untidy if u not in held), None)
                if mine is None:
                    return None, left
            # taking a held file up again is a try too: one a helper never finished got it back every claim without a
            # try against it, so it never left and left() never reached 0, as a function did before #108
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id, "tidy", mine)
            self._tidying[(proj["id"], mine)] = (agent.id, now + CLAIM_SECONDS)
        fp = ForkProject(Path(proj["root"]))
        source = next((u.source for u in fp.units() if u.name == mine), None) or mine
        language = self._in_c(proj, fp, source)
        headers = ("\n   While the game's files are C and C++ both, a header wraps its declarations in `#ifdef __cplusplus` "
                   "`extern \"C\" {` `#endif` (and the closing one), so either includes it." if language else "")
        return TIDY.format(unit=mine, source=source, data=self._data_held(agent, proj, fp, source),
                           language=language, headers=headers), left

    def _in_c(self, proj, fp: ForkProject, source: str) -> str:
        """The tidy job's step for a C++ file of a game written in C (Console.game_language): a debug-built Visual
        C++ 6.0 game whose Rich header says 208 files of C and 2 of C++ was made a project of .cpp files, and its
        agents' C had extern "C" on every declaration and one-method classes for its __fastcall calls. '' else."""
        if not source.endswith((".cpp", ".cc", ".cxx")):
            return ""
        try:
            from .. import consoles

            language = consoles.get(self.net.cfg(proj).get("platform")).game_language(fp)
        except Exception:  # (help for the job, never in its way)
            return ""
        if language != "c":
            return ""
        return ("\n6. Language: the game was written in C (its build record says so), and this file is C++. Write it as "
                "C: no extern \"C\", no classes (a function that takes its object in ecx is __fastcall, with an "
                "unused second argument in edx), no references, declarations at the start of each block (Visual C++'s "
                f"C is C89), then set_file_language(\"{source}\", \"c\"): it's kept only if every match still "
                "matches; where one doesn't, leave the file C++.")

    def _data_held(self, agent: Agent, proj, fp: ForkProject, source: str) -> str:
        """What the globals a source file declares hold in the original (read_data's summary of each), for its tidy
        brief; '' when there's nothing to tell."""
        try:
            text = (fp.root / source).read_text(errors="replace", encoding="utf-8")
        except OSError:
            return ""
        lines = []
        for name in list(dict.fromkeys(EXTERN_DATA.findall(text)))[:DATA_SHOWN]:
            try:
                said = self.net.forks.read_data(agent, proj["slug"], name, DATA_READ)
            except Exception:  # not data the console can read (a name it doesn't know, no copy of the game)
                continue
            rows = said.splitlines()
            # a string before floats: read_data lists floats first, and text reads as floats too ("spark" did)
            told = next((r for r in rows if r.startswith("as a string:")), None) or \
                next((r for r in rows if r.startswith("as f32:")), None)
            told = told or (rows[0].split(": ", 1)[1] if rows and ": " in rows[0] else rows[1].strip() if len(rows) > 1 else "")
            if told:
                lines.append(f"   {name}: {told}")
        if not lines:
            return ""
        return "\n\nWhat the globals it declares hold in the original (read_data; check names against these):\n" + \
            "\n".join(lines)

    def tidy_done(self, agent: Agent, slug: str, unit: str, summary: str) -> str:
        """An agent's tidy of a file, done: recorded with what it changed (its edits were kept by edit_file only while
        every match held, so the file still matches)."""
        proj = self.net._project(slug)
        if not summary.strip():
            raise NetworkError("say what you changed in the summary, in a sentence or two")
        left = self._untidy_left(proj, unit)
        if left and (proj["id"], unit) not in self._tidy_asked:
            with self._tidy_lock:
                held = self._tidying.get((proj["id"], unit))
                if held is not None and held[0] == agent.id and held[1] > time.time():
                    self._tidy_asked.add((proj["id"], unit))
                    return ("✋ Not tidy yet:\n" + "\n".join(f"- {line}" for line in left) + "\nFix these with "
                            f"edit_file and rename_symbol, then tidy_done(\"{unit}\", summary) again. Where one "
                            "really can't be (it breaks a match), say why in the summary and send it again: it's "
                            "taken as it is.")
        # under the lock and only while the claim lasts: a helper whose claim had run out could mark tidy a file
        # _tidy_job had given to another helper since, whose edits then landed in a file already counted tidy (#89)
        with self._tidy_lock:
            held = self._tidying.get((proj["id"], unit))
            if held is None or held[0] != agent.id or held[1] <= time.time():
                raise NetworkError(f"you aren't tidying {unit}: claim_readable gives you a file to tidy")
            del self._tidying[(proj["id"], unit)]
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], agent.id, "tidied", unit)
            self.net._event(db, proj["id"], agent.id, "tidy_summary", f"{unit}: {summary.strip()[:500]}")
        return f"✅ {unit} is tidy. claim_readable for the next one."

    def _unreviewed(self, proj) -> list[str]:
        """The files tidied this round still to review (REVIEW), most recently tidied last: none reviewed as holding
        yet, fewer than REVIEWS reviews, and not given up on (POLISH_TRIES hand-outs per review). Project mode only,
        as tidying is."""
        if self.net.is_rom(proj):
            return []
        since = self._tidy_since(proj)
        rows = self.net.store.all(
            "SELECT detail AS unit, SUM(kind='reviewed') AS reviews, SUM(kind='review') AS tries, "
            "SUM(kind='review_clean') AS clean, SUM(kind='tidied') AS tidied, MAX(id) AS last FROM events "
            "WHERE project_id=? AND kind IN ('tidied', 'review', 'reviewed', 'review_clean') AND created_at >= ? "
            "GROUP BY detail ORDER BY MIN(id)", proj["id"], since)
        return [r["unit"] for r in rows if r["tidied"] and not r["clean"] and r["reviews"] < REVIEWS
                and r["tries"] < POLISH_TRIES * REVIEWS]

    def _own_fresh(self, proj, unit: str, agent: Agent) -> bool:
        """Whether this helper tidied or reviewed the file last, less than SELF_REVIEW ago: its review is another
        helper's then (fresh eyes), or its own later."""
        row = self.net.store.one("SELECT agent_id, created_at FROM events WHERE project_id=? AND detail=? AND kind IN "
                                 "('tidied', 'reviewed') ORDER BY id DESC LIMIT 1", proj["id"], unit)
        return row is not None and row["agent_id"] == agent.id and time.time() - row["created_at"] < SELF_REVIEW

    def _review_job(self, agent: Agent, proj) -> str | None:
        """A tidied file to review for this agent (the one it holds, or the next nobody does that it didn't just tidy
        or review itself), or None."""
        now = time.time()
        with self._tidy_lock:
            self._reviewing = {k: v for k, v in self._reviewing.items() if v[1] > now}
            todo = self._unreviewed(proj)
            mine = next((u for (pid, u), (who, _) in self._reviewing.items() if pid == proj["id"] and who == agent.id),
                        None)
            if mine is not None and mine not in todo:
                del self._reviewing[(proj["id"], mine)]
                mine = None
            if mine is None:
                held = {u for (pid, u) in self._reviewing if pid == proj["id"]}
                free = [u for u in todo if u not in held]
                mine = next((u for u in free if not self._own_fresh(proj, u, agent)), None)
                if mine is None:
                    return None
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id, "review", mine)
            self._reviewing[(proj["id"], mine)] = (agent.id, now + CLAIM_SECONDS)
        fp = ForkProject(Path(proj["root"]))
        source = next((u.source for u in fp.units() if u.name == mine), None) or mine
        return REVIEW.format(unit=mine, source=source)

    def review_done(self, agent: Agent, slug: str, unit: str, findings: str, fixed: bool) -> str:
        """An agent's review of a tidied file: what it found and whether it fixed anything. A file whose review fixed
        something is reviewed again (REVIEWS), preferably by another helper; one whose review found it holds is done."""
        proj = self.net._project(slug)
        if not findings.strip():
            raise NetworkError("say what you found in findings: what was wrong and what you fixed, or that it holds")
        with self._tidy_lock:
            held = self._reviewing.get((proj["id"], unit))
            if held is None or held[0] != agent.id or held[1] <= time.time():
                raise NetworkError(f"you aren't reviewing {unit}: claim_readable gives you a file to review")
            del self._reviewing[(proj["id"], unit)]
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], agent.id, "reviewed", unit)
            if not fixed:
                self.net._event(db, proj["id"], agent.id, "review_clean", unit)
            self.net._event(db, proj["id"], agent.id, "review_summary", f"{unit}: {findings.strip()[:800]}")
        return f"✅ {unit} reviewed. claim_readable for the next one."

    def _untidy_left(self, proj, unit: str) -> list[str]:
        """What a file still has that the tidy job asks to be gone: names made of addresses, its own extern
        declarations, C++ in a game written in C. [] when it's tidy, or the file can't be read."""
        try:
            fp = ForkProject(Path(proj["root"]))
            source = next((u.source for u in fp.units() if u.name == unit), None)
            if source is None:
                return []
            text = (fp.root / source).read_text(errors="replace", encoding="utf-8")
        except OSError:
            return []
        left = []
        names = placeholders(text)
        if names:
            left.append(f"names made of addresses: {', '.join(names[:16])}{', ...' if len(names) > 16 else ''} "
                        "(rename_symbol the globals and functions; name the structs and fields for what they are)")
        externs = EXTERN_LINE.findall(text)
        if externs:
            left.append(f"{len(externs)} extern declarations of its own (`{externs[0].strip()}`...): declare them in "
                        "a header in include/ and #include it")
        fakes = sorted({m.group(0) for m in FAKE_THIS.finditer(text)})
        if fakes:
            left.append(f"calls through a made-up object to put a value in a register (`{fakes[0]}...)`): declare the "
                        "callee with its real convention and arguments and call it as a function")
        try:
            left += [f"two copies of one struct disagree, {c} (they can't both be right: the code that uses it says "
                     "which; keep one, in a header)" for c in structcheck.conflicts(fp.root, source)]
        except Exception:  # (a check over the project's text: never in the way)
            logging.getLogger("decompdecomp").exception("the struct check of %s", source)
        if self._in_c(proj, fp, source):
            left.append(f"it's C++ and the game was written in C: write it as C and set_file_language(\"{source}\", "
                        "\"c\")")
        return left

    def claim(self, agent: Agent, slug: str) -> str:
        """The next matched function that isn't readable yet, held for this agent, with what it needs to know."""
        proj = self.net._project(slug)
        fork = not self.net.is_rom(proj)
        now = time.time()
        with self.net.store.tx() as db:
            self.net._expire_claims(db)
            self.net._drop_dead_claims(db, agent.id, ("open", "matched"))  # #283: set aside while it held it
            held = db.execute("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=?",
                              (agent.id,)).fetchone()
            fn = held if held is not None and held["status"] == "matched" else None
            if held is not None and fn is None:
                raise NetworkError(f"you hold {held['name']}; match it or release_function it first")
            left = None
            if fn is not None:
                # taking a held function up again is a try too: a helper whose every rewrite of one failed to compile
                # kept its claim (each compile renewed it) and got it back each session, 174 times in an afternoon on
                # an Xbox game, as only a new claim counted
                if db.execute(f"SELECT 1 FROM functions WHERE id=? AND {TODO}", (fn["id"], proj["id"])).fetchone():
                    self.net._event(db, proj["id"], agent.id, "polish", fn["name"])
                else:  # its tries are up, or it was set aside or made readable while held: the next one
                    db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
                    tried = db.execute(f"SELECT 1 WHERE ? IN ({GIVEN_UP})", (fn["name"], proj["id"])).fetchone()
                    left, fn = fn["name"] if tried else None, None
            if fn is None:
                # in ORDER. The game's own code: an Xbox game's matched SDK functions, set aside, would have been
                # polished with its 33
                fn = db.execute(f"SELECT * FROM functions WHERE project_id=? AND {TODO} "
                                f"AND id NOT IN (SELECT function_id FROM claims) ORDER BY {ORDER} LIMIT 1",
                                (proj["id"], proj["id"])).fetchone()
                if fn is not None:
                    db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + CLAIM_SECONDS))
                    self.net._event(db, proj["id"], agent.id, "polish", fn["name"])  # not "claim": the feed and routing tell them apart
        given_up = _left_as_it_is(left, "a rewrite that kept it matching") if left else ""
        if fn is None:
            if fork:  # every function done: the files next
                # a file tidied is reviewed first, while its tidy is fresh: with reviews last, a game's 1,736 files
                # would all be tidied before any review could say what its tidies get wrong
                job = self._review_job(agent, proj)
                if job is not None:
                    return given_up + job
                job, file_left = self._tidy_job(agent, proj)
                if file_left:
                    given_up += _left_as_it_is(file_left, "being tidied")
                if job is not None:
                    return given_up + job
            if self.left(proj):  # what's left is held by other helpers
                return given_up + self._held_by_others(proj)
            return (given_up + "Every matched function is readable already (or was tried "
                    f"{POLISH_TRIES} times without staying matched), and every file tidy. 🎉 Stop here: nothing is "
                    "left to polish.")
        counts = self.counts(proj)
        where = f" at 0x{fn['vram']:08X}" if fn["vram"] is not None else f" in {fn['unit']}"
        names = ("- rename_symbol the function, and the globals and functions it uses, once their purpose is clear "
                 "(read_file and search_code show what it calls and what calls it);\n"
                 "- describe structs, enums and constants in the project's headers (edit_file) and use their names here;\n"
                 if fork else
                 "- rename_symbol the function, and the globals and functions it uses, once their purpose is clear;\n"
                 "- describe structs, enums and constants in the shared header (edit_context) and use their names here;\n")
        # helpers named two getters of class names "static data" without looking at what the globals held, and each
        # picked its own style (Shape3_Init, Shape2_init, vec3_dot_product)
        # every job, debug information or not: polished C that still read `*(int*)(self + 0x58)` throughout a PC game
        # without debug information wasn't readable, and the code says what each field is as well as a symbol would
        names += ("- no reads or writes through casts and offsets (`*(int*)(self + 0x58)`): work out what the pointer "
                  "points to from how this function and the others that take it use it (guess_struct gives the "
                  "offsets and sizes the code uses), declare that struct "
                  + ("in a header in include/" if fork else "in the shared header") +
                  " with a field named for each use and `char pad_XX[n]` for the gaps, and write `self->field`. The "
                  "compiler makes the same code for a field as for its offset; extend a struct that's declared "
                  "already rather than making a second one;\n")
        names += ("- no names made of addresses: a struct C_<address> named for what the object is, fields like f28 or "
                  "unk_c named for what the code does with them, globals D_... and functions func_... it uses renamed "
                  "with rename_symbol; numbers that mean something (switch cases, type codes, flags) as an enum;\n")
        names += ("- read_data a global before you name it: what it holds (a string, a table, a constant) says what it "
                  "is;\n- name things in the style the names around them already use.\n")
        # The game's own types for it and what it calls: polished C kept `int tex` and `*(unsigned int *)(tex + 0x2c)`
        # for the debug information's `tex *Tex` and `Tex->flags`, because the job never showed them
        # Without debug information, the struct layouts the code itself says (structs.py: its arguments', what it
        # returns, what its calls return) are the same help
        known = self._types_known(proj, fn, fork)
        named = self._named_reads(proj, fn, self._matching_c(proj, fn))
        if named:
            known += ["", "### Reads through offsets that the header names", *named,
                      "Write each by name (`pModel->Geometries[i].geometries`): a field read compiles to the same code "
                      "as the offset it's at."]
        if known:
            names += ("- use the types below (the game's debug information's, or the layouts its code shows): struct "
                      "pointers and their fields by name instead of ints, casts and offsets, declared in the shared "
                      "header so every function uses them;\n")
        return (f"{given_up}MAKE READABLE: {fn['name']}{where}, {fn['n_insns']} instructions "
                f"({counts['readable']} of {counts['matched']} matched functions are readable so far).\n\n"
                f"It matches today with this C:\n```c\n{self._matching_c(proj, fn).strip()}\n```\n"
                + ("\n".join(known) + "\n" if known else "") + "\n"
                "Make it readable without changing what the compiler makes of it:\n" + names +
                "- give parameters and locals meaningful names; write one comment saying what the function does;\n"
                "- keep the statements' shape: the order, the casts and the temporaries that make it match.\n"
                + ("- it's a big function: rename and comment in place, statement for statement; don't restructure it "
                   "(one slip anywhere in it and the rewrite is refused).\n" if fn["n_insns"] > BIG_INSNS else "") +
                f"Then make_readable(\"{fn['name']}\", source). It's judged again: it must still match byte for byte, or "
                "it's refused and the matching C stays.")

    def _worth_polishing_again(self, proj, fn, fork: bool, guesses: bool = False) -> bool:
        """Whether there are types to polish a function's offsets into: the game's debug information (its own types
        or its callees'), or a struct layout the code of at least LAYOUT_FUNCTIONS functions shows (one function's
        loads say little more than its offsets already do: on a PC game, half the 692 readable functions had such a
        guess, most of one function's)."""
        try:
            if not fork and (self.net._debug_brief(fn, proj) or self.net._callee_brief(fn, proj)):
                return True
            if fork:
                _, fp, cfg = self.net.forks.get(proj["slug"])
                if self.net.forks._debug_brief(fp, cfg, fn):
                    return True
                if not guesses:
                    return False
                found = self.net.forks._structs(fp, cfg)
                addr = found.symbols.get(self.net.forks._meta(fn).get("symbol") or fn["name"]) if found else None
            else:
                if not guesses:
                    return False
                found = self.net.structs(proj)
                addr = fn["vram"]
            if found is None or addr is None:
                return False
            kinds = [(structs.ARGUMENT, addr, n) for n in layouts.BRIEF_ARGUMENTS] + [(structs.RETURN, addr)]
            types = [found.type_of(k) for k in kinds] + [t for _, t in found.results_in(addr)]
            return any(len(found.layout(t).functions) >= LAYOUT_FUNCTIONS for t in types if t is not None)
        except Exception:  # (a heuristic over the game's code: never in the way)
            logging.getLogger("decompdecomp").exception("the types for %s", fn["name"])
            return False

    def _named_reads(self, proj, fn, source: str) -> list[str]:
        """The reads `source` makes through a byte pointer and an offset that the function's header names
        (cfields.py)."""
        if not source or not cfields.READ.search(source):
            return []
        try:
            if self.net.is_rom(proj):
                ctx = self.net._context(proj["id"], fn["unit"])
                header = ctx["header"] if ctx else ""
            else:
                header = self.net.forks.permuter_header(proj["slug"], fn["name"])
            return cfields.named_reads(source, header, self._debug_parameters(fn, source))
        except Exception:  # (help for the job, never in its way)
            logging.getLogger("decompdecomp").exception("the named reads of %s", fn["name"])
            return []

    @staticmethod
    def _debug_parameters(fn, source: str) -> dict[str, str]:
        """The structs the debug information's prototype says the parameters point to, by the names the matched C
        gives them: `void mdDetach(undefined4 param_1, int param_2)` with `void mdDetach(TModel *pModel, TObject
        *pObj)` is {"param_1": "TModel", "param_2": "TObject"}."""
        try:
            meta = json.loads(fn["meta"] or "{}") if "meta" in fn.keys() else {}
        except ValueError:
            return {}
        prototype = (meta.get("debug") or {}).get("prototype") or ""
        name = re.search(r"(\w+)\s*\(", prototype)
        if not name:
            return {}
        real = structs.parameter_types(prototype + " {", name.group(1))
        m = re.search(rf"\b{re.escape(fn['name'])}\s*\(([^()]*)\)\s*\{{", source)
        if not m:
            return {}
        names = [re.findall(r"\w+", p)[-1] if re.findall(r"\w+", p) else "" for p in m.group(1).split(",")]
        out = {}
        for var, ctype in zip(names, real):
            if var and (struct := structs.type_name(ctype)):
                out[var] = struct
        return out

    def _types_known(self, proj, fn, fork: bool) -> list[str]:
        """The brief's lines on the function's types: its debug information and its callees' (ROM mode), and the
        struct layouts its code and the game's say (both modes)."""
        try:
            if fork:
                _, fp, cfg = self.net.forks.get(proj["slug"])
                return self.net.forks._debug_brief(fp, cfg, fn) + self.net.forks._struct_brief(fp, cfg, fn)
            return self.net._debug_brief(fn, proj) + self.net._callee_brief(fn, proj) + self.net._struct_brief(fn, proj)
        except Exception:  # (help for the job, never in its way)
            logging.getLogger("decompdecomp").exception("the types for %s's polishing job", fn["name"])
            return []

    def _held_by_others(self, proj) -> str:
        """claim's answer when everything left to polish is held by other helpers: come back later, not stop. Told to
        stop, a helper left for good, and a function or file whose holder's claim then ran out had nobody to take it
        (#89)."""
        now = time.time()
        held = [(r["name"], r["agent"], r["expires_at"]) for r in self.net.store.all(
            "SELECT f.name, a.name AS agent, c.expires_at FROM claims c "
            f"JOIN (SELECT id, name FROM functions WHERE project_id=? AND {TODO}) f ON f.id=c.function_id "
            "LEFT JOIN agents a ON a.id=c.agent_id", proj["id"], proj["id"])]
        with self._tidy_lock:
            files = [(u, who, until) for (pid, u), (who, until) in [*self._tidying.items(), *self._reviewing.items()]
                     if pid == proj["id"] and until > now]
        for unit, who, until in files:
            row = self.net.store.one("SELECT name FROM agents WHERE id=?", who)
            held.append((f"the file {unit}", row["name"] if row else None, until))
        held.sort(key=lambda h: h[2])
        shown = ", ".join(f"{name} ({who or '?'}, {max(0, int(until - now)) // 60} min left)"
                          for name, who, until in held[:10])
        return (f"Nothing to take right now: what's left to polish is held by other helpers: {shown}"
                f"{', ...' if len(held) > 10 else ''}. Each is free again when its helper finishes it or its claim "
                "runs out: call claim_readable again later. Don't stop.")

    def submit(self, agent: Agent, slug: str, function: str, source: str) -> str:
        """An agent's readable rewrite of a matched function: kept only when it still matches byte for byte."""
        with self.net.progress.judging(slug):
            return self._submit(agent, slug, function, source)

    def _submit(self, agent: Agent, slug: str, function: str, source: str) -> str:
        proj = self.net._project(slug)
        fn = self.net._function(function, proj["slug"])
        if fn["status"] != "matched":
            raise NetworkError(f"{fn['name']} isn't matched yet: compile_and_diff it first")
        claim = self.net.store.one("SELECT agent_id FROM claims WHERE function_id=?", fn["id"])
        if claim is not None and claim["agent_id"] != agent.id:
            raise NetworkError(f"{fn['name']} is held by {self.net._agent_name(claim['agent_id'])}")
        if " ".join(source.split()) == " ".join(self._matching_c(proj, fn).split()):
            raise NetworkError("that's the C it has already: rename, type and comment it first")
        # Once per function: a helper polished every other field into its name and left `*(char ***)((char *)pModel
        # + 0x40)` for pModel->Geometries, twice, though the job listed the types. A second time it's judged as it
        # is: the named form may not have matched
        named = self._named_reads(proj, fn, source)
        if named and fn["id"] not in self._named_asked:
            self._named_asked.add(fn["id"])
            self._offsets_asked.add(fn["id"])  # (sent back once, for either)
            return ("✋ Not judged yet: it still reads through offsets that the header names:\n" + "\n".join(named)
                    + "\nWrite them by name (a field read compiles to the same code as its offset), then "
                    f"make_readable(\"{fn['name']}\", source) again. If the named form doesn't match, send this one "
                    "again and it's judged as it is.")
        # Once per function too: reads through offsets with no struct at all, whatever the header has
        if OFFSET_READ.search(source) and fn["id"] not in self._offsets_asked:
            self._offsets_asked.add(fn["id"])
            reads = sorted({m.group(0) for m in OFFSET_READ.finditer(source)})
            return ("✋ Not judged yet: it still reads memory through casts and offsets, which isn't readable:\n"
                    + "\n".join(f"- `{r}`" for r in reads[:12]) + ("\n- ..." if len(reads) > 12 else "") +
                    "\nDeclare the struct each pointer points to (guess_struct shows what the code uses; name the "
                    "fields for what the code does with them, `char pad_XX[n]` for gaps), use its fields, then "
                    f"make_readable(\"{fn['name']}\", source) again. A field compiles to the same code as its "
                    "offset. If the struct form really can't match, send this one again and it's judged as it is.")
        # Once per function too: names made of addresses (struct C_0046C950 { int f28; }, D_06880AC8, func_0046C250)
        names = [n for n in placeholders(source) if n.lstrip("_") != fn["name"].lstrip("_")]
        if names and fn["id"] not in self._placeholders_asked:
            self._placeholders_asked.add(fn["id"])
            return ("✋ Not judged yet: it still has names made of addresses, which aren't readable: "
                    + ", ".join(names[:16]) + (", ..." if len(names) > 16 else "") +
                    "\nName the struct for what the object is and its fields for what the code does with them; "
                    "read_data and read_file the globals and functions, then rename_symbol each. Then "
                    f"make_readable(\"{fn['name']}\", source) again. Where you really can't tell what one is, send "
                    "it again and it's judged as it is.")
        # what happened before it's judged: a rename or a header edit committed while it is (a helper sends
        # make_readable and rename_symbol together) wasn't judged with this C, nor this C with it
        since = self.net.store.one("SELECT COALESCE(MAX(id), 0) AS id FROM events WHERE project_id=?", proj["id"])["id"]
        if not self.net.is_rom(proj):  # the project's own file, judged and committed (or put back) as any compile
            res = self.net.forks.attempt(agent, proj["slug"], fn["name"], source, comment=True)
            if not res.get("matched"):
                return res["text"]
            return self._readable(proj, fn, agent, source)
        ctx = self.net._context(proj["id"], fn["unit"])
        result = self.net._compile(proj, ctx["header"], source, fn)
        if not result.ok:
            self.net._record(fn, agent, None, source, ctx["version"])  # its compiles count, as a decompiling one's
            return f"❌ COMPILE ERROR: the matching C stays.\n{result.log.strip()}"
        cand, verdict, problems = self.net._evaluate(fn, proj, result.obj)
        if cand is None:
            self.net._record(fn, agent, None, source, ctx["version"], compiled=True)
            return f"❌ No function named `{fn['name']}` in it: keep its name (rename it with rename_symbol)."
        d = scoring.diff(self.net._target_obj(fn, proj), cand)
        self.net._record(fn, agent, d.score, source, ctx["version"])  # not as a match: it was one already
        if not (d.bytes_match if verdict is None else verdict):
            note = "\n".join(f"- {p}" for p in problems)
            return (f"❌ It no longer matches (score {d.score}): the matching C stays. Keep the statements' shape and "
                    f"change names, types and comments only.\n{d.render()}" + (f"\n{note}" if note else ""))
        return self._readable(proj, fn, agent, source, since)

    def _readable(self, proj, fn, agent: Agent, source: str, since: int | None = None) -> str:
        """A rewrite that still matches: it's the function's C now, and the function counts as readable. `since`:
        the last event before it was judged (ROM mode): a rename or header edit after it means it was judged
        against what no longer is, and the rename wrote this function's C without it, so it's sent again."""
        with self.net.progress._project_lock(proj["slug"]), self.net.store.tx() as db:
            if since is not None and db.execute(
                    "SELECT 1 FROM events WHERE project_id=? AND id>? AND kind IN ('rename', 'context') LIMIT 1",
                    (proj["id"], since)).fetchone():
                return (f"✋ Not saved: a name or the shared header changed while {fn['name']} was judged. Read it "
                        f"again (get_function) and make_readable(\"{fn['name']}\", source) with the current names.")
            self.net.progress.check_result()
            db.execute("UPDATE functions SET matched_source=?, best_source=?, readable=1 WHERE id=?",
                       (source, source, fn["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            self.net._event(db, proj["id"], agent.id, "readable", fn["name"])
        counts = self.counts(proj)
        return (f"✅ {fn['name']} is readable now, and still matches byte for byte ({counts['readable']} of "
                f"{counts['matched']} readable). claim_readable for the next one.")
