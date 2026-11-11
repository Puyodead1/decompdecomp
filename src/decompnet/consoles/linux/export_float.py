"""A Linux export's floats made the game's in the plain build: GCC 2.95 computed with the x87's 80-bit registers,
rounding a float only where it stored one, and the C that compiles to the game's code says nothing of that, so a
newer GCC gives other floats from it (a quaternion a bit off, a frame of the game a few pixels off: #lockstep).

With -fexcess-precision=standard a newer GCC rounds where the C assigns a float and keeps a long double exact, which
lets the C say what the game's code did: where it kept a value exact (`long double`), where it rounded (a float
assignment), what it read a constant as (`(double)3.14159...`), what a float function returned (all 80 bits: long
double). This pass finds that C for each function the exported tree's tools/floatcheck.py (export_floatcheck.py)
finds different: from the C as it is, in turn,
- each literal not exact in its type cast to it (GCC 2.95 read its double or float, standard mode a long double),
- an inline helper of the file or the headers taking and returning long double (2.95's inlining rounded neither),
- a float function returning long double (its prototype too),
- a float local declared long double, and a float assignment's value kept exact for the reads after it (all, or
  one), each kept where it brings the function closer to the game's results, the closest first, until it is the
  game's or nothing brings it closer.
What it changes is written beside the C as it was, `#ifdef NON_MATCHING` (the matching build is untouched), and a
source file builds with -fexcess-precision=standard (build.json's plain_flags, the Makefile's rule for it) only where
that makes it closer to the game's results than GCC's default; the rest keep it. StormyReef's hand-made patch of an
arcade game's 3dmath.c was what the first cases were checked against.
"""

from __future__ import annotations

import importlib.util
import json
import re
import struct
import tempfile
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

DEFAULT = ["-O2", "-fno-builtin-sin", "-fno-builtin-cos"]  # (the Makefile's CFLAGS: sin and cos of one value made
# one sincos call returns them through doubles, rounded, where the game's code kept them)
STANDARD = "-fexcess-precision=standard"
INPUTS = 100
TRIES = 160  # the most C one function is tried in
WORKERS = 4
NUMBER = r"(?:(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?|\d+[eE][-+]?\d+)"
LITERAL = re.compile(rf"(?<![\w.)\]])(\(\s*(?:float|double)\s*\)\s*)?({NUMBER})([fFlL]?)(?![\w.])")
CONSTANT = re.compile(rf"(?<![\w)\]])\(\s*({NUMBER}|\d+)([fF]?)\s*([-+*/])\s*({NUMBER}|\d+)([fF]?)\s*\)")
FLOAT_DECLARATION = re.compile(r"^(\s*)float\s+((?:[^;(){}]|\([^;{}]*?\))*);", re.M)


def _tool(out: Path):
    spec = importlib.util.spec_from_file_location("floatcheck", out / "tools" / "floatcheck.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _exact(text: str, single: bool) -> bool:
    value = float(text)
    if single:
        value = struct.unpack("<f", struct.pack("<f", value))[0]
    return Decimal(text) == Decimal(value)


_NOT_CODE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*', re.S)


def literal_casts(body: str) -> str:
    """Each literal not exact in its type cast to it, and a constant expression of two literals too
    (`(1.0 / 180.0)`): standard mode reads them as long doubles, GCC 2.95 as the double (or float) the C says. Code
    only: a string's `%5.2f` and a comment stay as they are."""
    out, at = [], 0
    for m in _NOT_CODE.finditer(body):
        out += [_code_casts(body[at:m.start()]), m.group()]
        at = m.end()
    return "".join(out) + _code_casts(body[at:])


def _code_casts(body: str) -> str:
    def folded(m):
        single = bool(m.group(2) or m.group(5))
        return f"({'float' if single else 'double'}){m.group(0)}"
    body = CONSTANT.sub(folded, body)

    def cast(m):
        if m.group(1) or (m.group(3) and m.group(3) in "lL"):
            return m.group(0)
        single = bool(m.group(3))
        if _exact(m.group(2), single):
            return m.group(0)
        return f"({'float' if single else 'double'}){m.group(2)}{m.group(3)}"
    return LITERAL.sub(cast, body)


def float_locals(body: str) -> list[str]:
    """The float locals a function's body declares (not arrays)."""
    out = []
    for m in FLOAT_DECLARATION.finditer(body):
        for part in _split(m.group(2)):
            name = re.match(r"\s*([A-Za-z_]\w*)", part)
            if name and "[" not in part:
                out.append(name.group(1))
    return out


def _split(declarators: str) -> list[str]:
    """A declaration's declarators, at its commas outside parentheses."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(declarators):
        depth += {"(": 1, ")": -1}.get(c, 0)
        if c == "," and depth == 0:
            parts.append(declarators[start:i])
            start = i + 1
    return parts + [declarators[start:]]


def long_double_local(body: str, var: str) -> str:
    """A float local `var` declared long double (the others of its declaration stay float)."""
    def one(m):
        parts = _split(m.group(2))
        mine = [p for p in parts if re.match(rf"\s*{re.escape(var)}\b", p)]
        if not mine:
            return m.group(0)
        rest = [p for p in parts if p not in mine]
        indent = m.group(1).rsplit("\n", 1)[-1]
        return (m.group(1) + "float " + ",".join(rest).strip() + ";\n" + indent if rest else m.group(1)) + \
            f"long double {mine[0].strip()};"
    return FLOAT_DECLARATION.sub(one, body)


_OPERAND = r"(?:[A-Za-z_]\w*(?:(?:->|\.)\w+|\[[^\[\]]*\])*|\d+\.\d*[fF]?|\.\d+[fF]?)"
PRODUCT = re.compile(rf"(?<![\w.>\])])({_OPERAND}\s*[*/]\s*{_OPERAND})(?![\w.(\[])")


def products(body: str) -> list[tuple[int, int]]:
    """Each product or quotient of two operands in a function's code (not its head): where it starts and ends."""
    head = body.find("{") + 1
    out = []
    at = head
    for m in _NOT_CODE.finditer(body):
        out += [(head_m.start(1) + at, head_m.end(1) + at) for head_m in PRODUCT.finditer(body[at:m.start()])]
        at = m.end()
    out += [(m.start(1) + at, m.end(1) + at) for m in PRODUCT.finditer(body[at:])]
    return [(a, b) for a, b in out if a >= head and "float" not in body[max(0, a - 8):a]]


def spilled(body: str, at: tuple[int, int]) -> str:
    """A product rounded to a float where it is, `(float)(a * b)`: what GCC 2.95 did where it ran out of x87
    registers and spilled it to a float slot of the stack mid-expression (a particle renderer's `mag * cos`)."""
    a, b = at
    return body[:a] + f"(float)({body[a:b]})" + body[b:]


def volatile_local(body: str, var: str) -> str:
    """A float local `var` declared `volatile float`: stored and read again at each use, rounded where the game's code
    rounded it (GCC's default precision keeps a float in a register, all 80 bits, where it likes)."""
    return long_double_local(body, var).replace(f"long double {var}", f"volatile float {var}", 1)


def _assigned_after(body: str, var: str, at: int) -> int | None:
    """Where `var` is assigned again after `at`."""
    m = re.compile(rf"(?<![\w.>])\b{re.escape(var)}\s*(=(?!=)|\+=|-=|\*=|/=)").search(body, at)
    return m.start() if m else None


def float_assignments(body: str, floats: set[str]) -> list[tuple[int, int, str]]:
    """Each statement `v = E;` of a float variable: (where E starts, where it ends, v)."""
    out = []
    for m in re.finditer(r"(?<![\w.>\]])([A-Za-z_]\w*)\s*=(?!=)\s*", body):
        before = body[:m.start()].rstrip()
        end = body.find(";", m.end())
        if m.group(1) in floats and (not before or before[-1] in ";{}") and end > 0 and \
                "=" not in re.sub(r"[=!<>]=", "", body[m.end():end]):
            out.append((m.end(), end, m.group(1)))
    return out


def exact_copy(body: str, at: tuple[int, int, str], temp: str, only: int | None = None) -> str | None:
    """`v = E;` as `v = temp = E;` (temp a long double: E exact) and v's reads after it, up to its next assignment
    (or only the `only`th of them), temp: what the game's code read from the register it computed E in."""
    lo, hi, var = at
    nxt = _assigned_after(body, var, hi)
    region = body[hi:nxt] if nxt is not None else body[hi:]
    count = iter(range(1 << 30))
    used = re.sub(rf"(?<![\w.>])\b{re.escape(var)}\b",
                  lambda m: temp if only is None or next(count) == only else m.group(), region)
    if used == region:
        return None
    new = body[:lo] + f"{temp} = " + body[lo:hi] + used + (body[nxt:] if nxt is not None else "")
    brace = new.index("{")
    return new[:brace + 1] + f"\n    long double {temp};  /* the game's code kept {var} exact here */" + new[brace + 1:]


def _combined(kept: str, base: str, other: str) -> str | None:
    """`other`'s change to `base` (a function's body) made on `kept` too, where it applies there as it is."""
    import difflib

    a, b = base.splitlines(keepends=True), other.splitlines(keepends=True)
    out = kept
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
        if tag == "equal":
            continue
        old, new = "".join(a[i1:i2]), "".join(b[j1:j2])
        if tag == "insert":  # (a declaration after the opening brace)
            brace = out.index("{")
            out = out[:brace + 1] + "\n" + new.rstrip("\n") + out[brace + 1:] if out[brace + 1:].startswith("\n") \
                else None
            if out is None:
                return None
            continue
        if out.count(old) != 1:
            return None
        out = out.replace(old, new)
    return out


def inner_assignments(body: str, floats: set[str]) -> list[tuple[int, int, str]]:
    """Each assignment of a float variable whose value an expression takes (`sin(t = t * omega)`): (where it starts,
    where it ends, the variable)."""
    out = []
    for m in re.finditer(r"(?<![\w.>\]])([A-Za-z_]\w*)\s*=(?!=)", body):
        before = body[:m.start()].rstrip()
        if m.group(1) not in floats or not before or before[-1] not in "(,":
            continue
        depth, end = 0, None
        for i in range(m.end(), len(body)):
            c = body[i]
            if c == "(":
                depth += 1
            elif c in "),;" and depth == 0:
                end = i
                break
            elif c == ")":
                depth -= 1
        if end is not None and body[end] != ";":
            out.append((m.start(), end, m.group(1)))
    return out


def exact_value(body: str, at: tuple[int, int, str], temp: str) -> str:
    """`v = E` whose value an expression takes as `(v = temp = E, temp)`: v rounded as the C says, the expression
    given E exact, as the game's code passed on the register it computed E in."""
    lo, hi, var = at
    assignment = body[lo:hi]
    rhs = assignment.split("=", 1)[1]
    new = body[:lo] + f"({var} = {temp} ={rhs}, {temp})" + body[hi:]
    brace = new.index("{")
    return new[:brace + 1] + f"\n    long double {temp};  /* the game's code passed {var} on exact here */" + \
        new[brace + 1:]


def _reads(body: str, at: tuple[int, int, str]) -> int:
    lo, hi, var = at
    nxt = _assigned_after(body, var, hi)
    return len(re.findall(rf"(?<![\w.>])\b{re.escape(var)}\b", body[hi:nxt] if nxt is not None else body[hi:]))


def _float_names(text: str, headers: dict[str, str]) -> set[str]:
    out = set()
    for t in [text, *headers.values()]:
        for names in re.findall(r"^\s*(?:static\s+|extern\s+)?float\s+([A-Za-z_][\w\s,]*);", t, re.M):
            out |= {n.strip() for n in names.split(",") if n.strip()}
    return out


class _File:
    """One source file's search."""

    def __init__(self, out: Path, rel: str, tool, work: Path, headers: dict[str, str], tc: Path | None = None,
                 archive: Path | None = None):
        self.out, self.rel, self.tool = out, rel, tool
        self.text = (out / rel).read_text(encoding="utf-8")
        self.original = self.text
        self.headers: dict[str, str] = {}  # (include/<name> -> its text, where this file's search changed it)
        self.tree_headers = headers
        self.check = tool.Check(rel, work, ["gcc"], [*DEFAULT, STANDARD], tc, archive)
        self.default = tool.Check(rel, work.with_name(work.name + "-default"), ["gcc"], DEFAULT, tc, archive)
        self.active = self.check  # (the precision the search judges C in: standard, then GCC's default)
        self.tries = 0

    def score(self, text: str, headers: dict[str, str], fn: str | None = None) -> dict:
        self.tries += 1
        return self.active.run(text, {**headers} or None, only=fn, inputs=INPUTS)

    def header_text(self, name: str) -> str:
        return self.headers.get(name) or self.tree_headers[name]

    def fix(self, fn: str, best: int) -> int:
        """Changes kept for `fn`, the closest first, while they bring it closer; how many of its calls still differ."""
        text, headers = self.text, dict(self.headers)
        floats = _float_names(text, {**self.tree_headers, **headers})
        tried = 0

        def body_of(t):
            where = self.tool.span(t, fn)
            return (where[0], where[1], t[where[0]:where[1]]) if where else (0, 0, "")
        # (all 80 bits, as the game's code returned it in st(0); not where it rounded first, Vector3fMag's
        # `fstps`/`flds` before its `ret`: a float, as the C says)
        if self.check.defs[fn][0] == "f" and fn not in getattr(self.check, "rounds", ()):
            changed = {name: re.sub(rf"\bfloat(\s+{fn}\s*\()", r"long double\1", self.header_text(name))
                       for name in self.tree_headers}
            changed = {k: v for k, v in changed.items() if v != self.header_text(k)}
            a, b, body = body_of(text)
            new_text = text[:a] + re.sub(rf"\bfloat(\s+{fn}\s*\()", r"long double\1", body, count=1) + text[b:]
            new_text = re.sub(rf"^(\s*(?:extern\s+)?)float(\s+{fn}\s*\([^;{{]*\);)", r"\1long double\2", new_text,
                              flags=re.M)
            got = self.score(new_text, {**headers, **changed}, fn).get(fn)
            # (kept where no worse: what else the function needs may show it only with this, as a long double local
            # whose value the return rounded)
            if got is not None and got <= best:
                text, headers, best = new_text, {**headers, **changed}, got
        while best and tried < TRIES:
            a, b, body = body_of(text)
            head = body[:body.find("{")]  # (its parameters: `float t` assigned in it, slerp's `sin(t = t * omega)`)
            floats |= set(re.findall(r"\bfloat\s+([A-Za-z_]\w*)\s*[,)]", head))
            options = [(text[:a] + long_double_local(body, var) + text[b:]) for var in float_locals(body)]
            if self.active is self.check:  # (standard precision rounds a cast: a spill said in C)
                options += [(text[:a] + spilled(body, at) + text[b:]) for at in products(body)]
            if self.active is self.default:  # (GCC's default keeps a float exact where it likes: volatile rounds it)
                options += [(text[:a] + volatile_local(body, var) + text[b:]) for var in float_locals(body)
                            if f"volatile float {var}" not in body]
            for at in inner_assignments(body, floats | set(float_locals(body))):
                temp = next(f"{at[2]}_exact{k or ''}" for k in range(1 << 16)
                            if not re.search(rf"\b{at[2]}_exact{k or ''}\b", text))
                options.append(text[:a] + exact_value(body, at, temp) + text[b:])
            for at in float_assignments(body, floats | set(float_locals(body))):
                temp = next(f"{at[2]}_exact{k or ''}" for k in range(1 << 16)
                            if not re.search(rf"\b{at[2]}_exact{k or ''}\b", text))
                reads = _reads(body, at)
                for only in [None] + (list(range(reads)) if reads > 1 else []):
                    if (new := exact_copy(body, at, temp, only)) is not None:
                        options.append(text[:a] + new + text[b:])
            scored = []
            for option in options[:TRIES - tried]:
                tried += 1
                got = self.score(option, headers, fn).get(fn)
                if got is not None and got < best:
                    scored.append((got, option))
                    if got == 0:
                        break
            if not scored:
                break
            # each that brought it closer, the closest first, on top of those kept before it, kept where it still does
            scored.sort(key=lambda s: s[0])
            best, text = scored[0]
            for _, option in scored[1:]:
                if not best or tried >= TRIES:
                    break
                c, d, kept = body_of(text)
                e, f_, mine = body_of(option)
                combined = _combined(kept, body, mine)
                if combined is None:
                    continue
                tried += 1
                got = self.score(text[:c] + combined + text[d:], headers, fn).get(fn)
                if got is not None and got < best:
                    best, text = got, text[:c] + combined + text[d:]
        self.text, self.headers = text, headers
        return best

    def search(self) -> dict | None:
        """The file's search: None where it has nothing to compare."""
        if self.check.prepare(self.text) or self.default.prepare(self.text) or not self.check.defs:
            return None
        default = self.default.run(self.text, inputs=INPUTS)
        if not default:
            return None
        # every function's literals, as the game's code read them
        for fn in sorted(self.check.defs):
            where = self.tool.span(self.text, fn)
            if where:
                self.text = self.text[:where[0]] + literal_casts(self.text[where[0]:where[1]]) + self.text[where[1]:]
        start = self.score(self.text, self.headers)
        if not start:
            self.text = self.original
            return None
        # inline helpers of the file's and the headers': long double in and out, as 2.95's inlining kept them
        total = sum(v for v in start.values() if v)
        for name, source in [(None, self.text)] + sorted(self.tree_headers.items()):
            for m in re.finditer(r"^static\s+(?:__inline__|inline)\s+(?:float|double)\b[^;{]*?\([^)]*\)\s*\{", source,
                                 re.M):
                end = source.find("\n}", m.end())
                helper = re.search(r"(\w+)\s*\(", m.group()).group(1)
                if end < 0 or not re.search(rf"\b{helper}\s*\(", self.text[:m.start()] + self.text[m.end():]
                                            if name is None else self.text):
                    continue
                current = self.text if name is None else self.header_text(name)
                at = current.find(m.group())
                if at < 0:
                    continue
                stop = current.find("\n}", at) + 2
                changed = current[:at] + re.sub(r"\b(?<!long )(float|double)\b", "long double",
                                                current[at:stop]) + current[stop:]
                got = self.score(changed, self.headers) if name is None else \
                    self.score(self.text, {**self.headers, name: changed})
                if got and sum(v for v in got.values() if v) < total:
                    total, start = sum(v for v in got.values() if v), got
                    if name is None:
                        self.text = changed
                    else:
                        self.headers[name] = changed
        results = self._rounds(start)
        standard = (self.text, dict(self.headers), results)
        # and in GCC's default precision, which keeps the file's other functions as they are: the file builds in
        # whichever comes closer (GCC takes the precision for a whole file; one function that only standard makes the
        # game's kept a file of twelve that differ there on the default)
        self.active, self.text, self.headers = self.default, self.original, {}
        fixed = self._rounds(default)
        both = [fn for fn in results if results[fn] is not None and fixed.get(fn) is not None]
        start_default = sum(default.get(fn) or 0 for fn in both)
        totals = {"standard": sum(results[fn] for fn in both), "default": sum(fixed[fn] for fn in both)}
        mode = "standard" if totals["standard"] < totals["default"] else "default"
        if mode == "standard":
            self.text, self.headers, _ = standard
        chosen = results if mode == "standard" else fixed
        return {"mode": mode, "start": start_default, **totals,
                "differ_default": sorted(fn for fn in both if default.get(fn)),
                "differ": sorted(fn for fn in both if chosen[fn]),
                "untestable": sorted(fn for fn, v in chosen.items() if v is None), "tries": self.tries}

    def _rounds(self, start: dict) -> dict:
        """Each function that differs fixed (fix), twice: a function another calls, fixed in the first round, fixes
        that one too; what the file then gives."""
        results = dict(start)
        for _ in range(2):
            for fn in sorted(n for n, v in results.items() if v):
                self.fix(fn, results[fn])
            results = self.score(self.text, self.headers) or results
            if not any(results.values()):
                break
        return results


def _prototype(text: str, name: str) -> tuple[int, int] | None:
    """Where `name`'s prototype is in `text` (a line of its own, not a definition)."""
    m = re.search(rf"^(?![ \t])[A-Za-z_][\w \t\*]*?\b{re.escape(name)}\s*\([^;{{}}=]*\)\s*;[^\n]*$", text, re.M)
    return (m.start(), m.end()) if m else None


def merged(old: str, new: str, span) -> str:
    """`new`'s changed definitions (functions and inline helpers, `span`: name, text -> where) and prototypes written
    beside `old`'s, `#ifdef NON_MATCHING` (what the matching build compiles stays as it was)."""
    names = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", new))
    pieces = []
    for find in (span, _prototype):  # (whole definitions first: a prototype is only a line)
        for name in sorted(names):
            a, b = find(old, name) or (None, None)
            c, d = find(new, name) or (None, None)
            if a is None or c is None or old[a:b] == new[c:d] or "NON_MATCHING" in old[max(0, a - 24):a]:
                continue
            if any(x < b and a < y for x, y, _ in pieces):
                continue
            pieces.append((a, b, f"#ifdef NON_MATCHING\n{new[c:d]}\n#else\n{old[a:b]}\n#endif"))
    for a, b, text in sorted(pieces, reverse=True):
        old = old[:a] + text + old[b:]
    return old


def _same_match(out: Path, tc: Path, rel: str, build: dict, old: str, new: str) -> bool:
    """Whether GCC 2.95 builds the same code from `new` as from `old` (export_clean.same_code)."""
    from . import export_clean

    unit = next((u for u in build.get("units") or [] if u.get("c") == rel), {})
    flags = (["-include", "tools/prelude.h"] if (out / "tools" / "prelude.h").exists() else []) + \
        list(unit.get("flags") or ["-O2"])
    a = export_clean._compile(out, tc, out / rel, flags, old)
    b = export_clean._compile(out, tc, out / rel, flags, new)
    return a is not None and b is not None and export_clean.same_code(a, b, export_clean.addresses(build))


def available() -> bool:
    """Whether the system has what tools/floatcheck.py runs: gcc that compiles 32-bit code, and binutils."""
    import shutil
    import subprocess

    if not all(shutil.which(t) for t in ("gcc", "ld", "objcopy", "objdump", "nm")):
        return False
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "a.c").write_text("float f(float x) { return x * 2; }\n")
        said = subprocess.run(["gcc", "-m32", "-nostdinc", "-c", "a.c", "-o", "a.o"], cwd=tmp, capture_output=True)
        return said.returncode == 0


_HELPER = re.compile(r"^static\s+(?:__inline__|__inline|inline)\s+(?:float|double)\b[^;{]*?\([^)]*\)\s*\{", re.M)


def x87_helpers(out: Path) -> int:
    """The headers' inline helpers that are the x87's own instruction (`fsqrt` in an asm, "=t" its result) long
    double in and out in a plain build: GCC 2.95 inlined them on the 80-bit register, and a `double` one rounded its
    operand first (an arcade game's quaternion normalised a hair off, frames some pixels off). Returns how many."""
    count = 0
    for header in sorted((out / "include").glob("*.h")):
        text, at, done = header.read_text(encoding="utf-8"), 0, []
        for m in _HELPER.finditer(text):
            end = text.find("\n}", m.end())
            if end < 0:
                continue
            end += 2
            helper = text[m.start():end]
            if not re.search(r"__asm__|\basm\b", helper) or not re.search(r'"=[tu]"', helper) \
                    or text[:m.start()].endswith("#else\n"):  # (done before: the matching build's, after #else)
                continue
            exact = re.sub(r"\b(?<!long )(float|double)\b", "long double", helper)
            done.append(text[at:m.start()] + "#ifdef NON_MATCHING  /* the x87's own: all 80 bits, as GCC 2.95 inlined "
                        "it */\n" + exact + "\n#else\n" + helper + "\n#endif")
            at = end
            count += 1
        if done:
            header.write_text("".join(done) + text[at:], encoding="utf-8")
    return count


def precision(out: Path, build: dict, tc: Path | None = None, log=print) -> dict:
    """Each source file's float functions made the game's in the plain build where the search finds how (the module
    docstring): its C beside the matching C, NON_MATCHING, and build.json's plain_flags where standard mode is closer.
    Returns what it did, by file."""
    tool = _tool(out)
    if (helpers := x87_helpers(out)):
        log(f"the headers' x87 helpers long double in a plain build: {helpers}")
    rels = list(dict.fromkeys(u["c"] for u in build.get("units") or [] if u.get("c")))
    headers = {f"include/{h.name}": h.read_text(encoding="utf-8") for h in sorted((out / "include").glob("*.h"))}
    done: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="decompnet-float-") as tmp:
        game = tool.game_archive(Path(tmp), tc) if tc is not None else None  # (the rest of the program, linked in)
        files = {rel: _File(out, rel, tool, Path(tmp) / re.sub(r"\W", "_", rel), headers, tc, game) for rel in rels}
        def search(rel: str) -> dict | None:
            try:
                return files[rel].search()
            except (Exception, SystemExit) as e:  # (one file's: the others go on)
                log(f"{rel}: its floats weren't compared ({e})")
                return None
        with ThreadPoolExecutor(WORKERS) as pool:
            for rel, res in zip(rels, pool.map(search, rels)):
                if res is not None:
                    done[rel] = res
    changed_headers: dict[str, str] = {}
    for rel, res in done.items():
        f = files[rel]
        standard = res["mode"] == "standard"
        res["plain_flags"] = [STANDARD] if standard else []
        if f.text == f.original and not f.headers:
            continue
        # (the literals cast in the C both builds read, where GCC 2.95 still builds the game's code from it: a cast
        # to the type a literal has changes nothing there; the rest beside the matching C)
        base = f.original

        def cast(text: str, fns, span=f.tool.span) -> str:
            for fn in fns:
                if (where := span(text, fn)) is not None:
                    text = text[:where[0]] + literal_casts(text[where[0]:where[1]]) + text[where[1]:]
            return text
        if tc is not None:
            fns = [fn for fn in f.tool.definitions(base) if cast(base, [fn]) != base]
            if fns and _same_match(out, tc, rel, build, base, cast(base, fns)):
                base = cast(base, fns)
            else:  # (each function's on its own, where GCC 2.95 still builds the same code)
                for fn in fns:
                    if _same_match(out, tc, rel, build, base, cast(base, [fn])):
                        base = cast(base, [fn])
        (out / rel).write_text(merged(base, f.text, f.tool.span), encoding="utf-8")
        for name, body in f.headers.items():
            changed_headers[name] = merged(changed_headers.get(name, headers[name]), body, f.tool.span)
        for unit in build.get("units") or []:
            if unit.get("c") == rel and standard:
                unit["plain_flags"] = [STANDARD]
        log(f"{rel}: the plain build's floats the game's in {res['start'] - res[res['mode']]} more of the calls "
            "tools/floatcheck.py makes, with NON_MATCHING C"
            + (" and -fexcess-precision=standard" if standard else " (GCC's default precision)")
            + (f" ({', '.join(res['differ'])} still differ)" if res["differ"] else ""))
    for name, text in changed_headers.items():
        (out / name).write_text(text, encoding="utf-8")
    (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
    return done
