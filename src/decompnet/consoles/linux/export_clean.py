"""A Linux export's source made plain C, after the export has checked it matches: each change to a source file is
kept only where GCC 2.95 still compiles the file to the same code, every relocation reaching the same address of the
program (same_code), so the matching build stays byte for byte and nothing has to be checked twice.

A tree that matches isn't yet one a person builds as the game's own source: the matching build's linker script
supplied names the C read (`D_080B9BB0 = SegmentModel + 112;`), which a plain `gcc -o game *.c` link doesn't have.
Each pass here writes one kind of that machinery as the C it stands for:

- linked_names: a name the linker script gave an address inside a variable (a project's automatic name, another
  symbol of the program's) written as that variable, at its offset.
- own_helpers: a helper agents wrote `inline` (GNU C89: an external definition too) made `static inline`.
- numbered_addresses: a number the C writes that is a variable's address, by its name (both, `#ifdef NON_MATCHING`,
  where GCC 2.95 builds the game's code only from the number).
- library_tables: a 2001 glibc's <ctype.h> tables read inline (`__ctype_toupper[c]`) as the calls they were.
- set_names: a variable `.set` to another name the C reads it by, one name (the C's where the export's was made
  unique by its address).
- called_by_name: a function's redeclaration of another (`extern int sndPlay__healthHit() __asm__("sndPlay");`)
  dropped, the call by its own name, wherever the shared header's prototype builds the same code.
- struct_fields: a read at an offset into a variable written as the field there, by the game's own types.
- cross_reads: a read of rows past a variable's end written as the variable it lands in (what ASan finds).
- varargs: a file's own va_start, which steps from an argument's address, the compiler's own in a plain build.
- pool_constants: a constant read from the program's data by an address name, its literal in a plain build.
- copied_literals: a table copied from a literal the match placed at it (`memcpy(vlist, "", 72)`), the table's
  bytes in a plain build.
- module_headers: common.h, which declared every file's names, cut into a header per source file of what the others
  read of it; each file includes those it uses.
"""

from __future__ import annotations

import json
import re
import struct
import subprocess
from pathlib import Path

from ...limits import capped

_TOKEN = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|\b[A-Za-z_]\w*\b', re.S)


def addresses(build: dict) -> dict[str, int]:
    """Every name the tree's objects may reach, at its address in the program."""
    out = dict(build.get("symbols") or {})
    out.update({f["name"]: f["vram"] for f in build["functions"]})
    entries = list(build.get("units") or []) + list(build.get("data_files") or [])
    for entry in entries:
        for name, address, _, _ in (entry.get("data") or {}).get("variables") or []:
            out.setdefault(name, address)
    for entry in entries:
        data = entry.get("data") or {}
        for alias, (base, off) in {**(data.get("aliases") or {}), **(data.get("link_aliases") or {})}.items():
            if base in out:
                out.setdefault(alias, out[base] + off)
    return out


def _sections(obj: bytes):
    """An object's allocated sections, its symbols and its relocations, read with nothing but struct."""
    shoff, = struct.unpack_from("<I", obj, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", obj, 0x2E)
    heads = [struct.unpack_from("<IIIIIIIIII", obj, shoff + k * shentsize) for k in range(shnum)]
    names_at = heads[shstrndx][4]

    def name(off: int, base: int) -> str:
        end = obj.index(b"\0", base + off)
        return obj[base + off:end].decode("latin-1")
    sections = [dict(name=name(h[0], names_at), type=h[1], flags=h[2], offset=h[4], size=h[5], link=h[6], info=h[7],
                     index=k) for k, h in enumerate(heads)]
    symtab = next((s for s in sections if s["type"] == 2), None)
    symbols = []
    if symtab is not None:
        strings = sections[symtab["link"]]["offset"]
        for k in range(symtab["size"] // 16):
            st_name, value, size, info, _, shndx = struct.unpack_from("<IIIBBH", obj, symtab["offset"] + k * 16)
            symbols.append(dict(name=name(st_name, strings) if st_name else "", value=value, size=size,
                                type=info & 15, shndx=shndx))
    return sections, symbols


def _resolved(obj: bytes, where: dict[str, int]):
    """What an object's code and data are, by section name: its bytes with each relocated word taken out, and where
    each relocation reaches in the program (a name's address plus its addend; inside a variable of the object's own,
    that variable's address; else the section and the offset, as both compiles must have them)."""
    sections, symbols = _sections(obj)
    owned: dict[int, list] = {}
    for sym in symbols:
        if sym["type"] == 1 and sym["name"] and sym["shndx"] < len(sections):
            owned.setdefault(sym["shndx"], []).append(sym)
    out = {}
    for sec in sections:
        if not sec["flags"] & 2 or sec["type"] == 8:  # (SHF_ALLOC; .bss holds no bytes)
            if sec["flags"] & 2:
                out[sec["name"]] = (sec["size"], None)
            continue
        out[sec["name"]] = [bytearray(obj[sec["offset"]:sec["offset"] + sec["size"]]), []]
    for rs in sections:
        if rs["type"] != 9:  # SHT_REL
            continue
        target = sections[rs["info"]]
        if target["name"] not in out or out[target["name"]][1] is None:
            continue
        body, reached = out[target["name"]]
        for k in range(rs["size"] // 8):
            off, info = struct.unpack_from("<II", obj, rs["offset"] + k * 8)
            sym, kind = symbols[info >> 8], info & 0xFF
            addend, = struct.unpack_from("<i", body, off)
            body[off:off + 4] = b"\0\0\0\0"
            if sym["type"] == 3:  # STT_SECTION: the variable of the object's there, else the place itself
                home = sections[sym["shndx"]]["name"]
                inside = next((s for s in owned.get(sym["shndx"], ()) if s["value"] <= addend < s["value"] + max(s["size"], 1)
                               and s["name"] in where), None)
                reach = ("at", where[inside["name"]] + addend - inside["value"]) if inside else (home, addend)
            elif sym["name"] in where:
                reach = ("at", where[sym["name"]] + addend)
            else:
                reach = (sym["name"], addend)
            if kind == 1 and reach[0] == "at":  # (R_386_32 to a place of the program's: that address, as a number is)
                body[off:off + 4] = (reach[1] & 0xFFFFFFFF).to_bytes(4, "little")
                continue
            reached.append((off, kind, reach))
    # code by the game's functions in it (a helper that isn't one, inlined away, is no part of the program)
    executable = {sec["name"] for sec in sections if sec["flags"] & 4}
    found = {}
    for name, value in out.items():
        if name not in executable:
            found[name] = (bytes(value[0]), sorted(value[1])) if isinstance(value, list) else value
            continue
        index = next(sec["index"] for sec in sections if sec["name"] == name)
        for sym in symbols:
            if sym["type"] == 2 and sym["shndx"] == index and sym["name"] in where:  # STT_FUNC
                lo, hi = sym["value"], sym["value"] + sym["size"]
                found[(name, sym["name"])] = (bytes(value[0][lo:hi]),
                                              sorted((off - lo, kind, reach) for off, kind, reach in value[1]
                                                     if lo <= off < hi))
    return found


def same_code(old: bytes, new: bytes, where: dict[str, int], new_where: dict[str, int] | None = None) -> bool:
    """Whether two compiles of a source file are the same program: every section's bytes, and every relocation
    reaching the same address (`D_080B9BB0` and `SegmentModel + 112` are one place). `new_where`: the names there
    are for the new one (without those a change drops)."""
    return _resolved(old, where) == _resolved(new, where if new_where is None else new_where)


def _compile(out: Path, tc: Path, source: Path, flags: list[str], text: str) -> bytes | None:
    work = out / "build" / "clean"
    work.mkdir(parents=True, exist_ok=True)
    probe = source.with_name(f".clean-{source.name}")  # (beside it: its own folder's includes)
    probe.write_text(text, encoding="utf-8")
    obj = work / f"{source.stem}.o"
    try:
        proc = subprocess.run(capped(["sh", "tools/cc.sh", str(tc), str(probe.relative_to(out)), str(obj), "-Iinclude",
                                      *flags]), cwd=out, capture_output=True, timeout=600)
        return obj.read_bytes() if proc.returncode == 0 and obj.exists() else None
    finally:
        probe.unlink(missing_ok=True)
        obj.unlink(missing_ok=True)


_DEFINES = re.compile(r"(?:static\s+|const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*"
                      r"[A-Za-z_]\w*[\s*]+(?:const\s+)?\**\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:=|;|__attribute__)")


def _outside_both(text: str):
    """Each line of `text`, and whether it's in an `#ifdef NON_MATCHING` block (a change made before: as it is)."""
    depth = 0  # (inside the block: how many conditionals deep)
    for line in text.splitlines(keepends=True):
        directive = re.match(r"\s*#\s*(\w+)", line)
        if depth == 0:
            if directive and directive.group(1) == "ifdef" and re.match(r"\s*#\s*ifdef\s+NON_MATCHING\b", line):
                depth = 1
                yield line, True
                continue
            yield line, False
            continue
        if directive and directive.group(1) in ("if", "ifdef", "ifndef"):
            depth += 1
        elif directive and directive.group(1) == "endif":
            depth -= 1
        yield line, True


def _code_tokens(text: str, rewrite) -> str:
    """`text` with each identifier outside comments and strings given to `rewrite` (word -> text): not where it's
    declared (an `extern` line, what `__typeof__` reads) or defined (a top-level `char D_0809EB4C[] = ...`)."""
    lines = []
    for line, settled in _outside_both(text):
        if settled or re.match(r"\s*extern\b", line) or re.match(r"\s*#\s*(?:if|elif|ifdef|ifndef|undef|define)\b", line):
            lines.append(line)
            continue
        m = _DEFINES.match(line) if not line[:1].isspace() and not line.startswith("return") else None
        defined = m.start(1) if m else -1

        def one(t: re.Match, defined: int = defined, line: str = line) -> str:
            word = t.group(0)
            if t.start() == defined or not (word[0].isalpha() or word[0] == "_") \
                    or line[:t.start()].endswith("__typeof__("):  # (what a rewrite reads the type of: as it is)
                return word
            return rewrite(word)
        lines.append(_TOKEN.sub(one, line))
    return "".join(lines)


def _declared_as(text: str, names: dict[str, str]) -> str | None:
    """`text` with each of `names`' declarations given that symbol (`extern char D_08F78580[] __asm__("vect_ix");`),
    or None where one isn't declared in it: the C reads the name as before, the link finds the variable's own."""
    for word, symbol in names.items():
        pattern = re.compile(rf"^([ \t]*extern\b[^;(){{}}]*\b{re.escape(word)}\s*(?:\[[^\]]*\])*)\s*;", re.M)
        if pattern.search(text):
            text = pattern.sub(lambda m, symbol=symbol: f'{m.group(1)} __asm__("{symbol}");', text)
            continue
        # (declared first in a header every file includes, where a symbol given again isn't taken: a name of the
        # file's own for it, declared so)
        last = None
        for last in re.finditer(r'^#\s*include\b.*\n', text, re.M):
            pass
        if last is None:
            return None
        text = (text[:last.end()] + f"/* {word} is the program's {symbol}: GCC 2.95 builds the game's code only from "
                f"a name it doesn't define */\nextern __typeof__({word}) {word}__{symbol} __asm__(\"{symbol}\");\n"
                f"#define {word} {word}__{symbol}\n" + text[last.end():])
    return text


def linked_names(build: dict):
    """The rewrites for the names the matching build's linker script gave addresses inside variables, best first:
    each written as the variable at its offset, the type it was read with kept (`(*(__typeof__(D_080B9BB0) *)((char
    *)&SegmentModel + 112))`); where that changes the code, one at a variable's start declared as that variable's
    symbol (GCC 2.95 reads a variable the file defines itself otherwise than a name it doesn't)."""
    names: dict[str, tuple[str, int]] = {}
    for entry in list(build.get("units") or []) + list(build.get("data_files") or []):
        for alias, (base, off) in ((entry.get("data") or {}).get("link_aliases") or {}).items():
            names[alias] = (base, off)

    def written(word: str) -> str:
        base, off = names[word]
        at = f"((char *)&{base} + {off})" if off else f"&{base}"
        return f"(*(__typeof__({word}) *){at})"

    def candidates(text: str):
        used = {w for w in set(re.findall(r"\b[A-Za-z_]\w*\b", text)) if w in names
                and not re.search(rf"^#define {re.escape(w)} {re.escape(w)}__", text, re.M)}  # (done before)
        if not used:
            return
        yield _code_tokens(text, lambda w: written(w) if w in used else w)
        starts = {w: names[w][0] for w in used if not names[w][1]}
        if starts:
            rest = _code_tokens(text, lambda w: written(w) if w in used and w not in starts else w)
            for base in (rest, text):
                declared = _declared_as(base, starts)
                if declared is not None:
                    yield declared
    return candidates


def own_helpers(build: dict):
    """The rewrite for the helpers agents wrote `inline` (GNU C89's: an external definition too, so two files' are
    one name defined twice in a plain link): `static inline`, each file's own, as a header's helper is."""
    game = {f["name"] for f in build["functions"]}

    def candidates(text: str):
        new = re.sub(r"^inline\b(?=[^;{]*\b(\w+)\s*\()", lambda m: m.group(0) if m.group(1) in game
                     else "static inline", text, flags=re.M)
        if new != text:
            yield new
    return candidates


_NUMBER = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|\b0[xX][0-9a-fA-F]+[uUlL]*\b', re.S)


_BOTH = re.compile(r"^#ifdef NON_MATCHING\n.*?^#endif\n", re.M | re.S)


def _in_both(text: str):
    """Whether a place of `text` is in a `#ifdef NON_MATCHING` block (done already: both forms there)."""
    spans = [(m.start(), m.end()) for m in _BOTH.finditer(text)]
    return lambda at: any(a <= at < b for a, b in spans)


def _non_matching(old: str, new: str) -> str | None:
    """`new`'s changed lines kept beside `old`'s, `#ifdef NON_MATCHING` (the matching build doesn't define it, the
    plain one does): what decompilations write where the clean C isn't the one that matches. None where a line is
    part of a macro (a directive can't go there)."""
    a, b = old.splitlines(keepends=True), new.splitlines(keepends=True)
    if len(a) != len(b):
        return None
    out = []
    for k, (x, y) in enumerate(zip(a, b)):
        if x == y:
            out.append(x)
            continue
        if x.rstrip().endswith("\\") or (k and a[k - 1].rstrip().endswith("\\")):
            return None
        end = "" if x.endswith("\n") else "\n"
        out.append(f"#ifdef NON_MATCHING\n{y}{end}#else\n{x}{end}#endif\n")
    return "".join(out)


def numbered_addresses(build: dict, out: Path):
    """The rewrites for the numbers the C writes that are addresses of the program's variables (`*(GLmatrix
    *)0x80be300`): each by the variable's name (`((int)&g_Players + 0x79c)`); where GCC 2.95 builds the game's code
    only from the number (it folds a number into others, never a name), both, `#ifdef NON_MATCHING`."""
    spans: list[tuple[int, int, str, str | None]] = []  # (address, end, name, the file it is static in)
    for entry in list(build.get("units") or []) + list(build.get("data_files") or []):
        data = entry.get("data") or {}
        globals_ = set(data.get("defines") or [])
        for name, address, size, _ in data.get("variables") or []:
            if "." not in name:
                spans.append((address, address + max(size, 1), name, None if name in globals_ else entry.get("c")))
    spans.sort()
    import bisect

    lows = [lo for lo, _, _, _ in spans]

    def rewrite(text: str, rel: str) -> str:
        def one(m: re.Match) -> str:
            word = m.group(0)
            if not re.fullmatch(r"0[xX][0-9a-fA-F]+[uUlL]*", word):
                return word
            value = int(word.rstrip("uUlL"), 16)
            k = bisect.bisect_right(lows, value) - 1
            if k < 0 or not spans[k][0] <= value < spans[k][1] or spans[k][3] not in (None, rel):
                return word
            lo, _, name, _ = spans[k]
            return f"((int)&{name} + 0x{value - lo:x})" if value > lo else f"((int)&{name})"
        lines = []
        for line, settled in _outside_both(text):
            lines.append(line if settled or re.match(r"\s*#\s*(?:if|elif)\b", line) else _NUMBER.sub(one, line))
        return "".join(lines)

    def candidates(text: str, rel: str = ""):
        new = rewrite(text, rel)
        if new == text:
            return
        yield new
        both = _non_matching(text, new)
        if both is not None:
            yield both
    return candidates


def _bracketed(text: str, at: int) -> int | None:
    """Where the `[` at `at` is closed."""
    depth = 0
    for k in range(at, len(text)):
        depth += {"[": 1, "]": -1}.get(text[k], 0)
        if depth == 0:
            return k
    return None


def library_tables(build: dict):
    """The rewrites for the C library's tables a 2001 glibc's <ctype.h> read inline (`__ctype_toupper[c]`, what
    `toupper(c)` was at -O2), which no newer glibc exports: the call (both, `#ifdef NON_MATCHING`, where GCC 2.95
    builds the game's code only from the table)."""
    calls = {"__ctype_toupper": "toupper", "__ctype_tolower": "tolower"}

    def rewrite(text: str) -> str:
        lines = []
        for line, settled in _outside_both(text):
            for table, call in calls.items():
                while not settled and (m := re.search(rf"\b{table}\s*\[", line)) is not None:
                    end = _bracketed(line, m.end() - 1)
                    if end is None:
                        break
                    line = line[:m.start()] + f"{call}({line[m.end():end]})" + line[end + 1:]
            lines.append(line)
        return "".join(lines)

    def candidates(text: str):
        new = rewrite(text)
        if new == text:
            return
        yield new
        both = _non_matching(text, new)
        if both is not None:
            yield both
    return candidates


_REDECLARED = re.compile(r'^[ \t]*extern\b[^;\n]*?__asm__\("(\w+)"\)[^;\n]*;[^\n]*\n', re.M)


def called_by_name(build: dict):
    """Items for the redeclarations a file's functions make of another's (`extern int sndPlay__healthHit()
    __asm__("sndPlay");`, how one function called it, undeclared, or declared it itself): each one dropped and its
    uses the function's own name, as the shared header declares it. An unprototyped call's floats are doubles, a
    pointer read as an int another type: where the header's prototype changes the code, the redeclaration stays."""

    def items(text: str) -> list[tuple[str, str, str]]:
        out = []
        for m in _REDECLARED.finditer(text):
            alias = re.search(rf"\b{re.escape(m.group(1))}__\w+\b", m.group(0))
            if alias:
                out.append((m.group(0), alias.group(0), m.group(1)))
        return out

    def apply(text: str, chosen) -> str:
        for line, alias, name in chosen:
            text = text.replace(line, "", 1)
            text = re.sub(rf"\b{re.escape(alias)}\b", name, text)
        return text
    return items, apply


_SET_BLOCK = re.compile(r'^__asm__\("((?:\\.|[^"\\])*)"\);  /\* the names the C reads these by \*/\n', re.M)


def _rename(text: str, old: str, new: str) -> str:
    """`old` as `new` wherever it's an identifier of the C (not in comments or strings), and a symbol an `__asm__`
    label gives a declaration."""
    text = _TOKEN.sub(lambda m: new if m.group(0) == old else m.group(0), text)
    return text.replace(f'__asm__("{old}")', f'__asm__("{new}")')


def set_names(build: dict, others: dict[str, str]):
    """Items for the names a source file `.set` to its own variables because the C reads them by another name
    (`.set FlashFogColor, FlashFogColor_080B17F0`, `.set oldCoins_262, ContinueUpdate_oldCoins`): the variable by one
    name, where no other file reads the other. The C's name where the variable's was the export's, made unique by its
    address (`FlashFogColor`), the variable's where the C's is a function static's GCC numbered (`oldCoins_262`, the
    program's `oldCoins.262`, is `ContinueUpdate_oldCoins`); at an offset, the variable and the offset."""

    def entries(text: str) -> list[tuple[str, str, int]]:
        m = _SET_BLOCK.search(text)
        if not m:
            return []
        out = []
        for found in re.finditer(r"\.set (\w+), (\w+)(?:\+(\d+))?", m.group(1)):
            out.append((found.group(1), found.group(2), int(found.group(3) or 0)))
        return out

    def items(text: str, rel: str = "") -> list[tuple[str, str, int]]:
        elsewhere = [t for r, t in others.items() if r != rel]
        return [(a, b, off) for a, b, off in entries(text)
                if not any(re.search(rf"\b{re.escape(a)}\b", t) for t in elsewhere)]

    def apply(text: str, chosen) -> str:
        drop = {a for a, _, _ in chosen}
        block = _SET_BLOCK.search(text)
        rest = [(a, b, off) for a, b, off in entries(text) if a not in drop]
        lines = "".join(f"\\n\\t.globl {a}\\n\\t.set {a}, {b}{f'+{off}' if off else ''}" for a, b, off in rest)
        new_block = f'__asm__("{lines[4:]}");  /* the names the C reads these by */\n' if rest else ""
        text = text[:block.start()] + new_block + text[block.end():]
        for alias, base, off in chosen:
            if off:
                text = _code_tokens(text, lambda w, alias=alias, base=base, off=off: (
                    f"(*(__typeof__({alias}) *)((char *)&{base} + {off}))" if w == alias else w))
            elif re.fullmatch(rf"{re.escape(alias)}_(?:[0-9A-F]{{8}})?", base):
                text = _rename(text, base, alias)  # (the export's name for it, unique by its address: the C's)
            else:
                text = _rename(text, alias, base)
        return text
    def kept(rel: str, chosen) -> None:
        """The variables renamed and the names dropped, in build.json too (what build.py checks the data by)."""
        for entry in list(build.get("units") or []) + list(build.get("data_files") or []):
            if entry.get("c") != rel or not entry.get("data"):
                continue
            data = entry["data"]
            for alias, base, off in chosen:
                (data.get("aliases") or {}).pop(alias, None)
                if off or not re.fullmatch(rf"{re.escape(alias)}_(?:[0-9A-F]{{8}})?", base):
                    continue
                data["variables"] = [[alias if v[0] == base else v[0], *v[1:]] for v in data.get("variables") or []]
                data["defines"] = [alias if n == base else n for n in data.get("defines") or []]
                for other in (data.get("aliases") or {}).values():
                    if other[0] == base:
                        other[0] = alias
    return items, apply, kept


# the game's types as common.h has them from the debug information: `struct _TCamera { /* 0x728 bytes */` and a
# field a line, its offset in a comment
_LAYOUT = re.compile(r"^(struct|union) (\w+) \{ /\* 0x([0-9A-Fa-f]+) bytes \*/\n(.*?)^\};", re.M | re.S)
_FIELD = re.compile(r"^    ([^;{}\n]+?);\s*/\* 0x([0-9A-Fa-f]+) \*/[ \t]*$", re.M)
_TYPEDEF = re.compile(r"^typedef ((?:struct|union) \w+|\w+) (\w+);", re.M)
_OFF = r"(0x[0-9a-fA-F]+|\d+)"


def _norm(t: str) -> str:
    return re.sub(r"\s*\*\s*", "*", " ".join(t.split())).strip()


class _Layouts:
    """Struct layouts by their field offsets: which field (`pos.y`) is at an offset into a variable of a type."""

    def __init__(self, text: str):
        self.typedefs = {name: target for target, name in _TYPEDEF.findall(text)}
        self.layouts = {}
        for kind, tag, size, body in _LAYOUT.findall(text):
            fields = []
            for decl, off in _FIELD.findall(body):
                m = re.search(r"\(\s*\*+\s*(\w+)\s*\)", decl)
                if m:  # (a pointer to a function or an array: one word)
                    fields.append((m.group(1), "void *", [], int(off, 16)))
                    continue
                m = re.match(r"(.*?)(\w+)((?:\[\w*\])*)$", decl.strip())
                if not m or not m.group(1).strip():
                    continue
                dims = [int(d, 0) for d in re.findall(r"\[(\w+)\]", m.group(3)) if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", d)]
                if m.group(3) and len(dims) != m.group(3).count("["):
                    continue
                fields.append((m.group(2), _norm(m.group(1)), dims, int(off, 16)))
            self.layouts[f"{kind} {tag}"] = (int(size, 16), kind == "union", fields)

    def key(self, type_: str) -> str | None:
        t = _norm(type_)
        for _ in range(8):
            if t in self.layouts:
                return t
            if t not in self.typedefs:
                return None
            t = _norm(self.typedefs[t])
        return None

    def base(self, type_: str) -> str:
        """`type_` through its typedefs (`uint` -> `unsigned int`)."""
        t = _norm(type_)
        for _ in range(8):
            if t not in self.typedefs:
                break
            t = _norm(self.typedefs[t])
        return t

    def same(self, a: str, b: str) -> bool:
        return self.base(a) == self.base(b)

    def paths(self, type_: str, off: int, want: str | None):
        """The fields of a `type_` at `off`, outermost first (`pos`, `pos.x`), each of type `want` (any: None)."""
        key = self.key(type_)
        if key is None:
            return
        size, union, fields = self.layouts[key]
        ends = [f[3] for f in fields[1:]] + [size]
        for (name, ftype, dims, at), end in zip(fields, ends):
            span = (size if union else end) - at
            if not at <= off < at + max(span, 1):
                continue
            rel, sub = off - at, name
            if dims:
                if len(dims) != 1 or not dims[0]:
                    continue
                inner = self.layouts.get(self.key(ftype) or "", (span // dims[0],))[0]
                if not inner:
                    continue
                if off - at >= inner * dims[0]:
                    continue
                if off == at and want is None:  # (an address there: the array's)
                    yield name
                sub, rel = f"{name}[{rel // inner}]", rel % inner
            if rel == 0 and (want is None or self.same(ftype, want)):
                yield sub
            for deeper in self.paths(ftype, rel, want) if "*" not in ftype else ():
                yield f"{sub}.{deeper}"


def _variable_types(texts) -> dict[str, str]:
    """Each variable a header or file declares or defines with a plain type (`extern TCamera g_Camera;`)."""
    out = {}
    for text in texts:
        for m in re.finditer(r"^(?:extern |static )?((?:struct |union |unsigned |const )*\w+) (\w+)\s*(\[\w+\])?\s*"
                             r"(?:=|;|__attribute__)", text, re.M):
            if m.group(1) not in ("return", "typedef", "extern", "static", "goto"):
                out.setdefault(m.group(2), m.group(1) + (m.group(3) or ""))
    return out


def _access(layouts: _Layouts, vtype: str, off: int, want: str | None, outermost: bool = False) -> str | None:
    """How C reads `off` bytes into a variable of `vtype` as a field of type `want` (any: None): `.pos.y`, or
    `[1].input` into an array; None where no field of that type starts there."""
    m = re.fullmatch(r"(.+?)\s*\[(\w+)\]", vtype or "")
    if m:
        key = layouts.key(m.group(1))
        size = layouts.layouts[key][0] if key else 0
        if not size or not re.fullmatch(r"0x[0-9a-fA-F]+|\d+", m.group(2)) or off >= size * int(m.group(2), 0):
            return None
        rest = off % size
        if rest == 0 and want is not None and layouts.same(m.group(1), want):
            return f"[{off // size}]"
        path = _first(layouts.paths(m.group(1), rest, want), want, outermost)
        return f"[{off // size}].{path}" if path else None
    path = _first(layouts.paths(vtype or "", off, want), want, outermost)
    return f".{path}" if path else None


def _first(paths, want: str | None, outermost: bool = False) -> str | None:
    """The field of a type asked for (the outermost), or with none asked, the innermost one there (`spaceVel.x`,
    what a read of one word is; an address: the outermost, `&g_Camera.scale`)."""
    if want is not None or outermost:
        return next(paths, None)
    found = None
    for path in paths:
        if found is not None and not path.startswith(found + "."):
            break
        found = path
    return found


def struct_fields(out: Path):
    """A read at an offset into a variable (`*(int *)((char *)&g_Camera + 0x6d8)`, `(*(__typeof__(D_08EC894C) *)
    ((char *)&g_Camera + 12))`, what the linker script's names became) written as the field there (`g_Camera.pos`),
    by the game's own types where the field's type is what the C reads."""
    shared = out / "include" / "common.h"
    layouts = _Layouts(shared.read_text(encoding="utf-8") if shared.exists() else "")
    headers = [p.read_text(encoding="utf-8") for p in sorted((out / "include").glob("*.h"))]
    typeof_ = re.compile(rf"\(\*\(__typeof__\((\w+)\) \*\)\(\(char \*\)&(\w+) \+ {_OFF}\)\)")
    read = re.compile(rf"\*\(((?:unsigned |signed |struct |const |volatile )*\w+(?: \*+)?) \*\)\(\(char \*\)&(\w+) \+ "
                      rf"{_OFF}\)")
    point = re.compile(rf"(?<![*\w)])\(((?:unsigned |signed |struct |const |volatile )*\w+(?: \*+)?) \*\)\(\(char \*\)&"
                       rf"(\w+) \+ {_OFF}\)")

    def items(text: str) -> list[tuple[int, int, str]]:
        if not layouts.layouts:
            return []
        types = _variable_types(headers + [text])
        found = []
        for m in typeof_.finditer(text):
            var, want = m.group(2), types.get(m.group(1))
            path = _access(layouts, types.get(var, ""), int(m.group(3), 0), want) if want else None
            if path:
                found.append((m.start(), m.end(), f"{var}{path}"))
        for m in read.finditer(text):
            var, off, want = m.group(2), int(m.group(3), 0), m.group(1)
            path = _access(layouts, types.get(var, ""), off, want)
            if path:
                found.append((m.start(), m.end(), f"{var}{path}"))
                continue
            path = _access(layouts, types.get(var, ""), off, None)  # (read as another type than the field's)
            if path:
                found.append((m.start(), m.end(), f"*({want} *)&{var}{path}"))
        for m in point.finditer(text):
            var, off = m.group(2), int(m.group(3), 0)
            path = (_access(layouts, types.get(var, ""), off, m.group(1))
                    or _access(layouts, types.get(var, ""), off, None, outermost=True))
            if path:
                found.append((m.start(), m.end(), f"({m.group(1)} *)&{var}{path}"))
        found.sort()
        return [f for i, f in enumerate(found) if not i or f[0] >= found[i - 1][1]]

    def apply(text: str, chosen) -> str:
        for start, end, new in sorted(chosen, reverse=True):
            text = text[:start] + new + text[end:]
        return text
    return items, apply


_SCALAR = {"char": 1, "signed char": 1, "unsigned char": 1, "short": 2, "unsigned short": 2, "signed short": 2,
           "int": 4, "unsigned int": 4, "signed int": 4, "unsigned": 4, "long": 4, "unsigned long": 4, "float": 4,
           "double": 8, "long long": 8, "unsigned long long": 8}
_ROWS = re.compile(r"\(\(\(int\)&(\w+) \+ (0x[0-9a-fA-F]+|\d+)\) \+ ([^;()]+?|\([^;()]*\)[^;()]*?) \* (\d+)\)")
_ROW_ALIAS = re.compile(r'^[ \t]*extern (?:\w+ )+(\w+)\[\]\[(\d+)\] __asm__\("(\w+)"\);[^\n]*\n', re.M)


def cross_reads(build: dict):
    """A read of rows past a variable's end (`(short *)(((int)&scrnHit + 0x12) + Difficulty * 18)`, a table the C
    reached from the one before it) written as the variable it lands in, where one starts on a row
    (`initMaxAmmo[Difficulty - 1]`, at the same address: the same code). What ASan finds in a plain build."""
    at: dict[str, dict[str, tuple[int, int]]] = {}
    for entry in list(build.get("units") or []) + list(build.get("data_files") or []):
        for name, address, size, _ in (entry.get("data") or {}).get("variables") or []:
            at.setdefault(entry.get("c") or "", {})[name] = (address, size)

    def arrays(text: str) -> dict[str, tuple[int, list[int]]]:
        out = {}
        for m in re.finditer(r"^(?:static )?((?:unsigned |signed )?\w+) (\w+)((?:\[\d+\])+)\s*(?:=|;|__attribute__)",
                             text, re.M):
            if m.group(1) in _SCALAR:
                out.setdefault(m.group(2), (_SCALAR[m.group(1)], [int(d) for d in re.findall(r"\d+", m.group(3))]))
        return out

    def landing(rel: str, text: str, base: int, past: int, row: int) -> tuple[str, int] | None:
        """The array of `rel` with a row of `row` bytes starting `j` rows after `base`, at or past `past`."""
        shapes = arrays(text)
        for name, (address, size) in (at.get(rel) or {}).items():
            shape = shapes.get(name)
            if shape is None or address < past or (address - base) % row:
                continue
            elem, dims = shape
            if elem * (dims[-1] if len(dims) > 1 else 1) == row and size % row == 0 and 0 < (address - base) // row <= 4:
                return name, (address - base) // row
        return None

    def index(expr: str, minus: int) -> str:
        m = re.fullmatch(r"(.*?)\s*\+\s*(\d+)", expr.strip())
        expr, k = (m.group(1), int(m.group(2))) if m else (expr.strip(), 0)
        k -= minus
        return expr if not k else f"{expr} + {k}" if k > 0 else f"{expr} - {-k}"

    def items(text: str, rel: str = "") -> list[tuple[int, int, str]]:
        vars_ = at.get(rel) or {}
        found = []
        for m in _ROWS.finditer(text):
            name, off, expr, row = m.group(1), int(m.group(2), 0), m.group(3), int(m.group(4))
            if name not in vars_:
                continue
            address, size = vars_[name]
            target = landing(rel, text, address + off, address + size, row)
            if target and off + row >= size:
                land, j = target
                cast = re.search(r"\((?:const )?((?:unsigned |signed )?\w+) \*\)\s*$", text[:m.start()])
                elem = arrays(text)[land][0]
                if cast and _SCALAR.get(cast.group(1)) == elem and len(arrays(text)[land][1]) > 1:
                    found.append((cast.start(), m.end(), f"{land}[{index(expr, j)}]"))
                else:
                    found.append((m.start(), m.end(), f"((int)&{land}[{index(expr, j)}])"))
        for alias in _ROW_ALIAS.finditer(text):
            short, cols, name = alias.group(1), int(alias.group(2)), alias.group(3)
            elem = re.match(r"^[ \t]*extern ((?:unsigned |signed )?\w+) ", alias.group(0))
            if name not in vars_ or not elem or elem.group(1) not in _SCALAR:
                continue
            address, size = vars_[name]
            row = _SCALAR[elem.group(1)] * cols
            target = landing(rel, text, address, address + size, row)
            if not target:
                continue
            for m in re.finditer(rf"\b{re.escape(short)}\[([^\[\]]+)\]", text):
                if m.start() < alias.end():
                    continue
                found.append((m.start(), m.end(), f"{target[0]}[{index(m.group(1), target[1])}]"))
        # (through a pointer the file only ever sets to the table: `clip = (short *) clipMaxAmmo;` ... `clip + D * 9`)
        sets: dict[str, set[tuple[str, str]]] = {}
        for m in re.finditer(r"\b(\w+) = \((?:const )?((?:unsigned |signed )?\w+) \*\) ?&?(\w+);", text):
            sets.setdefault(m.group(1), set()).add((m.group(2), m.group(3)))
        for pointer, targets in sets.items():
            if len(targets) != 1 or len(re.findall(rf"\b{re.escape(pointer)} = ", text)) != len(
                    re.findall(rf"\b{re.escape(pointer)} = \((?:const )?(?:unsigned |signed )?\w+ \*\) ?&?\w+;", text)):
                continue
            (elem, name), = targets
            if name not in vars_ or elem not in _SCALAR:
                continue
            address, size = vars_[name]
            for m in re.finditer(rf"\b{re.escape(pointer)} \+ ([^;(),]+?) \* (\d+)\b", text):
                row = _SCALAR[elem] * int(m.group(2))
                target = landing(rel, text, address, address + size, row) if row >= size else None
                if target and arrays(text)[target[0]][0] == _SCALAR[elem] and len(arrays(text)[target[0]][1]) > 1:
                    found.append((m.start(), m.end(), f"{target[0]}[{index(m.group(1), target[1])}]"))
        found.sort()
        return [f for i, f in enumerate(found) if not i or f[0] >= found[i - 1][1]]

    def apply(text: str, chosen) -> str:
        for start, end, new in sorted(chosen, reverse=True):
            text = text[:start] + new + text[end:]
        return text

    def candidates(text: str, rel: str):
        """The reads by the variable they reach, else both (`#ifdef NON_MATCHING`): GCC 2.95 writes
        `initMaxAmmo - 18` as an offset into the file's own data, which no relink of the file places as the game
        has it, while the address is the game's by construction."""
        done = _in_both(text)
        found = [f for f in items(text, rel) if not done(f[0])]
        if not found:
            return
        new = apply(text, found)
        yield new
        both = _non_matching(text, new)
        if both is not None:
            yield both
    return candidates


_OWN_VARARGS = re.compile(r"^#define va_start\(.*?(?=^#define va_end\(\w+\)[^\n]*\n)#define va_end\(\w+\)[^\n]*\n",
                          re.M | re.S)


def varargs(build: dict):
    """A file's own va_start (`(char *)&(LASTARG) + 4`, the argument where GCC 2.95 left it) is GCC 2.95's only;
    another compiler (or ASan) moves the argument, so a plain build takes the compiler's own (NON_MATCHING)."""
    def candidates(text: str):
        m = _OWN_VARARGS.search(text)
        if m and "__builtin_va_start" not in text:
            yield (text[:m.start()] + "#ifdef NON_MATCHING\n#define va_start(AP, LASTARG) __builtin_va_start(AP, LASTARG)"
                   "\n#define va_arg(AP, TYPE) __builtin_va_arg(AP, TYPE)\n#define va_end(AP) __builtin_va_end(AP)\n"
                   "#else\n" + m.group(0) + "#endif\n" + text[m.end():])
    return candidates


_POOL = re.compile(r"^(?:static )?(?:const )?(?:unsigned |signed )?char (\w+)\[(\d+)\] = \{([^}]*)\};", re.M)
_POOL_READ = re.compile(r"\(\*\(__typeof__\((\w+)\) \*\)(?:&(\w+)|\(\(char \*\)&(\w+) \+ (0x[0-9a-fA-F]+|\d+)\))\)")
_KINDS = {"float": ("<f", 4), "double": ("<d", 8), "int": ("<i", 4), "unsigned int": ("<I", 4), "short": ("<h", 2),
          "unsigned short": ("<H", 2), "long": ("<i", 4), "unsigned long": ("<I", 4)}


def _literal(kind: str, raw: bytes) -> str | None:
    """A constant's bytes as the C literal of its type: 384.0f, 1e-06, 0x43c80000, "string"."""
    import math
    if kind in ("char[]", "const char[]"):
        end = raw.find(b"\0")
        if end <= 0 or any(b < 32 and b not in (9, 10) or b > 126 for b in raw[:end]):
            return None
        body = raw[:end].decode("ascii").replace("\\", "\\\\").replace('"', '\\"')
        return '"' + body.replace("\n", "\\n").replace("\t", "\\t") + '"'
    fmt, size = _KINDS.get(kind.replace("const ", ""), (None, 0))
    if fmt is None or len(raw) < size:
        return None
    value, = struct.unpack(fmt, raw[:size])
    if fmt in ("<f", "<d"):
        if math.isnan(value) or math.isinf(value):
            return None
        text = repr(value if fmt == "<d" else struct.unpack("<f", struct.pack("<f", value))[0])
        if fmt == "<f":  # (the shortest decimal that is this float)
            for digits in range(1, 10):
                short = f"{value:.{digits}g}"
                if struct.pack("<f", float(short)) == raw[:4]:
                    text = repr(float(short))
                    break
        if not re.search(r"[.eE]", text):
            text += ".0"
        return f"{text}f" if fmt == "<f" else text
    return hex(value) if fmt in ("<I", "<H") and value > 9 else str(value)


def pool_constants(build: dict, out: Path):
    """A constant the C reads from the program's data by an address name (`(*(__typeof__(D_080A956C) *)
    &D_080A956C_data)`, so GCC 2.95 reads it where the game keeps it) written as the literal it is (`400.0f`), under
    NON_MATCHING: a literal is the compiler's to place. Only what the game keeps read-only (.rodata)."""
    readonly: dict[str, set[str]] = {}
    for entry in list(build.get("units") or []) + list(build.get("data_files") or []):
        for name, _, _, section in (entry.get("data") or {}).get("variables") or []:
            if section.startswith(".rodata"):
                readonly.setdefault(entry.get("c") or "", set()).add(name)
    headers = "\n".join(p.read_text(encoding="utf-8") for p in sorted((out / "include").glob("*.h")))

    def kind_of(name: str, text: str) -> str | None:
        m = re.search(rf"^extern ((?:const )?(?:unsigned |signed )?\w+) {re.escape(name)}(\[\])?\s*;", text + "\n"
                      + headers, re.M)
        if not m:
            return None
        return m.group(1) + "[]" if m.group(2) else m.group(1)

    def candidates(text: str, rel: str):
        pools = {m.group(1): bytes(int(v, 0) & 0xFF for v in m.group(3).split(",") if v.strip())
                 for m in _POOL.finditer(text) if m.group(1) in readonly.get(rel, ())}
        if not pools:
            return
        new, at, done = [], 0, _in_both(text)
        for m in _POOL_READ.finditer(text):
            if done(m.start()):
                continue
            pool = m.group(2) or m.group(3)
            kind = kind_of(m.group(1), text) if pool in pools else None
            if kind and kind.endswith("[]") and re.search(r"\)\s*\(?\s*$", text[:m.start()]):
                continue  # (its bytes read as another type: not a string)
            literal = _literal(kind, pools[pool][int(m.group(4) or "0", 0):]) if kind else None
            if literal is not None:
                new += [text[at:m.start()], literal]
                at = m.end()
        if not new:
            return
        both = _non_matching(text, "".join(new) + text[at:])
        if both is not None:
            yield both
    return candidates


_COPY = re.compile(r'\bmemcpy\s*\(\s*([^,;]+?)\s*,\s*"((?:\\.|[^"\\])*)"\s*,\s*(sizeof\s*\(\s*\w+\s*\)|0x[0-9a-fA-F]+|\d+)\s*\)')


# a copy into a local array of all of it, from a literal or a name of the program's address
_COPY_TABLE = re.compile(r'\bmemcpy\s*\(\s*(\w+)\s*,\s*(?:"((?:\\.|[^"\\])*)"|(?:\(\s*(?:const\s+)?void\s*\*\s*\)\s*)?&?'
                         r'(D_[0-9A-F]{8})\b)\s*,\s*(sizeof\s*\(\s*\w+\s*\))\s*\)')


def _program_bytes(image: bytes, address: int, size: int) -> bytes | None:
    """`size` bytes of the program at `address`, from its sections."""
    from io import BytesIO

    from elftools.elf.elffile import ELFFile
    for sec in ELFFile(BytesIO(image)).iter_sections():
        lo = sec["sh_addr"]
        if lo and sec["sh_type"] != "SHT_NOBITS" and lo <= address and address + size <= lo + sec["sh_size"]:
            return sec.data()[address - lo:address - lo + size]
    return None


def _sizeof(text: str, name: str) -> int | None:
    """The size of a local or file array `name` of scalars as `text` declares it (`ushort vlist[12][3];`)."""
    m = re.search(rf"\b((?:unsigned |signed )?\w+) {re.escape(name)}((?:\[\d+\])+)\s*;", text)
    if not m:
        return None
    elem = _SCALAR.get({"ushort": "unsigned short", "uint": "unsigned int", "uchar": "unsigned char",
                        "u8": "unsigned char", "u16": "unsigned short", "u32": "unsigned int", "s16": "short",
                        "s32": "int", "s8": "char"}.get(m.group(1), m.group(1)))
    if not elem:
        return None
    for d in re.findall(r"\d+", m.group(2)):
        elem *= int(d)
    return elem


def literal_reads(obj: bytes, image: bytes, where: dict[str, int]) -> dict[str, dict[bytes, set[int]]]:
    """Each game function's literals, by the program addresses the game's code loads where the object loads them
    (an immediate, `mov $table,%esi` or `push $table`: not a constant read in place, `flds 256.0f`, whose bytes may
    start as a literal's). The matched code is the game's, so the relocated word there is the game's address."""
    sections, symbols = _sections(obj)
    reads: dict[str, dict[bytes, set[int]]] = {}
    funcs = [(sym["name"], sym["value"], sym["size"], sym["shndx"]) for sym in symbols
             if sym["type"] == 2 and sym["name"] in where]
    for rs in sections:
        if rs["type"] != 9:
            continue
        target = sections[rs["info"]]
        for k in range(rs["size"] // 8):
            off, info = struct.unpack_from("<II", obj, rs["offset"] + k * 8)
            sym = symbols[info >> 8]
            if sym["type"] != 3 or not sections[sym["shndx"]]["name"].startswith(".rodata"):
                continue
            if not off or not (obj[target["offset"] + off - 1] in range(0xB8, 0xC0)
                               or obj[target["offset"] + off - 1] == 0x68):
                continue
            home = sections[sym["shndx"]]
            addend, = struct.unpack_from("<i", obj, target["offset"] + off)
            start = home["offset"] + addend
            end = obj.find(b"\0", start, home["offset"] + home["size"])
            if end < 0:
                continue
            for name, lo, size, shndx in funcs:
                if shndx == rs["info"] and lo <= off < lo + size:
                    game = _program_bytes(image, where[name] + off - lo, 4)
                    if game is not None:
                        reads.setdefault(name, {}).setdefault(obj[start:end], set()).add(struct.unpack("<I", game)[0])
    return reads


_SCALAR_NAMES = {"ushort": "unsigned short", "uint": "unsigned int", "uchar": "unsigned char", "u8": "unsigned char",
                 "u16": "unsigned short", "u32": "unsigned int", "s16": "short", "s32": "int", "s8": "char"}
_UNPACK = {1: "b", 2: "h", 4: "i"}


def local_table(source: str, reads: dict[bytes, set[int]], image: bytes) -> str | None:
    """`T v[12][3]; ... memcpy(v, "", sizeof(v));` (a copy from a literal the match placed at a table, or from a
    name of its address, `(void *)D_080A899C`) as the
    table's initializer, where the copy was: `{ T v[12][3] = { { 0, 1, 2 }, ... }; ... }`, a block to the end of the
    one the copy is in. What GCC 2.95 builds the same code from, its table in the file's .rodata as the game's."""
    from ...units import _mask
    out = source
    for m in reversed(list(_COPY_TABLE.finditer(source))):
        var, count = m.group(1), m.group(4)
        if re.search(r"\w+", count[6:]).group(0) != var:
            continue
        decl = re.search(rf"^([ \t]*)((?:unsigned |signed )?\w+) {re.escape(var)}((?:\[\d+\])+)\s*;[^\n]*\n", out[:m.start()],
                         re.M)
        if m.group(2) is not None:  # (a literal the match placed: where the game's code loads it)
            literal = bytes(m.group(2), "ascii").decode("unicode_escape").encode("latin-1")
            places = reads.get(literal) or set()
        else:  # (a name of the program's address: `(void *)D_080A899C`)
            literal, places = b"", {int(m.group(3)[2:], 16)}
        kind = _SCALAR_NAMES.get(decl.group(2), decl.group(2)) if decl else None
        if not decl or kind not in _SCALAR or len(places) != 1 or re.search(rf"\b{re.escape(var)}\b",
                                                                              out[decl.end():m.start()]):
            continue
        dims = [int(d) for d in re.findall(r"\d+", decl.group(3))]
        size = _SCALAR[kind]
        count_all = 1
        for d in dims:
            count_all *= d
        table = _program_bytes(image, next(iter(places)), size * count_all)
        if table is None or size not in _UNPACK or not table.startswith(literal):
            continue
        values = list(struct.unpack("<" + (_UNPACK[size].upper() if kind.startswith("unsigned") else _UNPACK[size])
                                    * count_all, table))

        def nested(vals: list, shape: list[int]) -> str:
            if len(shape) == 1:
                return "{ " + ", ".join(str(v) for v in vals) + " }"
            step = len(vals) // shape[0]
            return "{ " + ", ".join(nested(vals[i:i + step], shape[1:]) for i in range(0, len(vals), step)) + " }"
        # the statement's end, and the end of the block it's in
        stmt_end = out.index(";", m.end()) + 1
        masked = _mask(out)
        depth, k = 0, stmt_end
        while k < len(masked):
            if masked[k] == "{":
                depth += 1
            elif masked[k] == "}":
                if depth == 0:
                    break
                depth -= 1
            k += 1
        else:
            continue
        line_start = out.rfind("\n", 0, m.start()) + 1
        close = out.rfind("\n", 0, k) + 1
        if out[line_start:m.start()].strip() or close <= stmt_end or out[close:k].strip():
            continue  # (the copy starts its line, and the block's `}` its own)
        indent = out[line_start:m.start()]
        out = (out[:decl.start()] + out[decl.end():line_start]
               + f"{indent}{{\n{indent}{decl.group(2)} {var}{decl.group(3)} = {nested(values, dims)};"
               + out[stmt_end:close] + f"{indent}}}\n" + out[close:])
    return out if out != source else None


def copied_literals(build: dict, out: Path, tc: Path, flags_of: dict[str, list[str]]):
    """`memcpy(vlist, "", sizeof(vlist))`: the code copies a table the game keeps (a local array's initializer) from
    where GCC 2.95 put a literal its C wrote, and the match placed that literal at the table's address: a plain build
    copies past a 1-byte string. Under NON_MATCHING the literal is the table's bytes, read from the program at the
    address the game's code loads (the matched code is the game's, so the relocated word there is that address)."""
    image_path = out / "baserom"
    image = image_path.read_bytes() if image_path.is_file() else None
    where = addresses(build)

    def candidates(text: str, rel: str):
        if image is None or not _COPY.search(text):
            return
        obj = _compile(out, tc, out / rel, flags_of.get(rel, []), text)
        if obj is None:
            return
        reads = literal_reads(obj, image, where)
        from ...units import chunks
        new, at = [], 0
        done = _in_both(text)
        bodies = [(c.names[0], text.find(c.text), len(c.text)) for c in chunks(text) if c.kind == "func" and c.names]
        for m in _COPY.finditer(text):
            if done(m.start()):
                continue
            owner = next((n for n, lo, size in bodies if lo <= m.start() < lo + size), None)
            literal = bytes(m.group(2), "ascii").decode("unicode_escape").encode("latin-1")
            places = (reads.get(owner) or {}).get(literal) or set()
            count = m.group(3)
            n = _sizeof(text, re.search(r"\w+", count[6:]).group(0)) if count.startswith("sizeof") else int(count, 0)
            if len(places) != 1 or n is None or n <= len(literal) + 1:
                continue
            table = _program_bytes(image, next(iter(places)), n)
            if table is None or not table.startswith(literal):
                continue
            body = "".join(f"\\{b:03o}" for b in table)
            new += [text[at:m.start(2) - 1], f'"{body}"']
            at = m.end(2) + 1
        if new:
            both = _non_matching(text, "".join(new) + text[at:])
            if both is not None:
                yield both
    return candidates


PASSES = (("names the linker script gave", linked_names), ("helpers made each file's own", own_helpers),
          ("addresses written as numbers", numbered_addresses), ("the C library's tables read as calls", library_tables),
          ("functions called by their own names", called_by_name), ("variables by one name", set_names),
          ("offsets into variables read as their fields", struct_fields),
          ("reads past a variable's end as the one they reach", cross_reads),
          ("varargs as the compiler's own", varargs),
          ("constants read from the program's data as literals", pool_constants),
          ("tables copied from a literal the match placed", copied_literals))
ITEMIZED = {called_by_name, set_names, struct_fields}  # (passes whose changes are kept one by one: items, apply)


_VA_LIST = re.compile(r"^typedef (?:void|char) \*va_list;\n", re.M)


def _header_varargs(out: Path) -> None:
    """The headers' `typedef void *va_list;` (what a file's own va_start steps through) the compiler's own in a plain
    build, which its __builtin_va_start takes (varargs)."""
    for header in sorted((out / "include").glob("*.h")):
        text = header.read_text(encoding="utf-8")
        if _VA_LIST.search(text) and "__builtin_va_list" not in text:
            header.write_text(_VA_LIST.sub(lambda m: "#ifdef NON_MATCHING\ntypedef __builtin_va_list va_list;\n#else\n"
                                           + m.group(0) + "#endif\n", text, count=1), encoding="utf-8")


def clean(out: Path, build: dict, tc: Path, log=print) -> dict[str, int]:
    """Each pass over each C source file of the tree, kept where the file still compiles to the same code. Returns
    how many files each pass changed."""
    _header_varargs(out)  # (not read by the matching build: NON_MATCHING)
    where = addresses(build)
    files = [(u["c"], tuple(u.get("flags") or [])) for u in build.get("units") or [] if u.get("c")]
    files += [(f["c"], tuple(f.get("flags") or [])) for f in build["functions"] if f.get("c") and not f.get("file")
              and not any(f["c"] == c for c, _ in files)]
    files += [(d["c"], tuple(d.get("flags") or [])) for d in build.get("data_files") or [] if d.get("c")]
    prelude = ["-include", "tools/prelude.h"] if (out / "tools" / "prelude.h").exists() else []
    changed = {}
    for title, make in PASSES:
        if make in ITEMIZED:
            if make is set_names and not build.get("standalone"):
                continue  # (data/program.s names pointers by them)
            made = make(build, {rel: (out / rel).read_text(encoding="utf-8") for rel, _ in files}) \
                if make is set_names else make(out) if make is struct_fields else make(build)
            count, refused = _itemized(out, tc, files, prelude, where, title, made[0], made[1], log,
                                       made[2] if len(made) > 2 else None)
            if len(made) > 2 and count:
                (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
            changed[title] = count
            log(f"{title}: written as C in {count} files" + (f" ({refused} kept as they were)" if refused else ""))
            continue
        rewrite = make(build, out) if make in (numbered_addresses, pool_constants) else \
            make(build, out, tc, {rel: prelude + list(f) for rel, f in files}) if make is copied_literals else make(build)
        by_file = make in (numbered_addresses, cross_reads, pool_constants, copied_literals)  # (rewrite(text, rel))
        # (the names only the linker script gives reach nothing in a plain link: the new C mustn't read them)
        linked = {a for e in list(build.get("units") or []) + list(build.get("data_files") or [])
                  for a in ((e.get("data") or {}).get("link_aliases") or {})}
        plain_where = {k: v for k, v in where.items() if k not in linked} if make is linked_names else where
        count = refused = 0
        for rel, flags in dict.fromkeys(files):
            path = out / rel
            text = path.read_text(encoding="utf-8")
            old_obj = None
            why = None
            for new in (rewrite(text, rel) if by_file else rewrite(text)):
                if new == text:
                    continue
                if old_obj is None:
                    old_obj = _compile(out, tc, path, prelude + list(flags), text)
                    if old_obj is None:
                        why = "it doesn't compile alone"
                        break
                new_obj = _compile(out, tc, path, prelude + list(flags), new)
                if new_obj is not None and same_code(old_obj, new_obj, where, plain_where):
                    path.write_text(new, encoding="utf-8")
                    count += 1
                    why = None
                    break
                why = "it no longer compiles" if new_obj is None else "its code changed"
            if why:
                refused += 1
                log(f"{rel}: {title} kept as it was ({why})")
        changed[title] = count
        if count or refused:
            log(f"{title}: written as C in {count} files")
    title = "headers of each source file's own"
    changed[title] = module_headers(out, build, tc, files, prelude, where, log)
    if changed[title]:
        log(f"{title}: {changed[title]} files read them")
    title = "declarations a header makes"
    items, apply = redeclared(out)
    changed[title], refused = _itemized(out, tc, files, prelude, where, title, items, apply, log)
    if changed[title] or refused:
        log(f"{title}: dropped in {changed[title]} files ({refused} kept)")
    return changed


def _itemized(out: Path, tc: Path, files, prelude, where, title: str, items, apply, log, kept_hook=None) \
        -> tuple[int, int]:
    """A pass whose changes are kept one by one: all of a file's at once, else each half, and so on down to one,
    each kept where the file still compiles to the same code. Returns (files changed, changes kept as they were)."""
    changed = refused_total = 0
    for rel, flags in dict.fromkeys(files):
        path = out / rel
        text = path.read_text(encoding="utf-8")
        found = items(text, rel) if items.__code__.co_argcount > 1 else items(text)
        if not found:
            continue
        old_obj = _compile(out, tc, path, prelude + list(flags), text)
        if old_obj is None:
            continue
        kept = _what_works(found, lambda chosen, path=path, flags=flags, text=text, old_obj=old_obj: _works(
            out, tc, path, prelude + list(flags), apply(text, chosen), old_obj, where,
            {item[0] for item in chosen} if kept_hook is not None else set()))
        refused_total += len(found) - len(kept)
        if kept:
            path.write_text(apply(text, kept), encoding="utf-8")
            changed += 1
            if kept_hook is not None:
                kept_hook(rel, kept)
    return changed, refused_total


def _works(out: Path, tc: Path, path: Path, flags: list[str], text: str, old_obj: bytes, where, gone: set[str]) -> bool:
    """Whether `text` compiles to `old_obj`'s code; a name in `gone` (one the change drops) reaches nothing."""
    new_obj = _compile(out, tc, path, flags, text)
    return new_obj is not None and same_code(old_obj, new_obj, where, {k: v for k, v in where.items() if k not in gone})


def _what_works(found: list, works) -> list:
    """The changes of `found` kept: all at once if `works` takes them, else each half's, down to single ones, each
    tried on top of those kept before it."""
    kept: list = []

    def search(group: list) -> None:
        if not group:
            return
        if works(kept + group):
            kept.extend(group)
        elif len(group) > 1:
            half = len(group) // 2
            search(group[:half])
            search(group[half:])
    search(found)
    return kept


# the first line of a shared header module_headers wrote (a second run leaves the tree as it is)
_SHARED = ("/* What every file of the program shares: its types, macros and the libraries' declarations. What a\n"
           " * source file defines for the others is in its own header (font.c's in font.h). */\n")
_LABEL_LINE = re.compile(r"^[ \t]*/\* [\w./-]+\.c \*/[ \t]*\n", re.M)  # (common.h's `/* 3dmath.c */` above a group)
_GLOBL = re.compile(r"\.globl\s+(\w+)")
_LOCAL = "/* What this file reads that no header declares as it does */"


def _module(rel: str) -> str:
    """The source file a C file of the tree is part of, by name: src/font.c is font, src/model/mdAttach.c (one
    function of model.c) is model."""
    p = Path(rel)
    return p.parent.name if p.parent.name != "src" else p.stem


def _defined(text: str) -> tuple[set[str], set[str]]:
    """The names a C file defines for the rest of the program (its functions and variables, the names its `.set`s
    give), and those it keeps to itself (static)."""
    from ...units import chunks
    public, own = set(), set()
    for c in chunks(text):
        if c.kind in ("func", "data"):
            (own if c.static else public).update(c.names)
        elif c.kind == "static" or (c.kind == "extern" and c.static):
            own.update(c.names)
        elif c.kind == "other":
            public.update(_GLOBL.findall(c.text))
    return public - own, own


def _declaration(chunk) -> str:
    """A declaration of common.h as a module's header has it: with the comment right above it, without a heading
    of common.h's (above a blank line) or the label of the group it opened."""
    from ...units import _mask
    masked = _mask(chunk.text)
    start = len(masked) - len(masked.lstrip())
    lead, decl = chunk.text[:start], chunk.text[start:]
    lead = _LABEL_LINE.sub("", re.split(r"\n[ \t]*\n", lead)[-1].lstrip("\n"))
    return lead + (decl if decl.endswith("\n") else decl + "\n")


def _conflicting(out: Path, tc: Path, candidates: list, others: list, prelude) -> set[str]:
    """The names of `candidates` (declarations) that GCC 2.95 finds conflicting with a declaration of `others` of
    the same name, or with common.h's."""
    wanted = {n for c in candidates for n in c.names}
    probe_dir = out / "build" / "clean"
    probe_dir.mkdir(parents=True, exist_ok=True)
    bad: set[str] = set()
    for _ in range(20):  # (GCC stops reporting after a while: until a probe compiles)
        decls = [c for c in candidates if not set(c.names) & bad]
        decls += [c for c in others if set(c.names) & wanted and not set(c.names) & bad]
        text = '#include "common.h"\n' + "".join(dict.fromkeys(c.text.rstrip("\n") + "\n" for c in decls))
        probe = out / "src" / ".clean-conflicts.c"
        probe.write_text(text, encoding="utf-8")
        try:
            proc = subprocess.run(capped(["sh", "tools/cc.sh", str(tc), str(probe.relative_to(out)),
                                          str(probe_dir / "conflicts.o"), "-Iinclude", *prelude]),
                                  cwd=out, capture_output=True, text=True, timeout=600)
        finally:
            probe.unlink(missing_ok=True)
            (probe_dir / "conflicts.o").unlink(missing_ok=True)
        if proc.returncode == 0:
            return bad
        found = set(re.findall(r"(?:conflicting types for|redeclaration of|previous declaration of) `(\w+)'",
                               proc.stderr)) & wanted
        if not found - bad:
            return wanted  # (it fails for another reason: none of them is safe to share)
        bad |= found
    return wanted


def module_headers(out: Path, build: dict, tc: Path, files, prelude, where, log=print) -> int:
    """common.h declared every file's functions and variables (and the statics of one file that another reads), so
    a file with a static of that name had its own copy without it (common_<file>.h): not how a program is written.
    Each source file gets a header of what the rest of the program reads of it (<file>.h, from common.h's
    declarations); common.h keeps the types, macros and the libraries'; each file includes common.h, its own header
    and those of the files whose names it uses, and declares what no header does (another file's static it reads, a
    declaration of its own) itself. A file is kept so where GCC 2.95 still compiles it to the same code; one that
    isn't reads the headers it was matched with (common_full.h, <file>_decls.h). Returns how many files read
    module headers."""
    from ...units import chunks
    inc = out / "include"
    shared = inc / "common.h"
    if not shared.exists() or shared.read_text(encoding="utf-8").startswith(_SHARED):
        return 0
    rels = list(dict.fromkeys(rel for rel, _ in files))
    texts = {rel: (out / rel).read_text(encoding="utf-8") for rel in rels}
    others = [p.relative_to(out).as_posix() for p in sorted((out / "src").rglob("*.c"))
              if not p.name.startswith(".") and p.relative_to(out).as_posix() not in texts]
    public: dict[str, set[str]] = {}
    statics: dict[str, set[str]] = {}
    owner_of: dict[str, set[str]] = {}
    static_somewhere: set[str] = set()
    for rel, text in texts.items():
        mine, own = _defined(text)
        public[rel], statics[rel] = mine, own
        static_somewhere |= own
        for name in mine:
            owner_of.setdefault(name, set()).add(_module(rel))
    owner = {n: next(iter(m)) for n, m in owner_of.items() if len(m) == 1}
    if others:  # (a C file no build compiles: it keeps the headers it has)
        log(f"module headers: {len(others)} source files aren't compiled by the build, so they keep the full header")

    # common.h cut: what a module defines goes to its header, a static's declaration to the files that read it
    old_common = shared.read_text(encoding="utf-8")
    kept, headers, of_statics = [], {}, {}
    for c in chunks(old_common):
        names = c.names if c.kind == "extern" and not c.static else ()
        modules = {owner.get(n) for n in names}
        if names and len(modules) == 1 and None not in modules:
            headers.setdefault(modules.pop(), []).append(c)
        elif names and all(n in static_somewhere and n not in owner_of for n in names):
            for n in names:
                of_statics[n] = c
        else:
            kept.append(c)

    # what each file was matched with
    private = {}
    for rel in rels:
        own = inc / f"{Path(rel).stem}.h"
        if _module(rel) == Path(rel).stem and own.exists() and re.search(
                rf'^#include "{re.escape(own.name)}"', texts[rel], re.M):
            private[rel] = own.read_text(encoding="utf-8")
    # a file's own functions and variables its private header declared and common.h didn't: its header's too, where
    # no other file declares one of them otherwise (two files' guesses at a type GCC calls conflicting)
    extra: dict[str, list] = {}
    extended: set[int] = set()  # (the declarations common.h didn't make)
    for rel, text in private.items():
        module = _module(rel)
        have = {n for c in headers.get(module, ()) for n in c.names}
        for c in chunks(text):
            if c.kind == "extern" and not c.static and c.names and not set(c.names) & have and all(
                    owner.get(n) == module for n in c.names):
                extra.setdefault(module, []).append(c)
                have.update(c.names)
    elsewhere = [c for text in private.values() for c in chunks(text) if c.kind == "extern" and not c.static]
    elsewhere += [c for text in texts.values() for c in chunks(text) if c.kind == "extern" and not c.static]
    clash = _conflicting(out, tc, [c for cs in extra.values() for c in cs], elsewhere, prelude)
    for module, cs in extra.items():
        added = [c for c in cs if not set(c.names) & clash]
        headers.setdefault(module, []).extend(added)
        extended.update(id(c) for c in added)
    declared = {n: m for m, cs in headers.items() for c in cs for n in c.names}

    def tokens(text: str) -> set[str]:
        return {t for t in _TOKEN.findall(text) if t[0].isalpha() or t[0] == "_"}

    # each file compiled as it was matched, before anything changes
    flags_of = {rel: tuple(f) for rel, f in files}
    old_objs = {rel: _compile(out, tc, out / rel, prelude + list(flags_of[rel]), texts[rel]) for rel in rels}

    def rewritten(rel: str, sparing: bool = False) -> str | None:
        """`rel` reading the module headers; `sparing`: not those with a declaration common.h didn't make (one
        that may change a call of this file's), what it needs of them declared itself."""
        text, module, own = texts[rel], _module(rel), statics[rel]
        first = re.match(r'#include "common(?:_[\w-]+)?\.h"\n', text)
        if not first:
            return None
        body = text[first.end():]
        local = []
        if rel in private:
            body = re.sub(rf'^\n?#include "{re.escape(Path(rel).stem)}\.h"\n', "", body, count=1, flags=re.M)
            for c in chunks(private[rel]):
                if c.kind in ("pp", "include") or (c.kind == "define" and c.names and c.names[0].startswith("FILE_")):
                    continue
                if c.kind == "extern" and c.names and all(
                        any(d.key == c.key and not (sparing and id(d) in extended)
                            for d in headers.get(declared.get(n), ())) for n in c.names):
                    continue  # (its header says the same)
                local.append(c.text.strip("\n"))
        used = tokens(body) | tokens("\n".join(local))
        need = {owner[t] for t in used if t in owner and t not in own}
        if headers.get(module):
            need.add(module)
        includes = []
        for m in sorted(need, key=lambda m: (m != module, m)):
            cs = headers.get(m, ())
            if not cs:
                continue
            # (it has a static of a name that header declares; or sparing)
            if any(n in own for c in cs for n in c.names) or (sparing and any(id(c) in extended for c in cs)):
                local += [_declaration(c).strip("\n") for c in cs if set(c.names) & used
                          and not set(c.names) & own and id(c) not in extended]
            else:
                includes.append(f'#include "{m}.h"\n')
        have = tokens("\n".join(local))
        local += [_declaration(of_statics[n]).strip("\n") for n in sorted(used & set(of_statics))
                  if n not in own and n not in have]
        block = (f"\n{_LOCAL}\n" + "\n".join(local) + "\n" if local else "")
        return '#include "common.h"\n' + "".join(includes) + block + body

    # the new headers
    new_common = _SHARED + "\n" + "".join(c.text for c in kept)
    new_headers = {}
    for m, cs in headers.items():
        guard = "FILE_" + re.sub(r"\W", "_", m).upper() + "_H"
        what = f"{m}.c" + (f" (src/{m}/, a file per function)" if (out / "src" / m).is_dir() else "")
        new_headers[m] = (f"/* What the rest of the program reads of {what} */\n#ifndef {guard}\n#define {guard}\n\n"
                          + "".join(_declaration(c) for c in cs) + "\n#endif\n")
    old_files = {p.name: p.read_text(encoding="utf-8") for p in inc.glob("*.h")}
    shared.write_text(new_common, encoding="utf-8")
    for m, text in new_headers.items():
        (inc / f"{m}.h").write_text(text, encoding="utf-8")

    done, fell_back = 0, []
    for rel in rels:
        for sparing in (False, True):
            new = rewritten(rel, sparing) if old_objs[rel] is not None else None
            if new is None:
                break
            obj = _compile(out, tc, out / rel, prelude + list(flags_of[rel]), new)
            if obj is not None and same_code(old_objs[rel], obj, where):
                (out / rel).write_text(new, encoding="utf-8")
                done += 1
                break
        else:
            fell_back.append(rel)
            continue
        if new is None:
            fell_back.append(rel)
    for rel in fell_back + others:
        text = (out / rel).read_text(encoding="utf-8")
        text = re.sub(r'^#include "common\.h"$', '#include "common_full.h"', text, count=1, flags=re.M)
        stem = Path(rel).stem
        if rel in private:
            (inc / f"{stem}_decls.h").write_text(private[rel], encoding="utf-8")
            text = re.sub(rf'^#include "{re.escape(stem)}\.h"$', f'#include "{stem}_decls.h"', text, count=1,
                          flags=re.M)
        (out / rel).write_text(text, encoding="utf-8")
        log(f"{rel}: kept the headers it was matched with (its code changed with the module headers)")
    if fell_back or others:
        (inc / "common_full.h").write_text(old_common, encoding="utf-8")
    # the copies of common.h no file reads any more, and a header of a file the new ones didn't replace
    reads = "\n".join([(out / rel).read_text(encoding="utf-8") for rel in rels + others]
                      + [p.read_text(encoding="utf-8") for p in inc.glob("*.h")])
    for name in old_files:
        if (name.startswith("common_") and name != "common_full.h" or
                (name[:-2] not in new_headers and name != "common.h" and not name.endswith("_decls.h"))) \
                and f'"{name}"' not in reads:
            (inc / name).unlink()
    return done


def redeclared(out: Path):
    """A declaration module_headers left in a file (what its private header said) that a header the file includes
    makes too: dropped, each where the file still compiles to the same code (`extern void xfPush();` beside
    xfstack.h's prototype is the prototype's call)."""
    from ...units import chunks

    def in_headers(text: str) -> set[str]:
        seen, todo = set(), re.findall(r'^#include "([\w.-]+)"', text, re.M)
        names = set()
        while todo:
            name = todo.pop()
            path = out / "include" / name
            if name in seen or not path.exists():
                continue
            seen.add(name)
            header = path.read_text(encoding="utf-8")
            todo += re.findall(r'^#include "([\w.-]+)"', header, re.M)
            names |= {n for c in chunks(header) if c.kind == "extern" for n in c.names}
        return names

    def block(text: str) -> tuple[int, int] | None:
        at = text.find(_LOCAL + "\n")
        if at < 0:
            return None
        start = at + len(_LOCAL) + 1
        end = text.find("\n\n", start)
        return start, (len(text) if end < 0 else end + 1)

    def items(text: str) -> list[tuple[str, str]]:
        span = block(text)
        if span is None:
            return []
        known = in_headers(text)
        return [(c.names[0], c.text) for c in chunks(text[span[0]:span[1]])
                if c.kind == "extern" and c.names and set(c.names) <= known]

    def apply(text: str, chosen) -> str:
        start, end = block(text)
        local = text[start:end]
        for _, decl in chosen:
            local = local.replace(decl, "", 1)
        if not local.strip():
            return text[:start - len(_LOCAL) - 2] + text[end:]
        return text[:start] + local + text[end:]
    return items, apply
