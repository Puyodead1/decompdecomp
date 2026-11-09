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


PASSES = (("names the linker script gave", linked_names), ("helpers made each file's own", own_helpers),
          ("addresses written as numbers", numbered_addresses), ("the C library's tables read as calls", library_tables),
          ("functions called by their own names", called_by_name), ("variables by one name", set_names))
ITEMIZED = {called_by_name, set_names}  # (passes whose changes are kept one by one: items, apply)


def clean(out: Path, build: dict, tc: Path, log=print) -> dict[str, int]:
    """Each pass over each C source file of the tree, kept where the file still compiles to the same code. Returns
    how many files each pass changed."""
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
                if make is set_names else make(build)
            count, refused = _itemized(out, tc, files, prelude, where, title, made[0], made[1], log,
                                       made[2] if len(made) > 2 else None)
            if len(made) > 2 and count:
                (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
            changed[title] = count
            log(f"{title}: written as C in {count} files" + (f" ({refused} kept as they were)" if refused else ""))
            continue
        rewrite = make(build, out) if make is numbered_addresses else make(build)
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
            for new in (rewrite(text, rel) if make is numbered_addresses else rewrite(text)):
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
