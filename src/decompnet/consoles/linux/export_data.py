"""A Linux program's data as C, file by file, for the export (export.py): each source file's globals, statics and
functions' statics defined in its C file with their types (the debug information's, cheader.Header's names) and
their values (the program's bytes, cdata.Writer), where the file defined them (by line, among its functions), and
judged: the file compiled whole, its code is still the game's (each reference to one of its variables that
variable's address in the game), and each variable is the game's, value for value, every pointer in it pointing at
what the game's does (judge_data). Where GCC 2.95 lays out the constants among the functions' own differently
(its pool's order, a `static const` read by value copied into it), the data needn't be laid out as the game's:
the relinked program takes it from the object, laid out by the linker (53 of a 2001 game's 73 files are anyway).

A file whose data is C carries it: the relinked program takes it from the file's object, not from your copy, and
the file's statics are its own (not the game's, patched in). Where the data can't be written or doesn't come out as
the program's, the file's data stays the program's bytes (data/program.s) and the README says why."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import BytesIO

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ... import cdata

DATA_SECTIONS = (".data", ".rodata", ".bss")


@dataclass
class Definition:
    name: str  # its name in C
    address: int
    size: int
    section: str
    line: int
    text: str  # its definition, `static Foo foo = { ... };`
    forward: str  # what declares it before its definition, for what refers to it first (`static Foo foo;`)
    key: str  # its declaration as units.merge compares declarations (`Foo foo;`)


@dataclass
class FileData:
    definitions: list[Definition] = field(default_factory=list)
    aliases: dict[str, tuple[str, int]] = field(default_factory=dict)  # a name the C reads it by -> (definition, offset)
    # the same for a global's: the relink's linker script makes them (`D_08F78580 = vect_ix;`: an uninitialized global
    # is common, which a newer assembler won't let `.set` name)
    link_aliases: dict[str, tuple[str, int]] = field(default_factory=dict)
    needs: list[str] = field(default_factory=list)  # declarations what the initializers name needs
    problem: str = ""


class Program:
    """The program's debug information, symbols and bytes, read once for the export."""

    def __init__(self, image: bytes):
        from ...app.engine.importing import _HEADER_NAMES
        from ..ps2 import stabs
        from ..ps2.cheader import Header
        from ..ps2.debuginfo import _short_names
        from . import debuginfo

        self.image = image
        self.elf = ELFFile(BytesIO(image))
        stab, strings = self.elf.get_section_by_name(".stab"), self.elf.get_section_by_name(".stabstr")
        units = debuginfo.entries(stab.data(), strings.data()) if stab is not None and strings is not None else []
        short = _short_names([name for name, _ in units])
        self.sources = {short[name]: stabs.read_file(short[name], found, debuginfo.x86_register)
                        for name, found in units}
        self.header = Header(list(self.sources.values()), _HEADER_NAMES)
        self.sections = [(s.name, s["sh_addr"], s["sh_addr"] + s["sh_size"], s) for s in self.elf.iter_sections()
                         if s["sh_addr"] and s["sh_flags"] & 2]
        self.globals: dict[int, list] = {}  # address -> global symbols there (STB_GLOBAL, defined)
        self.symbols: dict[str, object] = {}
        self.object_sizes: dict[int, int] = {}  # address -> the size of the data symbol there
        # each source file's own local symbols (they follow its STT_FILE entry): a static a header defines is one
        # per file that includes it, and the debug information gives the header's entries once, the first file's
        self.locals: dict[str, dict[str, int]] = {}
        current = None
        for sym in self.elf.get_section_by_name(".symtab").iter_symbols():
            if sym["st_info"]["type"] == "STT_FILE":
                current = self.locals.setdefault(sym.name.rsplit("/", 1)[-1], {})
            elif current is not None and sym.name and sym["st_info"]["bind"] == "STB_LOCAL" \
                    and sym["st_info"]["type"] == "STT_OBJECT":
                current.setdefault(sym.name, sym["st_value"])
            if sym.name and sym["st_shndx"] != "SHN_UNDEF":
                self.symbols.setdefault(sym.name, sym)
                if sym["st_info"]["type"] == "STT_OBJECT" and sym["st_size"]:
                    self.object_sizes.setdefault(sym["st_value"], sym["st_size"])
                if sym["st_info"]["bind"] == "STB_GLOBAL" and sym["st_info"]["type"] in ("STT_OBJECT", "STT_FUNC",
                                                                                         "STT_NOTYPE"):
                    self.globals.setdefault(sym["st_value"], []).append(sym)

    def sized(self, t, address: int):
        """`t`, an array of no size given the size of the symbol at `address`."""
        from ..ps2.stabs import Type

        r = self.header._resolve(t)
        size = self.object_sizes.get(address, 0)
        # (an integer the debug information makes `long long` where its symbol and the game's layout say 4 bytes:
        # the symbol's size)
        names = {1: "char", 2: "short int", 4: "int", 8: "long long int"}
        if r.kind == "base" and size and size != self.header.size(t) and size in names:
            return Type(kind="base", name=names[size], size=size, signed=r.signed)
        if r.kind != "array" or r.count or r.target is None:
            return t
        elem = self.header.size(r.target)
        if size and elem and size % elem == 0:
            return Type(kind="array", count=size // elem, target=r.target, size=size)
        return t

    def pointed_at(self):
        """Every word of the program's data that is an address in its data: an index of (target, where)."""
        if getattr(self, "_pointed", None) is None:
            import bisect

            found = []
            data = [(lo, hi, sec) for name, lo, hi, sec in self.sections if name in (".data", ".rodata")
                    and sec["sh_type"] != "SHT_NOBITS"]
            spans = [(lo, hi) for name, lo, hi, _ in self.sections if name in DATA_SECTIONS]
            for lo, hi, sec in data:
                raw = self.image[sec["sh_offset"]:sec["sh_offset"] + hi - lo]
                for at in range(0, len(raw) - 3, 4):
                    word = int.from_bytes(raw[at:at + 4], "little")
                    if any(a <= word < b for a, b in spans):
                        found.append((word, lo + at))
            found.sort()

            class Index:
                def get_range(self, lo: int, hi: int) -> list[tuple[int, int]]:
                    k = bisect.bisect_left(found, (lo, -1))
                    out = []
                    while k < len(found) and found[k][0] < hi:
                        out.append(found[k])
                        k += 1
                    return out
            self._pointed = Index()
        return self._pointed

    def variable_at(self, address: int) -> bool:
        """Whether a variable of any source file's debug information is at `address` (or covers it)."""
        if getattr(self, "_variables", None) is None:
            spans = []
            for unit in self.sources:
                for _, a, t, _, _ in variables(self, unit, {}):
                    spans.append((a, a + max(self.header.size(t), 1)))
            self._variables = sorted(spans)
        import bisect

        k = bisect.bisect_right(self._variables, (address, float("inf"))) - 1
        return k >= 0 and self._variables[k][0] <= address < self._variables[k][1]

    def next_symbol(self, address: int) -> int:
        """The next address after `address` a symbol of the program is at."""
        if getattr(self, "_starts", None) is None:
            self._starts = sorted({s["st_value"] for s in self.elf.get_section_by_name(".symtab").iter_symbols()
                                   if s["st_value"]})
        import bisect

        k = bisect.bisect_right(self._starts, address)
        return self._starts[k] if k < len(self._starts) else address + 32

    def address_of(self, name: str) -> int | None:
        sym = self.symbols.get(name)
        return sym["st_value"] if sym is not None and isinstance(sym["st_shndx"], int) else None

    def section(self, address: int) -> str | None:
        return next((name for name, lo, hi, _ in self.sections if lo <= address < hi), None)

    def read(self, address: int, size: int) -> bytes | None:
        for _, lo, hi, sec in self.sections:
            if lo <= address and address + size <= hi:
                if sec["sh_type"] == "SHT_NOBITS":
                    return bytes(size)
                at = sec["sh_offset"] + address - lo
                return self.image[at:at + size]
        return None

    def global_at(self, address: int) -> tuple[object, int] | None:
        """The global symbol a data address is in: (symbol, offset)."""
        if address in self.globals:
            return self.globals[address][0], 0
        for start, found in self.globals.items():
            sym = found[0]
            if sym["st_info"]["type"] == "STT_OBJECT" and start < address < start + sym["st_size"]:
                return sym, address - start
        return None


_DECLARED: dict[int, dict[str, set[str]]] = {}


def header_declarations(shared: str) -> dict[str, set[str]]:
    """{name: its declarations as compared} for the shared header's one-line externs of variables."""
    from ...tidy import _key
    from ...units import chunks

    if id(shared) not in _DECLARED:
        found: dict[str, set[str]] = {}
        for line in shared.splitlines():
            if _one_line_extern(line):
                for name in chunks(line + "\n")[0].names:
                    found.setdefault(name, set()).add(_key(line))
        _DECLARED.clear()
        _DECLARED[id(shared)] = found
    return _DECLARED[id(shared)]


def _sizeless(key: str) -> str:
    """A declaration with its arrays' sizes left out: `char name[15];` is the header's `char name[];`."""
    return re.sub(r"\[\s*\w*\s*\]", "[]", key)


def without_externs(header: str, names: set[str]) -> str:
    """`header` without its one-line externs of `names` (what a file defines static itself)."""
    from ...units import chunks

    if not names:
        return header
    out = []
    for line in header.splitlines(keepends=True):
        if _one_line_extern(line) and set(chunks(line if line.endswith("\n") else line + "\n")[0].names) & names:
            continue
        out.append(line)
    return "".join(out)


def _one_line_extern(line: str) -> bool:
    """`extern V2Vertex ClipVVert2[9];     /* a comment */`: a variable's declaration on one line."""
    from ... import cfields

    flat = cfields._COMMENT.sub(" ", line).strip()
    # (a pointer to functions is a variable too: `extern void (*main_looping_function)(void);`)
    return flat.startswith("extern ") and flat.endswith(";") and ("(" not in flat or bool(re.search(r"\(\s*\*", flat)))


def variables(program: Program, unit: str, functions: dict[int, str]) -> list[tuple[str, int, object, float, str]]:
    """The file's variables: (C name, address, type, line, storage: G, S or L for a function's static). A function's
    static is just before the function (GCC 2.95 writes it out where its declaration is, before the function's own
    constants); an array the debug information leaves without a size (`int table[]`) has its symbol's."""
    source = program.sources.get(unit)
    if source is None:
        return []
    out = []
    for v in source.globals:
        sym = program.symbols.get(v.name)
        if sym is not None and sym["st_info"]["type"] == "STT_OBJECT":
            out.append((v.name, sym["st_value"], program.sized(v.type, sym["st_value"]), v.line, "G"))
    mine = program.locals.get(unit.rsplit("/", 1)[-1], {})
    for v in source.statics:
        address = mine.get(v.name, v.address)  # (this file's copy of a static its header defines)
        if address:
            out.append((v.name, address, program.sized(v.type, address), v.line, "S"))
    for f in source.functions:
        for v in f.locals:
            if v.where == "static" and v.address:
                out.append((f"{functions.get(f.address, f.name)}_{v.name}", v.address, program.sized(v.type, v.address),
                            f.line - 0.5, "L"))
    return sorted(out, key=lambda v: (v[3], v[1]))


def file_data(program: Program, unit: str, functions: dict[int, str], code: str, shared: str,
              taken: dict[int, str], syms, as_globals: bool = False, elsewhere: set[str] = frozenset()) -> FileData:
    """The definitions of the file's variables (none for what its functions' C defines already: `taken`, the
    addresses of their statics), the names its C reads them by otherwise (D_080B8B81), and what the initializers
    need declared. `as_globals`: its statics global too (a file of data alone, src/<file>/data.c, beside a source
    file's functions one file each: they reach them by name)."""
    h = program.header
    found = FileData()
    own: dict[int, tuple[str, int]] = {}  # address -> (name, size), what this file defines
    plan = []
    in_header = header_declarations(shared)
    from ...tidy import _key as key_of
    for name, address, t, line, storage in variables(program, unit, functions):
        if address in taken:
            continue
        size = h.size(t)
        section = program.section(address)
        if section not in DATA_SECTIONS or size <= 0 or not h.complete(t):
            found.problem = f"{name}'s type isn't one C can define here"
            return found
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            name = re.sub(r"\W", "_", name)
        other = syms.resolve(name) if syms is not None else None
        kept = cdata.constant(h, t) if section == ".rodata" else t
        # a name the C means another global by, or the shared header declares as another type (the C reads
        # `version.Coins` of a `char *version`): a name of its own, and the C's name made the same address
        if (other is not None and other != address) or (name in in_header and {_sizeless(k) for k in in_header[name]}
                                                                 != {_sizeless(key_of(h.declaration(kept, name) + ";"))}):
            name = f"{name}_{address:08X}"
        if any(name == other for other, _ in own.values()):  # (two inner blocks' `static float x0;`: two variables)
            name = f"{name}_{address:08X}"
        own[address] = (name, size)
        plan.append((name, address, t, line, storage, size, section))
    starts = sorted(own)
    import bisect

    def mine(address: int) -> tuple[str, int] | None:
        k = bisect.bisect_right(starts, address) - 1
        if k >= 0 and address < starts[k] + own[starts[k]][1]:
            return own[starts[k]][0], address - starts[k]
        return None
    declared_text = shared

    def declared(name: str) -> bool:
        """Whether the shared header, or the file outside its functions, declares it (a function the C only calls
        isn't declared where the values are)."""
        pattern = rf"^(?:extern\s+)?[A-Za-z_][^;{{}}()#\n]*[\s*]{re.escape(name)}\s*(?:\([^;{{}}]*\)|\[[^;{{}}]*\])?\s*;"
        return re.search(pattern, declared_text, re.M) is not None or re.search(pattern, code, re.M) is not None

    def pointer(word: int, ptype) -> str | None:
        cast = "(" + h.declaration(ptype, "") + ")"
        target = h._resolve(ptype.target) if ptype.target is not None else None
        hit = mine(word)
        if hit is not None:
            name, off = hit
            return f"{cast}&{name}" if not off else f"{cast}((char *)&{name} + {off})"
        if word in functions:  # (the file's own function, a static one too: declared as defined)
            return f"{cast}{functions[word]}"
        glob = program.global_at(word)
        if glob is not None:
            sym, off = glob
            name = sym.name
            if not declared(name):
                found.needs.append(f"extern char {name}[];" if sym["st_info"]["type"] == "STT_OBJECT"
                                   else f"extern int {name}();")
                declared_text_add(name)
            if sym["st_info"]["type"] != "STT_OBJECT":  # (a function, or hand-written code's label)
                return f"{cast}{name}" if not off else None
            return f"{cast}&{name}" if not off else f"{cast}((char *)&{name} + {off})"
        if program.section(word) == ".rodata":  # a string literal, the file's own
            raw = program.read(word, 1)
            end = word
            while raw is not None and raw != b"\0" and end - word < 4096:
                end += 1
                raw = program.read(end, 1)
            text = program.read(word, end - word) if raw == b"\0" else None
            if text is not None and all(b in cdata.TEXT for b in text):
                literal = cdata.string_literal(text)
                char = target is not None and target.kind == "base" and h.size(target) == 1
                return literal if char else f"{cast}{literal}"
        return None

    def declared_text_add(name: str) -> None:
        nonlocal declared_text
        declared_text += f"\n{name};"

    writer = cdata.Writer(h, pointer)
    for name, address, t, line, storage, size, section in plan:
        kept = cdata.constant(h, t) if section == ".rodata" else t
        decl = h.declaration(kept, name)
        static = "static " if storage != "G" and not as_globals else ""
        if section == ".bss":
            text = f"{static}{decl};"
        else:
            data = program.read(address, size)
            try:
                value = writer.value(t, data, address)
            except cdata.Unwritable as e:
                found.problem = f"{name}: {e}"
                return found
            text = f"{static}{decl} = {value};"
        forward = f"{static}{decl};" if static else f"extern {decl};"
        from ...tidy import _key

        found.definitions.append(Definition(name, address, size, section, line, text, forward, _key(f"{decl};")))
    # the names the file's C reads them by that aren't theirs (an address's automatic name, another symbol's name)
    from ...rom.symbols import AUTO_NAME

    names = {d.name for d in found.definitions}
    # (and what the rest of the tree's C reads them by: another file's function naming this one's static)
    for word in set(re.findall(r"\b[A-Za-z_]\w*\b", code)) | set(elsewhere):
        if word in names:
            continue
        m = AUTO_NAME.match(word)
        address = int(m.group(1), 16) if m else syms.resolve(word) if syms is not None else None
        if address is None:
            continue
        hit = mine(address)
        if hit is not None:  # (a project symbol's name: `texComb_267`, the program's `texComb.267`)
            found.aliases[word] = hit
    # a constant the C reads by its address's name (`*(double *)D_080A9C88`: a function's own, in the game's pool,
    # that no variable is): its bytes as this file's, read-only data no other file's C can change, so a copy of it
    # is the same thing (the build has no copy of the program's to read it from)
    for d in constants(program, code, mine, syms):
        found.definitions.append(d)
        own[d.address] = (d.name, d.size)
        found.aliases[d.name[:-len("_data")]] = (d.name, 0)
    starts[:] = sorted(own)
    globals_ = {d.name for d in found.definitions if not d.forward.startswith("static")}
    for word in [w for w, (base, _) in found.aliases.items() if base in globals_]:
        found.link_aliases[word] = found.aliases.pop(word)
    # a static the rest of the program's data points at (a table of another file's): a name of its own, global, that
    # data/program.s writes the pointer by (the static's own name may be another file's too: rcsid)
    statics = {d.name: d for d in found.definitions if d.forward.startswith("static")}
    pointed = program.pointed_at()
    for d in statics.values():
        for word in pointed.get_range(d.address, d.address + d.size):
            if not any(o.address <= word[1] < o.address + o.size for o in found.definitions):  # (from outside)
                alias = f"{d.name}_{d.address:08X}" if not d.name.endswith(f"_{d.address:08X}") else f"{d.name}_"
                found.aliases.setdefault(alias, (d.name, 0))
                break
    # a static another name is `.set` to is used, as far as a newer GCC knows (it would drop it, or fold its value)
    mark_used(found, [base for base, _ in found.aliases.values()])
    return found


def mark_used(data: FileData, names) -> bool:
    """`__attribute__((used))` on the file's statics among `names` (GCC 2.95 ignores it, saying so): what another
    name reaches. Whether any was marked now."""
    names, changed = set(names), False
    for d in data.definitions:
        if d.name in names and d.text.startswith("static ") and "__attribute__((used))" not in d.text:
            decl = d.forward[len("static "):].rstrip(";")
            d.text = d.text.replace(f"static {decl}", f"static {decl} __attribute__((used))", 1)
            changed = True
    return changed


WIDTHS = {"char": 1, "short": 2, "int": 4, "long": 4, "float": 4, "double": 8, "long long": 8}


def constants(program: Program, code: str, mine, syms) -> list[Definition]:
    """The read-only constants `code` reads by an address's generated name (D_080A9C88) that are no variable's:
    each a `char` array of the program's bytes, up to the next thing anything names (or as far as the C reads it)."""
    from ...rom.symbols import AUTO_NAME
    from ...tidy import _key

    names: dict[int, str] = {}  # address -> the name the C reads it by (D_080A9C88, or a name given it: gl_modulate_f)
    for word in set(re.findall(r"\b[A-Za-z_]\w*\b", code)):
        m = AUTO_NAME.match(word)
        address = int(m.group(1), 16) if m else syms.resolve(word) if syms is not None else None
        sym = None if m else syms.by_name.get(word)
        if address is not None and (m is None or word.startswith("D_")) and (m or (sym is not None and sym.kind != "func")):
            names.setdefault(address, word)
    wanted = sorted(a for a in names if program.section(a) == ".rodata" and mine(a) is None
                    and not program.variable_at(a))
    if not wanted:
        return []
    out = []
    for k, address in enumerate(wanted):
        width = max([WIDTHS.get(" ".join(t.split()).replace("unsigned ", "").replace("signed ", ""), 1)
                     for t in re.findall(rf"\(\s*((?:unsigned\s+|signed\s+)?(?:char|short|int|long long|long|float|double))"
                                         rf"\s*\*\s*\)\s*\(?\s*&?{re.escape(names[address])}\b", code)] or [4])
        nxt = min([b for b in wanted[k + 1:]] + [program.next_symbol(address), address + 32])
        size = max(width, min(nxt - address, 32))
        if out and out[-1].address + out[-1].size > address:  # (inside the one before, read wider: part of it)
            continue
        data = program.read(address, size)
        if data is None:
            continue
        name = f"{names[address]}_data"  # (the C's D_080A9C88, declared as whatever it reads: the same address)
        text = f"char {name}[{size}] = {{ {', '.join(str(b if b < 128 else b - 256) for b in data)} }};"
        out.append(Definition(name, address, size, ".rodata", 0, text, f"extern char {name}[];", _key(f"char {name}[];")))
    return out


def forward(data: FileData) -> str:
    """What goes before the file's functions: each variable declared (a static's first declaration decides its
    place in .bss: GCC 2.95 lays them out in that order, so they're declared from the lowest address up), what the
    values name, and the names the C reads them by."""
    bss = sorted((d for d in data.definitions if d.section == ".bss" and d.forward.startswith("static")),
                 key=lambda d: d.address)
    rest = [d for d in data.definitions if d not in bss]
    return "".join(f"{d.forward}\n" for d in bss + rest) + "".join(f"{n}\n" for n in data.needs) + aliases_asm(data.aliases)


def aliases_asm(aliases: dict[str, tuple[str, int]]) -> str:
    """The names the C reads a variable by that aren't its own, made its symbol (`D_080B8B81` for a function's
    static, written `drawText_count`): the same address, global so the rest of the program finds it by that name."""
    if not aliases:
        return ""
    lines = "".join(f"\\n\\t.globl {n}\\n\\t.set {n}, {d}{f'+{off}' if off else ''}"
                    for n, (d, off) in sorted(aliases.items()))
    return f'__asm__("{lines[4:]}");  /* the names the C reads these by */\n'


def read_by_code(obj: bytes, definitions: list[Definition], placements: dict[str, dict[int, int]]) -> list[Definition]:
    """The object's other variables (its functions' own statics, which they define themselves), each where the game
    has it by what the code reads of it: so they're checked and placed as the file's own data is."""
    elf = ELFFile(BytesIO(obj))
    known = {d.name for d in definitions}
    out = []
    for sym in elf.get_section_by_name(".symtab").iter_symbols():
        if not sym.name or sym.name in known or sym["st_info"]["type"] != "STT_OBJECT" \
                or not isinstance(sym["st_shndx"], int) or not sym["st_shndx"]:
            continue
        sec = elf.get_section(sym["st_shndx"]).name
        if sec not in DATA_SECTIONS:
            continue
        lo, size = sym["st_value"], max(sym["st_size"], 1)
        at = next((off for off in sorted(placements.get(sec, {})) if lo <= off < lo + size), None)
        if at is not None:
            out.append(Definition(sym.name, placements[sec][at] - (at - lo), sym["st_size"], sec, 0, "", "static", ""))
    return out


def placer(obj: bytes, definitions: list[Definition]):
    """`placed(section, offset)` for the judge (x86_link.link): where the game has a byte of one of the file's
    variables in the object, or None."""
    elf = ELFFile(BytesIO(obj))
    by_name = {d.name: d for d in definitions}
    spans: dict[str, list[tuple[int, int, int]]] = {}
    for sym in elf.get_section_by_name(".symtab").iter_symbols():
        if sym.name in by_name and isinstance(sym["st_shndx"], int) and sym["st_shndx"]:
            spans.setdefault(elf.get_section(sym["st_shndx"]).name, []).append(
                (sym["st_value"], max(sym["st_size"], 1), by_name[sym.name].address))

    def placed(section: str, offset: int) -> int | None:
        for start, size, address in spans.get(section, ()):
            if start <= offset < start + size:
                return address + offset - start
        return None
    return placed


def judge_data(obj: bytes, definitions: list[Definition], resolve, read, text_at: int | None = None) -> \
        tuple[str, bool]:
    """Whether the file's data, compiled, is the game's: each variable's bytes the game's, every address in them
    pointing at what the game's points at (a symbol at its address, one of the file's variables where the game has
    it, a string literal holding the game's string there), its .bss variables as large. ("" and whether its data
    sections are also laid out as the game's, each in one place; or what differs.) Where the compiler puts its
    constants among the functions' own (GCC 2.95's pool of a function's strings, a `static const` read by value
    copied there) the program doesn't depend on, nor on where a section's variables are; the relinked program takes
    the data from this object, laid out by the linker. `text_at`: where the object's code starts in the game."""
    elf = ELFFile(BytesIO(obj))
    symtab = elf.get_section_by_name(".symtab")
    by_name = {d.name: d for d in definitions}
    sections = list(elf.iter_sections())
    syms = {s.name: s for s in symtab.iter_symbols() if s.name in by_name and isinstance(s["st_shndx"], int)}
    # where the game has each piece of each section: (section index) -> [(offset, size, address)]
    places: dict[int, list[tuple[int, int, int]]] = {}
    for name, sym in syms.items():
        places.setdefault(sym["st_shndx"], []).append((sym["st_value"], max(sym["st_size"], 1), by_name[name].address))

    def game_address(shndx: int, offset: int) -> int | None:
        for start, size, address in places.get(shndx, ()):
            if start <= offset < start + size:
                return address + offset - start
        return None

    relocs: dict[int, list] = {}
    for rsec in sections:
        if isinstance(rsec, RelocationSection):
            relocs.setdefault(rsec["sh_info"], []).append(rsec)
    for d in definitions:
        sym = syms.get(d.name)
        if sym is None:
            if d.section == ".bss":
                continue  # (a global's tentative definition: common, the linker's)
            return f"the object doesn't define {d.name}", False
        if sym["st_size"] != d.size:
            return f"{d.name} is {sym['st_size']} bytes in the object, {d.size} in the game", False
        sec = sections[sym["st_shndx"]]
        if sec["sh_type"] == "SHT_NOBITS":
            continue
        start = sym["st_value"]
        mine = bytearray(sec.data()[start:start + d.size])
        game = read(d.address, d.size)
        if game is None:
            return f"the game has no data where {d.name} is", False
        pointers = set()
        for rsec in relocs.get(sym["st_shndx"], ()):
            rsym = sections[rsec["sh_link"]]
            for rel in rsec.iter_relocations():
                at = rel["r_offset"] - start
                if not 0 <= at < d.size:
                    continue
                if rel["r_info_type"] != 1:
                    return f"{d.name} holds an address of a kind this check doesn't read", False
                pointers.add(at)
                target = rsym.get_symbol(rel["r_info_sym"])
                addend = int.from_bytes(mine[at:at + 4], "little")
                want = int.from_bytes(game[at:at + 4], "little")
                shndx = target["st_shndx"]
                offset = addend + (0 if target["st_info"]["type"] == "STT_SECTION" else target["st_value"])
                if isinstance(shndx, int) and shndx and sections[shndx].name == ".text":
                    value = (text_at + offset) if text_at is not None and target["st_info"]["type"] == "STT_SECTION" \
                        else (resolve(target.name) + addend if resolve(target.name) is not None else None)
                    ok = value == want
                elif isinstance(shndx, int) and shndx:
                    value = game_address(shndx, offset)
                    if value is not None:
                        ok = value == want
                    else:  # a literal of its own: the game's pointer holds a string of the same bytes there
                        raw = sections[shndx].data()
                        end = raw.find(b"\0", offset)
                        text = raw[offset:end + 1] if end >= 0 else raw[offset:]
                        ok = bool(text) and read(want, len(text)) == text
                else:
                    value = by_name[target.name].address + addend if target.name in by_name else \
                        (resolve(target.name) + addend if resolve(target.name) is not None else None)
                    ok = value == want
                if not ok:
                    return (f"{d.name}+0x{at:X} points at {target.name or sections[shndx].name}+0x{offset:X}, the "
                            f"game's at 0x{want:X}"), False
        for at in range(d.size):
            if any(p <= at < p + 4 for p in pointers):
                continue
            if mine[at] != game[at]:
                return (f"{d.name}+0x{at:X} differs from the game's: yours {bytes(mine[at:at + 8]).hex(' ')}, the "
                        f"game's {game[at:at + 8].hex(' ')}"), False
    # and whether each data section is in one place in the game, as the game's file had it
    laid_out = all(len({address - start for start, _, address in found}) == 1 for found in places.values())
    return "", laid_out
