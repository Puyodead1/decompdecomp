"""Export a Linux program's project as a rebuildable source tree: the base for ports and mods.

The program's source files as C (src/<source file>.c: each file whose functions all match, merged by units.py and
judged whole against the game's span of it; the others one function per file, src/<source file>/<function>.c), the
shared types in include/, and a build (export_build.py, copied as build.py) that compiles each with the pinned GCC
exactly as the judge did, links it at its address in the program with the toolchain's own ld (its own constants
placed where the game keeps them, the rest of the game's symbols at their addresses), puts its code in place in a
copy of your program and checks the result against the original, byte for byte. What isn't C yet stays your copy's
bytes. The Makefile (export_make.py) links a new program from the same C without decompdecomp, and `make port`
builds it with the system's GCC.

Relinking the whole program (its dynamic sections, PLT and GOT, as the 2001 linker laid them out) is left for when
all of its code is C: until then, the code is rebuilt function by function where it lies, as GBA's tree places its
pieces."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from io import BytesIO
from pathlib import Path

from elftools.elf.elffile import ELFFile

from ...limits import capped
from ...project import compiler_for
from ...rom.export import exported_header, exported_source
from ...rom.symbols import AUTO_NAME
from ...toolchains import registry as toolchain_registry
from ...units import only_own
from . import export_float, export_make


def _unit_name(unit: str | None) -> str:
    """A source file's folder and header name: `game.c` -> game, `src/zlib/inflate.c` -> inflate."""
    return re.sub(r"\W", "_", Path(unit or "program").stem) or "program"


def _statics(obj: bytes, placements: dict[str, dict[int, int]]) -> dict[str, int]:
    """The writable data the function's C defines itself (a file's statics, `x.12` for one inside a function), by
    name, where the game keeps it: the relinked program reads and writes the game's, shared by the file's functions,
    not a copy of its own. Names, not offsets: a static someone adds moves the others' offsets. A section laid out
    as the game's gives every static of it; else each static the code reads is where the code reads it (a source
    file's statics, compiled whole, in another order than the game's)."""
    elf = ELFFile(BytesIO(obj))
    out = {}
    for name, offsets in placements.items():
        sec = elf.get_section_by_name(name)
        if sec is None or not sec["sh_flags"] & 1:  # (SHF_WRITE)
            continue
        bases = {addr - off for off, addr in offsets.items()}
        index = elf.get_section_index(name)
        for sym in elf.get_section_by_name(".symtab").iter_symbols():
            if not (sym.name and sym["st_shndx"] == index and sym["st_info"]["type"] == "STT_OBJECT"):
                continue
            lo, hi = sym["st_value"], sym["st_value"] + max(sym["st_size"], 1)
            if len(bases) == 1:
                out[sym.name] = next(iter(bases)) + lo
            elif (at := next((off for off in sorted(offsets) if lo <= off < hi), None)) is not None:
                out[sym.name] = offsets[at] - (at - lo)
    return out


def _refs(row, syms) -> dict[int, str]:
    """What a function that isn't C refers to out of itself, by name: {offset of the word: its expression} (a call's
    `name - . - 4`, an address's `name+off`). Kept in build.json: tools/relink.py writes asm/ from your copy's bytes
    with it (asm/ is your copy's code, never in git)."""
    import json as _json

    code, vram, name = bytes(row["target"]), row["vram"], row["name"]
    refs = {}
    for at, kind, dest in _json.loads(row["relocs"] or "[]"):
        if kind == 2 and vram <= dest < vram + len(code):
            continue  # (a jump inside it: the same distance wherever it is)
        label, off = (name, dest - vram) if vram <= dest < vram + len(code) else syms.name_at(dest)
        target = f"{label}{f'+{off}' if off else ''}"
        refs[at] = f"{target} - . - 4" if kind == 2 else target
    return refs


def _own_constants(name: str, code: bytes, vram: int, refs: dict[int, str], syms, image: bytes):
    """The constants a function that isn't C reads by their address in the program's .rodata and no symbol names (the
    `.LC` doubles GCC wrote for it: `fldl 0x804b1f0`), as its own: (its references with those words by a label of its,
    the .rodata it carries, where the program has that), or None. As numbers, the relinked program and the plain
    builds read whatever was there (a 1999 program's volume read its own code's bytes in the plain build, and crashed
    relinked)."""
    import capstone

    elf = ELFFile(BytesIO(image))
    rodata = elf.get_section_by_name(".rodata")
    if rodata is None:
        return None
    lo_ro, hi_ro = rodata["sh_addr"], rodata["sh_addr"] + rodata["sh_size"]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    found: dict[int, tuple[int, int]] = {}  # offset of the word -> (address, size read)
    for ins in md.disasm(code, vram):
        for o in ins.operands:
            if o.type != capstone.x86.X86_OP_MEM or o.mem.base or o.mem.index or not ins.disp_offset:
                continue
            at, dest = ins.address - vram + ins.disp_offset, o.mem.disp & 0xFFFFFFFF
            if at in refs or not lo_ro <= dest < hi_ro or not syms.name_at(dest)[0].startswith("D_"):
                continue
            found[at] = (dest, max(o.size, 1))
    if not found:
        return None
    lo = min(a for a, _ in found.values())
    hi = min(hi_ro, max(a + n for a, n in found.values()))
    if hi - lo > 512:  # (constants a function wrote together, not a table of the file's)
        return None
    blob = image[rodata["sh_offset"] + lo - lo_ro:rodata["sh_offset"] + hi - lo_ro]
    labels = {a: f".L{name}_c{a:x}" for a, _ in found.values()}
    lines = [".section .rodata", ".align 4"]
    cuts = sorted({a - lo for a in labels} | {0, len(blob)})
    for start, end in zip(cuts, cuts[1:]):
        if lo + start in labels:
            lines.append(f"{labels[lo + start]}:")
        for off in range(start, end, 8):
            lines.append(f"\t.byte {', '.join(f'0x{b:02x}' for b in blob[off:min(off + 8, end)])}")
    return {**refs, **{at: labels[dest] for at, (dest, _) in found.items()}}, "\n".join(lines) + "\n", lo


def assembly(name: str, code: bytes, refs: dict[int, str]) -> str:
    """A function that isn't C as GNU assembly: its bytes, each word in `refs` by name (the relinked program moves
    the code, so a number would point at nothing). (tools/relink.py has the same, for a checkout without asm/.)"""
    lines, i = [f".text\n.globl {name}\n.type {name},@function\n{name}:\n"], 0
    while i < len(code):
        if i in refs:
            lines.append(f".long {refs[i]}\n")
            i += 4
            continue
        stop = min([len(code), i + 16] + [a for a in refs if a > i])
        lines.append(f".byte {', '.join(str(b) for b in code[i:stop])}\n")
        i = stop
    return "".join(lines)


def _unaligned_text(obj: bytes) -> bytes:
    """The object with its .text aligned to 1 (as build.py's unaligned_text)."""
    elf = ELFFile(BytesIO(obj))
    out = bytearray(obj)
    for i, section in enumerate(elf.iter_sections()):
        if section.name == ".text":
            at = elf["e_shoff"] + i * elf["e_shentsize"] + 32  # Elf32_Shdr.sh_addralign
            out[at:at + 4] = (1).to_bytes(4, "little")
    return bytes(out)


def assembly_source(name: str, code: bytes, vram: int, refs: dict[int, str], names: dict[str, int], toolchain: str,
                    work: Path, constants: tuple[str, int] | None = None) -> str | None:
    """A function that isn't C as GNU assembly (arch/x86_gas.py), assembled and linked where the program has it
    with the toolchain's own as and ld and compared with its bytes: what comes out otherwise stays bytes, an
    instruction at a time, and is checked again. None where it doesn't come out as the program's code. `constants`:
    the .rodata it carries (_own_constants) and where the program has it, linked there for the check."""
    import tempfile

    from ... import toolchains
    from ...arch import x86_gas
    from ...compiler import run_in
    from ...project import compiler_config

    if toolchains.installed(toolchain) is None:
        return None
    tc = toolchains.ensure(toolchain, log=lambda *_: None)
    keep: set[int] = set()
    starts = [i.address for i in x86_gas.instructions(code, vram)]
    for _ in range(len(starts) + 1):
        text = x86_gas.source(name, code, vram, refs, keep) + (constants[0] if constants else "")
        used = set(re.findall(r"[A-Za-z_][\w.]*", " ".join(refs.values()))) - {name}
        assigns = "".join(f"{n} = 0x{names[n]:X};\n" for n in sorted(used) if n in names)
        with tempfile.TemporaryDirectory(prefix="asm-", dir=work) as tmp:
            d = Path(tmp)
            (d / "f.s").write_text(text, encoding="utf-8")
            own = f"  .rodata 0x{constants[1]:X} : {{ f.o(.rodata) }}\n" if constants else ""
            (d / "f.ld").write_text(f"SECTIONS {{\n  .text 0x{vram:X} : {{ f.o(.text) }}\n{own}  /DISCARD/ : {{ *(.comment) "
                                    f"*(.note*) }}\n}}\n{assigns}", encoding="utf-8")
            cfg = compiler_config(d, {"compiler": {"toolchain": toolchain}})
            env = f'export LD_LIBRARY_PATH="{tc}/binutils/usr/lib${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"; '
            res = run_in(cfg, d, ["/bin/sh", "-c", env + f'"{tc}/binutils/usr/bin/as" -o f.o f.s'])
            if res.returncode == 0 and (d / "f.o").exists():
                # (its .text aligned to 1, so ld puts it exactly at the function's address, which needn't be a word's)
                (d / "f.o").write_bytes(_unaligned_text((d / "f.o").read_bytes()))
                res = run_in(cfg, d, ["/bin/sh", "-c", env + f'"{tc}/binutils/usr/bin/ld" -m elf_i386 -e 0 -T f.ld '
                                      '-o f.elf f.o'])
            built = None
            if res.returncode == 0 and (d / "f.elf").exists():
                linked = ELFFile(BytesIO((d / "f.elf").read_bytes()))
                sec = linked.get_section_by_name(".text")
                built = sec.data() if sec is not None else None
                # (as long as the function is: .size, not the padding gas puts after it)
                size = next((s_["st_size"] for s_ in linked.get_section_by_name(".symtab").iter_symbols()
                             if s_.name == name), 0)
                if built is not None and size:
                    built = built[:size]
        if built is not None and built[:len(code)] == code and len(built) - len(code) < 16:
            return text  # (the assembler pads its .text to its alignment, with a no-op of its own)
        if built is None:
            return None
        wrong = {max((s for s in starts if s <= at), default=0) for at in range(min(len(built), len(code)))
                 if built[at] != code[at]}
        if len(built) < len(code) or (wrong and len(built) - len(code) >= 16):
            # (an instruction gas made another length, `movl %eax, (%esp)` without the original's zero offset: the
            # rest has moved, so only the first that differs is known to)
            if wrong:
                wrong = {min(wrong)}
        if not wrong - keep:
            return None
        keep |= wrong
    return None


def _layout(elf, functions: list[dict]) -> dict:
    """The program's layout as the relink's linker script needs it: whether it's dynamic, the function it starts at,
    its lowest address, where the relinked code goes (above its data), and its data sections."""
    data = [[s.name, s["sh_addr"], s["sh_addr"] + s["sh_size"]] for s in elf.iter_sections()
            if s.name in (".rodata", ".data", ".bss") and s["sh_addr"]]
    end = max((hi for _, _, hi in data), default=0)
    starts = {f["vram"]: f["name"] for f in functions}
    return {"dynamic": elf.get_section_by_name(".interp") is not None, "entry": starts.get(elf["e_entry"]),
            # (the loaded sections': a 1999 linker left a .note it doesn't load at 0x319, and the relinked program's
            # headers went to address 0)
            "low": min(s["sh_addr"] for s in elf.iter_sections() if s["sh_addr"] and s["sh_flags"] & 2) & ~0xFFF,
            "code": (end + 0xFFFFF) & ~0xFFFFF, "data": data}


def _imported(undefined: bool, weak: bool, copied: bool, value: int) -> bool:
    """Whether a dynamic symbol is one the program imports: undefined in it, or a copy of a library's variable it
    has (R_386_COPY); not a weak one with no address in the program (__gmon_start__: nobody need define it). A 1999
    linker made glibc's weak aliases weak imports (malloc, open, read), each at its PLT entry: those are imports, or
    the relink stopped at "undefined reference to `malloc'"."""
    if not undefined and not copied:
        return False
    return copied or not weak or bool(value)


def _imports(elf) -> dict:
    """What the program imports, for the relink's stubs: {"needed": [libraries], "symbols": [[name, library,
    version or "", kind (1 data, 2 function), size]]}, an import the dynamic linker copies into the program (R_386_COPY:
    stdout) among them."""
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.gnuversions import GNUVerNeedSection, GNUVerSymSection
    from elftools.elf.relocation import RelocationSection

    needed = [t.needed for s in elf.iter_sections() if isinstance(s, DynamicSection) for t in s.iter_tags()
              if t.entry.d_tag == "DT_NEEDED"]
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return {"needed": needed, "symbols": []}
    versions: dict[int, tuple[str, str]] = {}
    versym = None
    for s in elf.iter_sections():
        if isinstance(s, GNUVerNeedSection):
            for need, auxes in s.iter_versions():
                for aux in auxes:
                    versions[aux["vna_other"]] = (need.name, aux.name)
        elif isinstance(s, GNUVerSymSection):
            versym = s
    copies = {r["r_info_sym"] for s in elf.iter_sections() if isinstance(s, RelocationSection)
              and s["sh_link"] == elf.get_section_index(".dynsym") for r in s.iter_relocations() if r["r_info_type"] == 5}
    plain = next((lib for lib in needed if lib not in {v[0] for v in versions.values()}), needed[0] if needed else "")
    out = []
    for k, sym in enumerate(dynsym.iter_symbols()):
        undefined = sym["st_shndx"] == "SHN_UNDEF"
        if not sym.name or not _imported(undefined, sym["st_info"]["bind"] == "STB_WEAK", k in copies,
                                         sym["st_value"]):
            continue
        ndx = versym.get_symbol(k)["ndx"] if versym is not None else 0
        ndx = ndx & 0x7FFF if isinstance(ndx, int) else 0
        lib, version = versions.get(ndx, (plain, ""))
        out.append([sym.name, lib, version, 1 if sym["st_info"]["type"] == "STT_OBJECT" else 2, sym["st_size"]])
    return {"needed": needed, "symbols": out}


def _runtime_names(toolchain: str) -> set[str]:
    """What the toolchain's C runtime objects define (_start, _init): the relinked program's link brings them."""
    from ... import toolchains

    found = toolchains.installed(toolchain)
    if found is None:
        return set()
    tc = toolchains.path(toolchain)
    objects = [obj.read_bytes() for obj in [*(tc / "crt").glob("crt[1in].o"), *tc.glob("gcc/usr/lib/**/crt*.o")]]
    nonshared = tc / "crt" / "libc_nonshared.a"  # (and libc_nonshared.a's members: glibc's atexit, -fPIC)
    raw = nonshared.read_bytes() if nonshared.exists() else b""
    at = 8 if raw.startswith(b"!<arch>\n") else len(raw)
    while at + 60 <= len(raw):
        size = int(raw[at + 48:at + 58].decode().strip() or 0)
        if raw[at + 60:at + 64] == b"\x7fELF":
            objects.append(raw[at + 60:at + 60 + size])
        at += 60 + size + (size & 1)
    names = set()
    for obj in objects:
        symtab = ELFFile(BytesIO(obj)).get_section_by_name(".symtab")
        names |= {s.name for s in (symtab.iter_symbols() if symtab else ()) if s.name and s["st_shndx"] != "SHN_UNDEF"
                  and s["st_info"]["bind"] != "STB_LOCAL"}
    return names


def _unlisted(image: bytes, functions: list[dict], syms, build_toolchain: str = "") -> list[dict]:
    """Code in .text that no function covers but a global symbol names: hand-written assembly (a .s file has no
    STABS, and its labels are NOTYPE, size 0: a program's jump_to, change_context and get_curr_cpu_time), each up to
    the next symbol or function. A relinked program that left them in the old .text called into nothing."""
    from .split import disassemble

    elf = ELFFile(BytesIO(image))
    text = elf.get_section_by_name(".text")
    index = elf.get_section_index(".text")
    lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
    covered = sorted((f["vram"], f["vram"] + f["size"]) for f in functions)
    starts = [a for a, _ in covered]

    def inside(addr: int) -> bool:
        import bisect

        k = bisect.bisect_right(starts, addr) - 1
        return k >= 0 and covered[k][0] <= addr < covered[k][1]
    library = _runtime_names(build_toolchain) if build_toolchain else set()
    labels = sorted({(s["st_value"], s.name) for s in elf.get_section_by_name(".symtab").iter_symbols()
                     if s.name and s["st_shndx"] == index and s["st_info"]["bind"] == "STB_GLOBAL"
                     and s.name not in library  # (crt1.o's _start: the link brings its own)
                     and s["st_info"]["type"] == "STT_NOTYPE" and lo <= s["st_value"] < hi and not inside(s["st_value"])})
    ends = sorted({a for a, _ in covered} | {a for a, _ in labels} | {hi})
    found = []
    for addr, name in labels:
        end = next(e for e in ends if e > addr)
        at = text["sh_offset"] + addr - lo
        code = image[at:at + end - addr]
        # (an operand counts as an address only where a symbol is exactly: a constant is a constant)
        _, _, refs = disassemble(code, addr, lambda a, exact=False: (syms.by_addr[a].name if a in syms.by_addr
                                                                     else None) if exact else syms.label(a))
        row = {"name": name, "vram": addr, "target": code, "relocs": json.dumps(refs)}
        found.append({"name": name, "vram": addr, "size": len(code), "unit": None, "refs": _refs(row, syms),
                      "code": code})
    return found


def _unplaceable(obj: bytes, scattered: set[str]) -> bool:
    """Whether a section the game keeps apart holds an address the build can't give the game's value: one into the
    function's own code (a switch's jump table, beside strings the game merged with its file's) it can. (One into
    its own data only where the code points at that too: the judge's placements also hold what it followed from a
    table of strings, which the build doesn't, so those stay the program's bytes.)"""
    from elftools.elf.relocation import RelocationSection

    elf = ELFFile(BytesIO(obj))
    for rsec in elf.iter_sections():
        if not isinstance(rsec, RelocationSection) or elf.get_section(rsec["sh_info"]).name not in scattered:
            continue
        symtab = elf.get_section(rsec["sh_link"])
        for rel in rsec.iter_relocations():
            sym = symtab.get_symbol(rel["r_info_sym"])
            if rel["r_info_type"] != 1 or not isinstance(sym["st_shndx"], int):
                return True
            if elf.get_section(sym["st_shndx"]).name != ".text":
                return True
    return False


def judge_unit(console, obj: bytes, rows: list, targets: list, syms, read, placed=None) -> \
        tuple[str, dict[str, dict[int, int]]]:
    """Whether a source file's object is the game's code from its first function to its last, judged as one piece
    the way the judge links a function: each function where the game has it from the first (its offset in the
    object), and the whole span, padding between functions included, the game's bytes once linked at its address,
    its calls, jump tables and constants checked against one layout of the file's own data. ("" and the placements
    of what its code reads, or what differs.)"""
    import dataclasses
    import struct

    elf = ELFFile(BytesIO(obj))
    symtab = elf.get_section_by_name(".symtab")
    text_index = elf.get_section_index(".text")
    where, first_index = {}, None
    for k, s in enumerate(symtab.iter_symbols()):
        if s.name and s["st_shndx"] == text_index and s["st_info"]["type"] == "STT_FUNC":
            where[s.name] = s["st_value"]
            if s.name == rows[0]["name"]:
                first_index = k
    first, last = rows[0], rows[-1]
    if first_index is None:
        return f"the object has no {first['name']}", {}
    base = where[first["name"]] - first["vram"]
    for row in rows:
        if where.get(row["name"]) != base + row["vram"]:
            return f"{row['name']} isn't where the game has it after the file's functions before it", {}
    span = last["vram"] + len(last["target"]) - first["vram"]
    # the first function's symbol stretched over the file's code: the judge takes a function's bytes by its symbol
    whole = bytearray(obj)
    struct.pack_into("<I", whole, symtab["sh_offset"] + first_index * symtab["sh_entsize"] + 8, span)
    code = read(first["vram"], span)
    if code is None:
        return "the game has no code there", {}
    target = dataclasses.replace(targets[0], code=code, relocs=[])
    linked = console.link_function(bytes(whole), first["name"], target, syms, read, placed)
    if not linked.exact:
        at = next((i for i, (a, b) in enumerate(zip(linked.candidate.code, code)) if a != b), None) if linked.candidate else None
        inside = max((r for r in rows if at is not None and r["vram"] <= first["vram"] + at), key=lambda r: r["vram"],
                     default=None)
        where_text = f" in {inside['name']} (+0x{first['vram'] + at - inside['vram']:X})" if inside else ""
        return f"its code differs from the game's{where_text}: {'; '.join(linked.problems[:2]) or 'other bytes'}", {}
    return "", linked.placements


def _data_numbers(out: Path, spans: list, followed: list) -> list[str]:
    """Where the tree's C writes an address of the program's data as a number (`*(int *)0x80b9244`) that isn't in
    one of its source files' variables (those the relink makes where the variable is: follow()), outside comments
    and strings."""
    found = []
    for path in sorted((out / "src").rglob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"', lambda m: re.sub(r"[^\n]", " ", m.group(0)), text,
                      flags=re.S)
        for n, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(r"\b0x([0-9a-fA-F]{6,8})\b", line):
                address = int(m.group(1), 16)
                if any(lo <= address < hi for _, lo, hi in spans) and not any(lo <= address < hi for lo, hi in followed):
                    found.append(f"{path.relative_to(out)}:{n}")
    return found


def _data_file(net, proj, cfg, rows: list, by_name: dict, hdr: str, include: str, syms, read, program, out: Path,
               stem: str, elsewhere: set[str] = frozenset(), unit: str | None = None):
    """A source file whose functions stay one file each: its variables as C in a file of their own, global (its
    functions reach them by name), compiled and judged as a whole file's data is. Its build.json entry, or why its
    data stays the program's ("" where it has none)."""
    from ...compiler import compile_source
    from ...project import compiler_config
    from . import export_data

    unit = unit or rows[0]["unit"]
    code = "\n".join(by_name[r["name"]].get("c") and (out / by_name[r["name"]]["c"]).read_text(encoding="utf-8") or ""
                     for r in rows)
    taken = {addr for r in rows for addr in (by_name[r["name"]].get("statics") or {}).values()}
    # (beside functions one file each, its statics global, which they reach by name; a file of data alone keeps
    # them static, its names the rest of the tree reads made the same addresses)
    data = export_data.file_data(program, unit, {r["vram"]: r["name"] for r in rows}, code, hdr, taken,
                                 syms, as_globals=bool(rows), elsewhere=elsewhere)
    if data.problem or not data.definitions:
        return data.problem
    what = (f"The variables of {unit}, whose functions are one file each for now" if rows else
            f"{unit}: data alone, no functions")
    text = (f'#include "{include}"\n\n/* {what} */\n' + export_data.forward(data) + "\n"
            + "\n".join(d.text for d in data.definitions) + "\n")
    compiler = compiler_for(cfg, rows[0]["vram"]) if rows else cfg["compiler"]
    config = compiler_config(Path(proj["root"]), {**cfg, "compiler": compiler})
    compiled = compile_source(config, hdr, text.replace(f'#include "{include}"\n', "", 1), trusted=True)
    if not compiled.ok:
        errors = [line for line in compiled.log.splitlines() if re.search(r":\d+: ", line) and "warning" not in line]
        return f"its data doesn't compile ({(errors or ['?'])[0][:160]})"

    def resolve(name: str) -> int | None:
        found = syms.resolve(name)
        return found if found is not None else program.address_of(name)
    problem, laid_out = export_data.judge_data(compiled.obj, data.definitions, resolve, read)
    if problem:
        return problem
    path = out / "src" / stem / "data.c" if rows else out / "src" / f"{stem}.c"
    if not rows and path.exists():
        path = out / "src" / f"{stem}_data.c"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return {"name": stem, "c": path.relative_to(out).as_posix(), "unit": unit,
            "toolchain": compiler["toolchain"], "flags": list(compiler.get("flags") or []),
            "data": {"laid_out": laid_out, "defines": [d.name for d in data.definitions] + sorted(data.aliases),
                     "variables": [[d.name, d.address, d.size, d.section] for d in data.definitions],
                     "aliases": {n: [b, o] for n, (b, o) in sorted(data.aliases.items())},
                     "link_aliases": {n: [b, o] for n, (b, o) in sorted(data.link_aliases.items())}}}


def _symbol_value(obj: bytes, name: str) -> int:
    symtab = ELFFile(BytesIO(obj)).get_section_by_name(".symtab")
    return next(s["st_value"] for s in symtab.iter_symbols() if s.name == name)


def _local_tables(net, proj, hdr: str, rows: list, sources: list, program) -> list:
    """`sources` with each copy from a literal the match placed at a table (`memcpy(vlist, "", sizeof(vlist))`)
    the local array's initializer, the table read from the program where the game's code loads it."""
    from . import export_clean
    if program is None:
        return sources
    by_name = {r["name"]: r for r in rows}
    out = []
    for name, c in sources:
        row = by_name.get(name)
        if row is None or not export_clean._COPY_TABLE.search(c):
            out.append((name, c))
            continue
        compiled = net._compile(proj, hdr, c, row)
        reads = export_clean.literal_reads(compiled.obj, program.image, {name: row["vram"]}) if compiled.ok else {}
        out.append((name, export_clean.local_table(c, reads.get(name) or {}, program.image) or c))
    return out


def _unit_file(net, proj, cfg, console, rows: list, include: str, own_header: str, hdr: str, syms, read,
               statics_at: dict[str, dict[str, int]] | None = None, program=None, asm_pieces=None,
               elsewhere: set[str] = frozenset(), sources=None):
    """A source file of the program as one C file, compiled whole and judged against the game's span of it: (the
    merged C, its compiler, its statics, its data) or (None, why, None, None). Tried with each compiler its
    functions are matched with (a file the compiler ranges cut in two is one compile in the game), each call as
    its function is defined first and then as each function declared it (units.merge's `as_called`). Then with its
    data as C (export_data.py, `program`): its data is {"sections": where each data section is, "defines": the
    names its object defines}, or {"problem": why its data stays the program's bytes}."""
    from ... import units
    from ...compiler import compile_source
    from ...project import compiler_config
    from ...rom.export import CONTEXT_INCLUDE
    from . import export_data

    compilers = list(dict.fromkeys((c["toolchain"], tuple(c.get("flags") or []))
                                   for c in (compiler_for(cfg, r["vram"]) for r in rows)))
    targets = [net._rom_target(r) for r in rows]
    asm_pieces = asm_pieces or {}
    if sources is None:
        sources = [(r["name"], r["matched_source"] or "") for r in rows]
        # first with a table a function copies from a literal the match placed at it as the local array's
        # initializer it was (export_clean.local_table): what the game's file has in its .rodata, where the literal
        # would be one byte of its own
        tabled = _local_tables(net, proj, hdr, rows, sources, program)
        if tabled != sources:
            for variant in (tabled, [(name, units.returned(c, name) or c) for name, c in tabled]):
                found = _unit_file(net, proj, cfg, console, rows, include, own_header, hdr, syms, read, statics_at,
                                   program, asm_pieces, elsewhere, variant)
                if found[0] is not None:
                    return found
        # first with each function that returns what GCC 2.95 left in %eax returning it (units.returned): the same
        # code where the file still matches, and a newer GCC's (make port) gets the value too
        fixed = [(name, units.returned(c, name) or c) for name, c in sources]
        if fixed != sources:
            found = _unit_file(net, proj, cfg, console, rows, include, own_header, hdr, syms, read, statics_at,
                               program, asm_pieces, elsewhere, fixed)
            if found[0] is not None:
                return found

    def attempt(merged, toolchain, flags, header=hdr, definitions=None):
        text = merged.c.replace(f'#include "{include}"\n', "", 1)  # (the compiler includes it first: context.h)
        text = text.replace(f'#include "{own_header}"\n', merged.header, 1)
        config = compiler_config(Path(proj["root"]), {**cfg, "compiler": {"toolchain": toolchain, "flags": list(flags)}})
        # (each piece was an agent's C, checked when it was judged: the file is longer than one function may be)
        compiled = compile_source(net._placed(config, proj, rows[0]), header, text, trusted=True)
        if not compiled.ok:
            errors = [line for line in compiled.log.splitlines() if re.search(r":\d+: ", line) and not re.search(
                r"warning|previous|In function|Each undeclared|for each function", line)]
            # (a system header by its own name: the README went out with this computer's toolchain folder in it)
            first = re.sub(r"(?<![\w.])/\S*?/(include/\S+)", r"\1", (errors or ["?"])[0])
            return None, f"it doesn't compile as one file ({first[:160]})", {}
        placed = export_data.placer(compiled.obj, definitions) if definitions else None
        problem, placements = judge_unit(console, compiled.obj, rows, targets, syms, read, placed)
        return (compiled.obj if not problem else None), problem, placements

    def with_data(merged, toolchain, flags, as_called):
        """The file with its data as C (export_data.py), compiled and judged: (its merged C, its data) or (None,
        why its data can't be C)."""
        functions = {r["vram"]: r["name"] for r in rows}
        taken = {addr for found in (statics_at or {}).values() for addr in found.values()}
        data = export_data.file_data(program, rows[0]["unit"], functions, merged.c + merged.header, hdr, taken, syms,
                                     elsewhere=elsewhere)
        if data.problem:
            return None, data.problem
        if not data.definitions:
            return None, ""
        source = program.sources.get(rows[0]["unit"])
        lines = {functions[f.address]: f.line for f in (source.functions if source else []) if f.address in functions}
        forward = export_data.forward(data)

        def merge_with_data():
            return units.merge(sources, include, own_header, CONTEXT_INCLUDE, statics_at, as_called, hdr,
                               own_data={d.name: d.key for d in data.definitions}, forward=forward,
                               placed=[(d.line, d.text) for d in data.definitions], func_lines=lines,
                               asm_pieces=asm_pieces)
        done = merge_with_data()
        # (a static a function declares as another type, under another name for the same symbol, is used as far
        # as a newer GCC knows: else it drops or folds it, not seeing that name is the static)
        if done.c is not None and export_data.mark_used(data, re.findall(r'__asm__\("(\w+)"\)', done.c)):
            done = merge_with_data()
        if done.c is None:
            return None, done.problem
        # (the shared header without its externs of the file's statics, as the file will include it: a static's
        # first declaration decides its place in .bss: _static_headers)
        statics_here = {d.name for d in data.definitions if d.forward.startswith("static")}
        obj, problem, placements = attempt(done, toolchain, flags, export_data.without_externs(hdr, statics_here),
                                           data.definitions)
        if obj is None:
            return None, f"with its data, {problem}"
        text_at = rows[0]["vram"] - _symbol_value(obj, rows[0]["name"])

        def resolve(name: str) -> int | None:  # (and the program's own symbols: a hand-written label)
            found = syms.resolve(name)
            return found if found is not None else program.address_of(name)
        # and what the functions' own C defines (their statics), where the code reads it: checked alike
        definitions = data.definitions + export_data.read_by_code(obj, data.definitions, placements)
        problem, laid_out = export_data.judge_data(obj, definitions, resolve, read, text_at)
        if problem:
            return None, problem
        defines = [d.name for d in data.definitions if d.forward.startswith("extern")] + sorted(data.aliases)
        return done, {"laid_out": laid_out, "defines": defines,
                      "variables": [[d.name, d.address, d.size, d.section] for d in definitions],
                      "aliases": {n: [base, off] for n, (base, off) in sorted(data.aliases.items())},
                      "link_aliases": {n: [base, off] for n, (base, off) in sorted(data.link_aliases.items())}}

    problems: dict[bool, str] = {}
    for as_called in (False, True):
        merged = units.merge(sources, include, own_header, CONTEXT_INCLUDE, statics_at, as_called, hdr,
                             asm_pieces=asm_pieces)
        if merged.c is None:
            return None, merged.problem, None, None
        for toolchain, flags in compilers:
            obj, problem, placements = attempt(merged, toolchain, flags)
            if obj is None:
                problems.setdefault(as_called, problem)
                # (what the file's code reads as constants of its own may be its data: with that as C, the file may
                # come out where it doesn't alone)
                if program is not None:
                    done, data = with_data(merged, toolchain, flags, as_called)
                    if done is not None:
                        return done, (toolchain, list(flags)), {}, data
                continue
            statics = _statics(obj, placements)
            if program is None:
                return merged, (toolchain, list(flags)), statics, None
            done, data = with_data(merged, toolchain, flags, as_called)
            if done is None:
                return merged, (toolchain, list(flags)), statics, {"problem": data} if data else None
            return done, (toolchain, list(flags)), {}, data
    if problems.get(True) and problems[True] != problems.get(False):
        return None, f"{problems[False]}; with each call as its function declared it, {problems[True]}", None, None
    return None, problems[False], None, None


def _static_headers(out: Path) -> int:
    """Each C file that defines a name `static` the header it includes declares `extern` (three files' own
    `static V2Vertex grvtx[4]` beside the shared header's `extern V2Vertex grvtx[4];`, from the debug information,
    which lists one) includes a copy of that header without the declaration: GCC 2.95 let it pass, a newer GCC
    refuses the file, and a static's first declaration decides its place (export_data.py judges the file so). The
    same code either way. How many files it took."""
    from ... import units
    from . import export_data

    texts: dict[str, str] = {}
    made, n = {}, 0
    for path in sorted((out / "src").rglob("*.c")):
        text = path.read_text(encoding="utf-8")
        m = re.match(r'#include "([^"]+)"\n', text)
        if not m or not (out / "include" / m.group(1)).exists():
            continue
        header = m.group(1)
        if header not in texts:
            texts[header] = (out / "include" / header).read_text(encoding="utf-8")
        mine = {name for c in units.chunks(text) if c.kind == "static" for name in c.names}
        clash = sorted(mine & set(export_data.header_declarations(texts[header])))
        if not clash:
            continue
        key = (header, tuple(clash))
        if key not in made:
            variant = f"{Path(header).stem}_{path.stem}.h"
            k = 2
            while (out / "include" / variant).exists():
                variant, k = f"{Path(header).stem}_{path.stem}{k}.h", k + 1
            (out / "include" / variant).write_text(
                f"/* {header} without what {path.stem}.c defines static itself: {', '.join(clash)} */\n"
                + export_data.without_externs(texts[header], set(clash)), encoding="utf-8")
            made[key] = variant
        path.write_text(text.replace(m.group(0), f'#include "{made[key]}"\n', 1), encoding="utf-8")
        n += 1
    return n


def export_linux(net, slug: str, out: Path, console, log=print) -> dict:
    proj = net._project(slug)
    cfg = net.cfg(proj)
    work = Path(proj["root"])
    image = (work / cfg["rom"]["file"]).read_bytes()
    elf = ELFFile(BytesIO(image))
    text = elf.get_section_by_name(".text")
    if out.exists():
        for child in out.iterdir():
            if child.name != ".git":
                shutil.rmtree(child) if child.is_dir() else child.unlink()
    out.mkdir(parents=True, exist_ok=True)

    rows = net.store.all("SELECT * FROM functions WHERE project_id=? ORDER BY vram", proj["id"])
    syms = net.symbols(proj["id"])
    units = net._unit_contexts(proj["id"])
    (out / "include").mkdir(exist_ok=True)
    common = net._context(proj["id"])["header"]
    (out / "include" / "common.h").write_text(exported_header(common), encoding="utf-8")
    headers = {None: "common.h"}

    log("checking the matched functions and writing them as C")
    functions, fallback = [], []
    program_functions = {r["name"] for r in rows}  # (each its own file: a copy in another's C goes)
    for row in rows:
        f = {"name": row["name"], "vram": row["vram"], "size": len(row["target"]), "unit": row["unit"]}
        functions.append(f)
        if row["status"] != "matched" or not row["matched_source"]:
            continue
        unit = net._effective_unit(row, units)
        hdr = net._context(proj["id"], unit)["header"]
        # its own definition only (units.only_own), checked as it's written; else as it matched (a function GCC 4.3
        # inlines another of the file into matches only with that one's C before it)
        for own in dict.fromkeys((only_own(row["matched_source"], row["name"], program_functions),
                                  row["matched_source"])):
            compiled = net._compile(proj, hdr, own, row)
            linked = (console.link_function(compiled.obj, row["name"], net._rom_target(row), syms, net.reader(proj))
                      if compiled.ok else None)
            if linked is not None and linked.exact:
                break
        if not compiled.ok:
            fallback.append((row["name"], "doesn't compile any more"))
            continue
        if not linked.exact:
            fallback.append((row["name"], "no longer matches"))
            continue
        # constants the game keeps apart (a file's equal strings merged): the build gives each word the game's
        # address, checked as the judge checks it; a table of addresses so scattered it can't
        scattered = {name for name, offsets in linked.placements.items()
                     if len({addr - off for off, addr in offsets.items()}) != 1}
        if scattered and _unplaceable(compiled.obj, scattered):
            fallback.append((row["name"], "its own data isn't laid out like the game's"))
            continue
        statics = _statics(compiled.obj, linked.placements)
        if statics:
            f["statics"] = statics
        if unit not in headers and hdr == common:  # (a source file with nothing of its own: the shared one)
            headers[unit] = "common.h"
        elif unit not in headers:
            headers[unit] = f"common_{_unit_name(unit)}.h"
            (out / "include" / headers[unit]).write_text(exported_header(hdr), encoding="utf-8")
        src = out / "src" / _unit_name(row["unit"]) / f"{row['name']}.c"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(exported_source("", headers[unit], own), encoding="utf-8")
        compiler = compiler_for(cfg, row["vram"])
        f.update({"c": src.relative_to(out).as_posix(), "toolchain": compiler["toolchain"],
                  "flags": list(compiler.get("flags") or [])})
        if compiled.layout:  # it matches where the code before it in its file put it (x86_link.layouts)
            f["prelude"] = compiled.layout

    # each source file whose functions all match as one C file, compiled whole and judged against the game's span
    # of it (the function files stay where it doesn't, and why is in the README)
    log("putting the matched functions back into their source files")
    unit_list, unit_fallback, data_fallback, data_files = [], [], [], []
    from . import export_data

    program = export_data.Program(image)
    # the names the tree's C reads a symbol by (a file's static another file's function reads): what a file whose
    # data is C gives its variables too
    elsewhere = {w for r in rows if r["status"] == "matched" and r["matched_source"]
                 for w in set(re.findall(r"\b[A-Za-z_]\w*\b", r["matched_source"])) if syms.resolve(w) is not None}
    by_name = {f["name"]: f for f in functions}
    taken = {p.name for p in (out / "include").iterdir()}
    groups: dict = {}
    for row in rows:
        groups.setdefault(row["unit"], []).append(row)
    read = net.reader(proj)
    library = _runtime_names(cfg["compiler"]["toolchain"])
    names_at = {s.name: s.address for s in syms.by_name.values() if s.address}
    names_at.update({f["name"]: f["vram"] for f in functions})
    for unit, members in groups.items():
        if unit is None:
            continue
        if any(r["name"] in library for r in members):  # (glibc's atexit: the link brings libc_nonshared.a's)
            continue
        if not any(by_name[r["name"]].get("c") for r in members):
            continue  # (nothing of it is C: hand-written assembly, a library's)
        # a function of it that isn't C yet: its assembly, at its place in the file (else one file per function)
        asm_pieces = {}
        for r in members:
            if not by_name[r["name"]].get("c"):
                written = assembly_source(r["name"], bytes(r["target"]), r["vram"], _refs(r, syms), names_at,
                                          cfg["compiler"]["toolchain"], work)
                if written is None:
                    break
                asm_pieces[r["name"]] = written
        if not all(by_name[r["name"]].get("c") or r["name"] in asm_pieces for r in members):
            missing = [r["name"] for r in members if not by_name[r["name"]].get("c")]
            unit_fallback.append((unit, f"{', '.join(missing[:3])}{' ...' if len(missing) > 3 else ''} isn't C yet"))
            continue
        stem = _unit_name(unit)
        name = stem if f"{stem}.h" not in taken and not (out / "src" / f"{stem}.c").exists() else f"{stem}_file"
        hdr = net._context(proj["id"], net._effective_unit(members[0], units))["header"]
        first_c = next(r for r in members if by_name[r["name"]].get("c"))
        merged, why, statics, data = _unit_file(
            net, proj, cfg, console, members, headers[net._effective_unit(first_c, units)], f"{name}.h", hdr, syms,
            read, {r["name"]: by_name[r["name"]].get("statics") or {} for r in members}, program, asm_pieces,
            elsewhere)
        if merged is None:
            unit_fallback.append((unit, why))
            # its data as C all the same, a file of its own its functions reach by name (src/<file>/data.c)
            found = _data_file(net, proj, cfg, members, by_name, hdr, headers[net._effective_unit(first_c, units)],
                               syms, read, program, out, stem, elsewhere)
            if isinstance(found, dict):
                data_files.append(found)
            elif found:
                data_fallback.append((unit, found))
            continue
        toolchain, flags = why
        taken.add(f"{name}.h")
        c_path = out / "src" / f"{name}.c"
        c_path.write_text(merged.c, encoding="utf-8")
        if merged.header:
            guard = "FILE_" + re.sub(r"\W", "_", name).upper() + "_H"  # (`3dsprite`: a macro can't start with a digit)
            (out / "include" / f"{name}.h").write_text(
                f"/* What {unit} declares for itself: its functions, and what it uses from the rest of the program */\n"
                f"#ifndef {guard}\n#define {guard}\n\n{merged.header}\n#endif\n", encoding="utf-8")
        for r in members:
            f = by_name[r["name"]]
            if f.get("c"):
                (out / f["c"]).unlink()
            else:
                f["asm"] = True  # (in its file as assembly: not C yet)
            f.update({"c": c_path.relative_to(out).as_posix(), "in": name})
            for gone in ("prelude", "statics"):
                f.pop(gone, None)
        folder = out / "src" / stem
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
        first, last = members[0], members[-1]
        entry = {"name": name, "c": c_path.relative_to(out).as_posix(), "unit": unit,
                 "functions": [r["name"] for r in members], "vram": first["vram"],
                 "size": last["vram"] + len(last["target"]) - first["vram"], "toolchain": toolchain, "flags": flags}
        if statics:
            entry["statics"] = statics
        if data and "problem" in data:
            data_fallback.append((unit, data["problem"]))
        elif data:
            entry["data"] = data
        unit_list.append(entry)
    # a source file of data alone (no functions: fonts.c's tables): its C is its variables
    for unit in program.sources:
        found_vars = export_data.variables(program, unit, {})
        if unit in groups or not found_vars or all(v[0] in library for v in found_vars):
            continue  # (glibc's init.c, _IO_stdin_used: the C runtime's, which the link brings)
        found = _data_file(net, proj, cfg, [], by_name, common, "common.h", syms, read, program, out, _unit_name(unit),
                           elsewhere, unit=unit)
        if isinstance(found, dict):
            data_files.append(found)
        elif found:
            data_fallback.append((unit, found))
    log(f"{len(unit_list)} of {len([u for u in groups if u is not None])} source files are one C file each, "
        f"{sum(1 for u in unit_list if 'data' in u)} with their data as C")

    _static_headers(out)

    # what isn't C yet, as assembly that names what it calls and reads: the relinked program moves the code (its
    # references in build.json, so `make` writes asm/ again from your copy in a checkout without it); and the code
    # no function covers that a global symbol names (hand-written assembly)
    asm = out / "asm"
    by_vram = {r["vram"]: r for r in rows}
    pieces = []
    for f in functions:
        if not f.get("c") and f["name"] not in library:  # (the link brings libc_nonshared.a's, crt's: no bytes)
            row = by_vram[f["vram"]]
            pieces.append((f, bytes(row["target"]), _refs(row, syms)))
    for extra in _unlisted(image, functions, syms, cfg["compiler"]["toolchain"]):
        code = extra.pop("code")
        functions.append(extra)
        pieces.append((extra, code, extra["refs"]))
    functions.sort(key=lambda f: f["vram"])
    names_at = {s.name: s.address for s in syms.by_name.values() if s.address}
    names_at.update({f["name"]: f["vram"] for f in functions})
    for f, code, refs in pieces:
        f["refs"] = {str(k): v for k, v in refs.items()}
        # as GNU assembly a person reads (src/asm/, the tree's own source: checked to assemble to your copy's
        # bytes where it lies), else as your copy's bytes (asm/, made from it, never in git)
        written = None
        if (own := _own_constants(f["name"], code, f["vram"], refs, syms, image)) is not None:
            # (its constants its own: build.json's references stay the program's, for asm/ made from your copy)
            written = assembly_source(f["name"], code, f["vram"], own[0], names_at, cfg["compiler"]["toolchain"],
                                      work, (own[1], own[2]))
        if written is None:
            written = assembly_source(f["name"], code, f["vram"], refs, names_at, cfg["compiler"]["toolchain"], work)
        if written is not None:
            # (no executable stack asked for: a newer ld warned of the object without the note)
            written += '.section .note.GNU-stack,"",@progbits\n'
            (out / "src" / "asm").mkdir(parents=True, exist_ok=True)
            (out / "src" / "asm" / f"{f['name']}.s").write_text(written, encoding="utf-8")
            f["s"] = f"src/asm/{f['name']}.s"
            continue
        asm.mkdir(exist_ok=True)
        (asm / f"{f['name']}.s").write_text(assembly(f["name"], code, refs), encoding="utf-8")
        f["s"] = f"asm/{f['name']}.s"

    names = {f["name"] for f in functions if f.get("c")}
    symbols = {s.name: s.address for s in syms.by_name.values() if s.name not in names and s.address}
    for path in dict.fromkeys(f.get("c") or f.get("s") for f in functions):
        # (automatic names matched C uses that no symbol has: their address is in the name; and the assembly's)
        if path:
            for word in set(re.findall(r"\b[A-Za-z]\w*_[0-9A-Fa-f]{1,8}\b", (out / path).read_text(encoding="utf-8"))):
                if (m := AUTO_NAME.match(word)) and word not in names:
                    symbols.setdefault(word, int(m.group(1), 16))
    build = {
        "title": proj["name"], "platform": console.id, "image": "baserom", "output": "build/program",
        "decompdecomp": __import__("decompnet").__version__,  # (build.py's checks need this one or later)
        "program": re.sub(r"[^\w.-]", "_", Path(cfg["rom"].get("program") or cfg["rom"]["file"]).name),
        "sha1": hashlib.sha1(image).hexdigest(), "toolchain": cfg["compiler"]["toolchain"],
        # (the relink compiles a file's variables each in a section of its own where the compiler can: tools/relink.py)
        "data_sections": toolchain_registry()[cfg["compiler"]["toolchain"]].data_sections,
        "text": {"vram": text["sh_addr"], "offset": text["sh_offset"], "size": text["sh_size"]},
        "functions": functions, "units": unit_list, "data_files": data_files,
        "symbols": dict(sorted(symbols.items(), key=lambda kv: kv[1])),
        "got": cfg.get("got"),  # (where -fPIC code finds the GOT, and what each entry holds)
        # names the program left weak and undefined (glibc's atexit reads __dso_handle, which no 2001 crtbegin.o
        # had): 0 in every link, as in the original's, whether or not the C says weak
        "weak": sorted({s.name for s in elf.get_section_by_name(".symtab").iter_symbols()
                        if re.fullmatch(r"[A-Za-z_]\w*", s.name) and s["st_shndx"] == "SHN_UNDEF"
                        and s["st_info"]["bind"] == "STB_WEAK"}),  # (not a versioned import's name@VERSION)
        # what the build needs of your copy otherwise: its layout and what it imports (the relink's linker script and
        # stubs), so a tree whose code and data are all source builds without it
        "layout": _layout(elf, functions), "imports": _imports(elf),
    }
    # whether it does: every function C or assembly source, every source file's data C (or none to have)
    # (a file one file per function: its data a file of its own, and none of its functions' statics the game's;
    # and no address of your copy's data the C still writes as a number, which nothing would be at)
    apart = {u for u, _ in unit_fallback}
    followed = [(a, a + max(size, 1)) for unit in unit_list + data_files
                for _, a, size, _ in ((unit.get("data") or {}).get("variables") or [])]
    numbers = _data_numbers(out, build["layout"]["data"], followed)
    build["standalone"] = all(f.get("c") or (f.get("s") or "").startswith("src/") or f["name"] in library
                              for f in functions) and not data_fallback \
        and all(not (f.get("unit") in apart and f.get("statics")) for f in functions) \
        and apart <= {d["unit"] for d in data_files} | {u for u in apart if not program.sources.get(u) or not
                                                         export_data.variables(program, u, {})} and not numbers
    if numbers:
        log(f"the C still writes {len(numbers)} addresses of the program's data as numbers (first {numbers[0]}): the "
            "build takes that data from your copy")
    (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
    shutil.copyfile(Path(__file__).with_name("export_build.py"), out / "build.py")
    export_make.write(out, build)
    shutil.copyfile(work / cfg["rom"]["file"], out / "baserom")
    # the C made plain where it still builds the same code: what only the matching build's linker script supplied,
    # written as C (export_clean.py), so `make` builds it with any GCC
    if (out / "tools" / "cc.sh").exists():
        from ... import toolchains
        from . import export_clean

        log("writing what only the matching build supplied as plain C")
        tc = Path(toolchains.ensure(build["toolchain"], log=lambda *_: None))
        export_clean.clean(out, build, tc, log=log)
        # and its floats as the game's code computed them, where the C can say so (export_float.py)
        if export_float.available():
            log("comparing the plain build's floats with the game's code, function by function (tools/floatcheck.py)")
            export_float.precision(out, build, tc, log=log)
            export_make.write(out, build)  # (each source file's precision, build.json's plain_flags)
        else:
            log("the plain build's floats weren't compared with the game's: that needs the system's gcc (32-bit) and "
                "binutils")
        export_clean.plain_system(out, tc)  # (last: every header and file as it stays)
    matched = sum(1 for f in functions if f.get("c") and not f.get("asm"))
    _docs(out, proj["name"], matched, len(functions), fallback, build["program"], len(unit_list), unit_fallback,
          data_fallback, sum(1 for u in unit_list if "data" in u), build["standalone"], export_make.packages(build),
          # (the compiler the program was built with: "GCC 2.95.3" said of an egcs 1.1.2 program)
          re.sub(r" for Linux\b.*", "", toolchain_registry()[build["toolchain"]].name))
    # (asm/ and data/ are your copy's code and data, written from it: never in git)
    # (and the compiler `make toolchain` downloads into tools/: only the tree's scripts are its own)
    (out / ".gitignore").write_text("/build/\n/baserom*\n/asm/\n/data/\n/tools/*/\n/tools/.downloads/\n", encoding="utf-8")

    log("building the exported project to check it rebuilds the program byte for byte")
    proc = subprocess.run(capped([sys.executable, "build.py"]), cwd=out, capture_output=True, text=True, timeout=3600,
                          encoding="utf-8", errors="replace")
    identical = "identical to the original" in proc.stdout
    relinked = proc.returncode == 0 and "relinked" in proc.stdout
    if not (identical and relinked):
        log((proc.stdout + proc.stderr)[-3000:])
    return {"path": str(out), "identical": identical, "relinked": relinked, "matched": matched,
            "functions": len(functions), "fallback": fallback, "units": len(unit_list), "unit_fallback": unit_fallback,
            "data": sum(1 for u in unit_list if "data" in u), "data_fallback": data_fallback,
            "log": (proc.stdout + proc.stderr)[-3000:]}


def _docs(out: Path, title: str, matched: int, total: int, fallback, program: str = "program", whole: int = 0,
          unit_fallback=(), data_fallback=(), with_data: int = 0, standalone: bool = False,
          packages: str = "gcc-multilib", compiler: str = "GCC 2.95.3") -> None:
    notes = "".join(f"\n- `{n}`: kept as the program's bytes, {why}" for n, why in fallback)
    notes += "".join(f"\n- `{u}`: one file per function in `src/{_unit_name(u)}/` for now: {why}"
                     for u, why in unit_fallback)
    notes += "".join(f"\n- `{u}`: its data stays the program's (data/program.s) for now: {why}" for u, why in data_fallback)
    (out / "README.md").write_text(f"""# {title} (decompilation)

A matching decompilation of {title}, a Linux (32-bit x86) program, started with [decompdecomp](https://github.com/n-delic/decompdecomp).
{matched} of {total} functions are C that {compiler} compiles to exactly the original code; the rest is still the
program's own bytes. {whole} of the program's source files are back together, each one C file that compiles to the
original file's code, function after function; {with_data} of them define their data too, each variable with its
type and the program's value. `build.py` rebuilds every decompiled file and function where it lies
in the program and checks the result against your original, byte for byte.

## Build

1. {"`make`: builds `build/plain/" + program + "`, the C as any C program is built: every source file compiled by "
   "your system's gcc (`CC`, `CFLAGS`) with `NON_MATCHING` defined, linked against your system's libraries "
   "(`LDLIBS`). Needs make and a 32-bit gcc and libraries (Debian and Ubuntu: `sudo apt install " + packages + "`; "
   "a link that can't find `-lGL` where only the libraries' `.so.1` files are there takes "
   "`make LDFLAGS=-L<a folder of links libGL.so -> libGL.so.1>`). Nothing of the original program, nor decompdecomp. "
   "`make asan` builds the same with AddressSanitizer (`build/asan/" + program + "`): a read past a variable into "
   "the next one, which the plain link lays out as it likes, is reported with its function and variable "
   "(`ASAN_OPTIONS=halt_on_error=0` carries on after each)." if standalone else
   "Put your own copy of the program here as `baserom`: what isn't source yet is made from it (`asm/`, "
   "`data/program.s`), and `make` builds the matching program (2. below) until every function and variable is "
   "source; then it builds the C as any C program is built, with your system's gcc and libraries"} (`baserom` is in
   `.gitignore`; never commit it).
2. `make match`: builds `build/{program}`, the program linked anew from the C with the compiler it was built with
   ({compiler}), its code byte for byte the original's. The first time it downloads that compiler into `tools/`
   (`make toolchain`: pinned archives, each checked against its SHA-256; where the system has no 32-bit loader, a
   32-bit C runtime too). Needs make, python3, curl or wget, tar and ar; not decompdecomp.
3. `python build.py` (with decompdecomp installed, and your copy as `baserom`) checks that the C still rebuilds your
   copy byte for byte, as `build/program`, and then runs `make match`.
4. `make port`: the C built by your system's GCC (`PORT_CC`, default `gcc -m32`; `PORT_FLAGS`) against the
   program's own C library headers from `tools/`, linked as `make match` links it, its variables where the program
   has them.
5. `make floatcheck`: whether the plain build's floats are what the game's code computes, bit for bit, function by
   function (`tools/floatcheck.py`: each float function of the matching build and of the plain one called with the
   same random arguments). GCC 2.95 used the x87's 80-bit registers, rounding a float only where it stored one; where
   the C says so (a `long double` kept exact, a float function returning all 80 bits, a literal read as a
   `(double)`), the file builds with `-fexcess-precision=standard` (its rule in the Makefile), which keeps it.

Where the plain C and the C that compiles to the original's code differ (GCC 2.95 builds the game's code only from
a number where a person writes the variable's name), the file has both, as decompilations write them:

```c
#ifdef NON_MATCHING
    texState = (GLtextureState *)((int)&glContext + 0x14);
#else
    texState = (GLtextureState *)0x8f14db4;
#endif
```

## Layout

| Path | What it is |
| :-- | :-- |
| `src/<source file>.c` | A source file of the program, its functions in their original order, its statics defined once. |
| `src/<source file>/<function>.c` | The functions of a file that isn't back together yet (README's notes say why), one per file; `data.c` beside them its variables. |
| `src/asm/<function>.s` | Code that isn't C: hand-written assembly, as GNU assembly that assembles to the original's bytes. |
| `include/` | `common.h`: the program's types, structs, macros and the libraries' declarations. `<source file>.h`: what the rest of the program reads of that file (its functions and variables); each file includes the headers of the files it uses, and declares itself what no header does. A file that only builds the game's code with the headers it was matched with reads those (`common_full.h`, `<source file>_decls.h`). |
| `asm/<function>.s` | What isn't C yet, as assembly (from your copy). |
| `data/program.s` | The program's data that isn't C yet, every global and pointer named (written from your copy by the first relink). |
| `Makefile`, `tools/` | The build: `make` the plain program, `make match` the matching one; `tools/relink.py` the matching build's steps, `tools/toolchain.sh` its compiler's download. |
| `build.json`, `build.py` | Where each function is; `build.py` (decompdecomp) checks the C against your copy, as `build/program`. |

`build/{program}` (`make match`) is every function compiled as written and laid out by the linker above the program's
data, where it may grow, with the compiler's own crt files and the libraries it imports. A source file's variables
sit as far apart as the program has them (C that reads past one into the next reads what the program read), there
and in `make port`; the plain build lays them out as its linker likes. Edit any function (make it longer, add one in
its file), run `make`, and run the program where your copy runs.

Keep going with any tool: write a function as `src/<source file>/<name>.c`, run `python build.py check <name>`,
then `python build.py`. Change a source file and run `python build.py check <file>` (or the name of one of its
functions). When it says *identical*, the program still matches.

## The data, and what isn't C yet

A source file whose data is C defines its globals, statics and its functions' statics itself, each with its type
and the program's value (`static Settings settings = {{ .volume = 7, .name = "default" }};`), where the file
defined it among its functions; each value is checked against your copy's, every pointer in it too. Those are the
real ones: the relinked program takes them from the file's object, change them there.

The rest of the program's data (files whose data isn't C yet, what no file's debug information lists) is written by
the first relink as `data/program.s`, from your copy: every global labelled by name, every
word that pointed at a function, a string or other data written as that (`.long greet`, `.long __orig_rodata+0x1a4`),
its constructor and destructor lists (a C++ program's globals) by name. Change it like any source. That data stays
where the original has it; `make move` lays it out after the code instead, the addresses the C
still writes as numbers moved with it (`make move`; it reads the code with Python's capstone). What's in `asm/` isn't C yet: assembly that names what it calls, so it moves
with the rest. `asm/` and `data/` are made from your copy: keep them out of git (`.gitignore` does).

The program's code and data belong to their rights holder: keep this tree to yourself unless you have the right to
share it.{chr(10) + chr(10) + '## Notes' + notes if notes else ''}
""", encoding="utf-8")
    (out / "AGENTS.md").write_text(f"""# Working on this decompilation

- Goal: C that {compiler} turns into exactly the original bytes. `python build.py` must end with "identical".
- Write a function as `src/<source file>/<name>.c` (one function, its header included first), then
  `python build.py check <name>`: it compiles it, links it at its address, compares it with the original and
  records it in `build.json`.
- A source file that is back together (`src/<file>.c`) is compiled whole: `python build.py check <file>` compares
  its code, first function to last, with the original's.
- Shared types and prototypes go in `include/`. Never edit `baserom` to force a match.
- `make` links a new program from the C (build/<program>), without decompdecomp: changes that don't match (a mod,
  a fix) go there. `python build.py` checks the matching first.
""", encoding="utf-8")
