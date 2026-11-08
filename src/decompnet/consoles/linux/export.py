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
from . import export_make


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


def judge_unit(console, obj: bytes, rows: list, targets: list, syms, read) -> tuple[str, dict[str, dict[int, int]]]:
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
    linked = console.link_function(bytes(whole), first["name"], target, syms, read)
    if not linked.exact:
        at = next((i for i, (a, b) in enumerate(zip(linked.candidate.code, code)) if a != b), None) if linked.candidate else None
        inside = max((r for r in rows if at is not None and r["vram"] <= first["vram"] + at), key=lambda r: r["vram"],
                     default=None)
        where_text = f" in {inside['name']} (+0x{first['vram'] + at - inside['vram']:X})" if inside else ""
        return f"its code differs from the game's{where_text}: {'; '.join(linked.problems[:2]) or 'other bytes'}", {}
    return "", linked.placements


def _unit_file(net, proj, cfg, console, rows: list, include: str, own_header: str, hdr: str, syms, read,
               statics_at: dict[str, dict[str, int]] | None = None):
    """A source file of the program as one C file, compiled whole and judged against the game's span of it: (the
    merged C, its own header's declarations, its statics) or (None, why, None). Tried with each compiler its
    functions are matched with (a file the compiler ranges cut in two is one compile in the game), each call as
    its function is defined first and then as each function declared it (units.merge's `as_called`)."""
    from ... import units
    from ...compiler import compile_source
    from ...project import compiler_config
    from ...rom.export import CONTEXT_INCLUDE

    compilers = list(dict.fromkeys((c["toolchain"], tuple(c.get("flags") or []))
                                   for c in (compiler_for(cfg, r["vram"]) for r in rows)))
    problems: dict[bool, str] = {}
    for as_called in (False, True):
        merged = units.merge([(r["name"], r["matched_source"]) for r in rows], include, own_header, CONTEXT_INCLUDE,
                             statics_at, as_called, hdr)
        if merged.c is None:
            return None, merged.problem, None
        text = merged.c.replace(f'#include "{include}"\n', "", 1)  # (the compiler includes it first: context.h)
        text = text.replace(f'#include "{own_header}"\n', merged.header, 1)
        for toolchain, flags in compilers:
            config = compiler_config(Path(proj["root"]), {**cfg, "compiler": {"toolchain": toolchain, "flags": list(flags)}})
            # (each piece was an agent's C, checked when it was judged: the file is longer than one function may be)
            compiled = compile_source(net._placed(config, proj, rows[0]), hdr, text, trusted=True)
            if not compiled.ok:
                errors = [line for line in compiled.log.splitlines() if re.search(r":\d+: ", line) and not re.search(
                    r"warning|previous|In function|Each undeclared|for each function", line)]
                problem = f"it doesn't compile as one file ({(errors or ['?'])[0][:160]})"
            else:
                problem, placements = judge_unit(console, compiled.obj, rows, [net._rom_target(r) for r in rows],
                                                 syms, read)
                if not problem:
                    return merged, (toolchain, list(flags)), _statics(compiled.obj, placements)
            problems.setdefault(as_called, problem)
    if problems.get(True) and problems[True] != problems.get(False):
        return None, f"{problems[False]}; with each call as its function declared it, {problems[True]}", None
    return None, problems[False], None


def _static_headers(out: Path) -> int:
    """Each C file that defines a name `static` the header it includes declares `extern` (three files' own
    `static V2Vertex grvtx[4]` beside the shared header's `extern V2Vertex grvtx[4];`, from the debug information,
    which lists one) includes a copy of that header without the declaration: GCC 2.95 let it pass, a newer GCC
    refuses the file. The same code either way. How many files it took."""
    from ... import units

    declared: dict[str, dict[str, list[int]]] = {}  # header -> name -> its extern lines

    def externs(header: str) -> dict[str, list[int]]:
        if header not in declared:
            lines = (out / "include" / header).read_text(encoding="utf-8").splitlines()
            found: dict[str, list[int]] = {}
            for k, line in enumerate(lines):
                if line.startswith("extern ") and line.rstrip().endswith(";") and "(" not in line:
                    for name in units.chunks(line + "\n")[0].names:
                        found.setdefault(name, []).append(k)
            declared[header] = found
        return declared[header]
    made, n = {}, 0
    for path in sorted((out / "src").rglob("*.c")):
        text = path.read_text(encoding="utf-8")
        m = re.match(r'#include "([^"]+)"\n', text)
        if not m or not (out / "include" / m.group(1)).exists():
            continue
        header = m.group(1)
        mine = {name for c in units.chunks(text) if c.kind == "static" for name in c.names}
        clash = sorted(mine & set(externs(header)))
        if not clash:
            continue
        key = (header, tuple(clash))
        if key not in made:
            gone = {k for name in clash for k in externs(header)[name]}
            lines = (out / "include" / header).read_text(encoding="utf-8").splitlines()
            variant = f"{Path(header).stem}_{path.stem}.h"
            k = 2
            while (out / "include" / variant).exists():
                variant, k = f"{Path(header).stem}_{path.stem}{k}.h", k + 1
            (out / "include" / variant).write_text(
                f"/* {header} without what {path.stem}.c defines static itself: {', '.join(clash)} */\n"
                + "\n".join(line for k, line in enumerate(lines) if k not in gone) + "\n", encoding="utf-8")
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
    for row in rows:
        f = {"name": row["name"], "vram": row["vram"], "size": len(row["target"]), "unit": row["unit"]}
        functions.append(f)
        if row["status"] != "matched" or not row["matched_source"]:
            continue
        unit = net._effective_unit(row, units)
        hdr = net._context(proj["id"], unit)["header"]
        compiled = net._compile(proj, hdr, row["matched_source"], row)
        if not compiled.ok:
            fallback.append((row["name"], "doesn't compile any more"))
            continue
        linked = console.link_function(compiled.obj, row["name"], net._rom_target(row), syms, net.reader(proj))
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
        src.write_text(exported_source("", headers[unit], row["matched_source"]), encoding="utf-8")
        compiler = compiler_for(cfg, row["vram"])
        f.update({"c": src.relative_to(out).as_posix(), "toolchain": compiler["toolchain"],
                  "flags": list(compiler.get("flags") or [])})
        if compiled.layout:  # it matches where the code before it in its file put it (x86_link.layouts)
            f["prelude"] = compiled.layout

    # each source file whose functions all match as one C file, compiled whole and judged against the game's span
    # of it (the function files stay where it doesn't, and why is in the README)
    log("putting the matched functions back into their source files")
    unit_list, unit_fallback = [], []
    by_name = {f["name"]: f for f in functions}
    taken = {p.name for p in (out / "include").iterdir()}
    groups: dict = {}
    for row in rows:
        groups.setdefault(row["unit"], []).append(row)
    read = net.reader(proj)
    library = _runtime_names(cfg["compiler"]["toolchain"])
    for unit, members in groups.items():
        if unit is None:
            continue
        if any(r["name"] in library for r in members):  # (glibc's atexit: the link brings libc_nonshared.a's)
            continue
        if not any(by_name[r["name"]].get("c") for r in members):
            continue  # (nothing of it is C: hand-written assembly, a library's)
        if not all(by_name[r["name"]].get("c") for r in members):
            missing = [r["name"] for r in members if not by_name[r["name"]].get("c")]
            unit_fallback.append((unit, f"{', '.join(missing[:3])}{' ...' if len(missing) > 3 else ''} isn't C yet"))
            continue
        stem = _unit_name(unit)
        name = stem if f"{stem}.h" not in taken and not (out / "src" / f"{stem}.c").exists() else f"{stem}_file"
        hdr = net._context(proj["id"], net._effective_unit(members[0], units))["header"]
        merged, why, statics = _unit_file(net, proj, cfg, console, members, headers[net._effective_unit(members[0], units)],
                                          f"{name}.h", hdr, syms, read,
                                          {r["name"]: by_name[r["name"]].get("statics") or {} for r in members})
        if merged is None:
            unit_fallback.append((unit, why))
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
            (out / f["c"]).unlink()
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
        unit_list.append(entry)
    log(f"{len(unit_list)} of {len([u for u in groups if u is not None])} source files are one C file each")

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
    for f, code, refs in pieces:
        asm.mkdir(exist_ok=True)
        (asm / f"{f['name']}.s").write_text(assembly(f["name"], code, refs), encoding="utf-8")
        f["s"] = f"asm/{f['name']}.s"
        f["refs"] = {str(k): v for k, v in refs.items()}

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
        "program": re.sub(r"[^\w.-]", "_", Path(cfg["rom"].get("program") or cfg["rom"]["file"]).name),
        "sha1": hashlib.sha1(image).hexdigest(), "toolchain": cfg["compiler"]["toolchain"],
        "text": {"vram": text["sh_addr"], "offset": text["sh_offset"], "size": text["sh_size"]},
        "functions": functions, "units": unit_list,
        "symbols": dict(sorted(symbols.items(), key=lambda kv: kv[1])),
        "got": cfg.get("got"),  # (where -fPIC code finds the GOT, and what each entry holds)
    }
    (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
    shutil.copyfile(Path(__file__).with_name("export_build.py"), out / "build.py")
    export_make.write(out, build)
    shutil.copyfile(work / cfg["rom"]["file"], out / "baserom")
    matched = sum(1 for f in functions if f.get("c"))
    _docs(out, proj["name"], matched, len(functions), fallback, build["program"], len(unit_list), unit_fallback)
    # (asm/ and data/ are your copy's code and data, written from it: never in git)
    # (and the compiler `make toolchain` downloads into tools/: only the tree's scripts are its own)
    (out / ".gitignore").write_text("build/\nbaserom*\nasm/\ndata/\ntools/*/\ntools/.downloads/\n", encoding="utf-8")

    log("building the exported project to check it rebuilds the program byte for byte")
    proc = subprocess.run(capped([sys.executable, "build.py"]), cwd=out, capture_output=True, text=True, timeout=3600,
                          encoding="utf-8", errors="replace")
    identical = "identical to the original" in proc.stdout
    relinked = proc.returncode == 0 and "relinked" in proc.stdout
    if not (identical and relinked):
        log((proc.stdout + proc.stderr)[-3000:])
    return {"path": str(out), "identical": identical, "relinked": relinked, "matched": matched,
            "functions": len(functions), "fallback": fallback, "units": len(unit_list), "unit_fallback": unit_fallback,
            "log": (proc.stdout + proc.stderr)[-3000:]}


def _docs(out: Path, title: str, matched: int, total: int, fallback, program: str = "program", whole: int = 0,
          unit_fallback=()) -> None:
    notes = "".join(f"\n- `{n}`: kept as the program's bytes, {why}" for n, why in fallback)
    notes += "".join(f"\n- `{u}`: one file per function in `src/{_unit_name(u)}/` for now: {why}"
                     for u, why in unit_fallback)
    (out / "README.md").write_text(f"""# {title} (decompilation)

A matching decompilation of {title}, a Linux (32-bit x86) program, started with [decompdecomp](https://github.com/n-delic/decompdecomp).
{matched} of {total} functions are C that GCC 2.95.3 compiles to exactly the original code; the rest is still the
program's own bytes. {whole} of the program's source files are back together, each one C file that compiles to the
original file's code, function after function. `build.py` rebuilds every decompiled file and function where it lies
in the program and checks the result against your original, byte for byte.

## Build

1. Put your own copy of the program here as `baserom` (it is in `.gitignore`; never commit it).
2. `make`: builds `build/{program}`, the program linked anew from the C. The first time it downloads the compiler the
   program was built with into `tools/` (`make toolchain`: pinned archives, each checked against its SHA-256; where
   the system has no 32-bit loader, a 32-bit C runtime too). Needs make, python3, curl or wget, tar and ar; not
   decompdecomp.
3. `python build.py` (with decompdecomp installed) checks that the C still rebuilds your copy byte for byte, as
   `build/program`, and then runs `make`.
4. `make port`: the same C built by your system's GCC (`PORT_CC`, default `gcc -m32`; `PORT_FLAGS`), against the
   program's own C library headers from `tools/`, linked the same way into `build/port/{program}`. Nothing has to
   match there: it's how the C fares with a modern compiler (its warnings are worth reading).

## Layout

| Path | What it is |
| :-- | :-- |
| `src/<source file>.c` | A source file of the program, its functions in their original order, its statics defined once. |
| `src/<source file>/<function>.c` | The functions of a file that isn't back together yet (README's notes say why), one per file. |
| `include/` | Types, structs and prototypes: `common.h` for the program, `common_<source file>.h` for each file's own, `<source file>.h` what a source file declares for itself (its functions, and what it uses from elsewhere). |
| `asm/<function>.s` | What isn't C yet, as assembly (from your copy). |
| `data/program.s` | The program's data, every global and pointer named (written from your copy by the first relink). |
| `Makefile`, `tools/` | The build: `make` links `build/{program}`; `tools/relink.py` its steps, `tools/toolchain.sh` the compiler's download. |
| `build.json`, `build.py` | Where each function is; `build.py` (decompdecomp) checks the C against your copy, as `build/program`. |

`build/{program}` is every function compiled as written and laid out by the linker above the program's data, where
it may grow, with the compiler's own crt files and the libraries it imports. That's the one to change: edit any
function (make it longer, add one in its file), run `make`, and run `build/{program}` where your copy runs.

Keep going with any tool: write a function as `src/<source file>/<name>.c`, run `python build.py check <name>`,
then `python build.py`. Change a source file and run `python build.py check <file>` (or the name of one of its
functions). When it says *identical*, the program still matches.

## The data, and what isn't C yet

The first relink writes the program's data as `data/program.s`, from your copy: every global labelled by name, every
word that pointed at a function, a string or other data written as that (`.long greet`, `.long __orig_rodata+0x1a4`),
its constructor and destructor lists (a C++ program's globals) by name. Change it like any source. The data stays
where the original has it; `make move` lays it out after the code instead, the addresses the C
still writes as numbers moved with it (`make move`; it reads the code with Python's capstone). What's in `asm/` isn't C yet: assembly that names what it calls, so it moves
with the rest. `asm/` and `data/` are made from your copy: keep them out of git (`.gitignore` does).

The program's code and data belong to their rights holder: keep this tree to yourself unless you have the right to
share it.{chr(10) + chr(10) + '## Notes' + notes if notes else ''}
""", encoding="utf-8")
    (out / "AGENTS.md").write_text("""# Working on this decompilation

- Goal: C that GCC 2.95.3 turns into exactly the original bytes. `python build.py` must end with "identical".
- Write a function as `src/<source file>/<name>.c` (one function, its header included first), then
  `python build.py check <name>`: it compiles it, links it at its address, compares it with the original and
  records it in `build.json`.
- A source file that is back together (`src/<file>.c`) is compiled whole: `python build.py check <file>` compares
  its code, first function to last, with the original's.
- Shared types and prototypes go in `include/`. Never edit `baserom` to force a match.
- `make` links a new program from the C (build/<program>), without decompdecomp: changes that don't match (a mod,
  a fix) go there. `python build.py` checks the matching first.
""", encoding="utf-8")
