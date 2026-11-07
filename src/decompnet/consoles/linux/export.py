"""Export a Linux program's project as a rebuildable source tree: the base for ports and mods.

The matched functions as C (src/<source file>/<function>.c, each with its source file's header), the shared types in
include/, and a build (export_build.py, copied as build.py) that compiles each with the pinned GCC 2.95.3 exactly as
the judge did, links it alone at its address in the program with the toolchain's own ld (its own constants placed
where the game keeps them, the rest of the game's symbols at their addresses), puts its code in place in a copy of
your program and checks the result against the original, byte for byte. What isn't C yet stays your copy's bytes.

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


def _unit_name(unit: str | None) -> str:
    """A source file's folder and header name: `game.c` -> game, `src/zlib/inflate.c` -> inflate."""
    return re.sub(r"\W", "_", Path(unit or "program").stem) or "program"


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

    names = {f["name"] for f in functions if f.get("c")}
    symbols = {s.name: s.address for s in syms.by_name.values() if s.name not in names and s.address}
    for f in functions:  # (automatic names matched C uses that no symbol has: their address is in the name)
        if f.get("c"):
            for word in set(re.findall(r"\b[A-Za-z]\w*_[0-9A-Fa-f]{1,8}\b", (out / f["c"]).read_text(encoding="utf-8"))):
                if (m := AUTO_NAME.match(word)) and word not in names:
                    symbols.setdefault(word, int(m.group(1), 16))
    build = {
        "title": proj["name"], "platform": console.id, "image": "baserom", "output": "build/program",
        "sha1": hashlib.sha1(image).hexdigest(), "toolchain": cfg["compiler"]["toolchain"],
        "text": {"vram": text["sh_addr"], "offset": text["sh_offset"], "size": text["sh_size"]},
        "functions": functions, "symbols": dict(sorted(symbols.items(), key=lambda kv: kv[1])),
    }
    (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
    shutil.copyfile(Path(__file__).with_name("export_build.py"), out / "build.py")
    shutil.copyfile(work / cfg["rom"]["file"], out / "baserom")
    matched = sum(1 for f in functions if f.get("c"))
    _docs(out, proj["name"], matched, len(functions), fallback)
    (out / ".gitignore").write_text("build/\nbaserom*\n", encoding="utf-8")

    log("building the exported project to check it rebuilds the program byte for byte")
    proc = subprocess.run(capped([sys.executable, "build.py"]), cwd=out, capture_output=True, text=True, timeout=3600,
                          encoding="utf-8", errors="replace")
    identical = proc.returncode == 0 and "identical" in proc.stdout
    if not identical:
        log((proc.stdout + proc.stderr)[-3000:])
    return {"path": str(out), "identical": identical, "matched": matched, "functions": len(functions),
            "fallback": fallback, "log": (proc.stdout + proc.stderr)[-3000:]}


def _docs(out: Path, title: str, matched: int, total: int, fallback) -> None:
    notes = "".join(f"\n- `{n}`: kept as the program's bytes, {why}" for n, why in fallback)
    (out / "README.md").write_text(f"""# {title} (decompilation)

A matching decompilation of {title}, a Linux (32-bit x86) program, started with [decompdecomp](https://github.com/n-delic/decompdecomp).
{matched} of {total} functions are C that GCC 2.95.3 compiles to exactly the original code; the rest is still the
program's own bytes. `build.py` rebuilds every decompiled function where it lies in the program and checks the
result against your original, byte for byte.

## Build

1. Put your own copy of the program here as `baserom` (it is in `.gitignore`; never commit it).
2. `python build.py` (needs decompdecomp installed, for Slackware 8.0's GCC 2.95.3 and binutils).

## Layout

| Path | What it is |
| :-- | :-- |
| `src/<source file>/<function>.c` | Decompiled functions, one per file, each matching the original. |
| `include/` | Types, structs and prototypes: `common.h` for the program, `common_<source file>.h` for each file's own. |
| `build.json`, `build.py` | Where each function is and how it's built. `build/program` is the rebuilt program. |

Keep going with any tool: write a function as `src/<source file>/<name>.c`, run `python build.py check <name>`,
then `python build.py`. When it says *identical*, the program still matches. Once all of its code is C, the program
can be relinked whole, changed and moved to other platforms.

The program's code and data belong to their rights holder: keep this tree to yourself unless you have the right to
share it.{chr(10) + chr(10) + '## Notes' + notes if notes else ''}
""", encoding="utf-8")
    (out / "AGENTS.md").write_text("""# Working on this decompilation

- Goal: C that GCC 2.95.3 turns into exactly the original bytes. `python build.py` must end with "identical".
- Write a function as `src/<source file>/<name>.c` (one function, its header included first), then
  `python build.py check <name>`: it compiles it, links it at its address, compares it with the original and
  records it in `build.json`.
- Shared types and prototypes go in `include/`. Never edit `baserom` to force a match.
""", encoding="utf-8")
