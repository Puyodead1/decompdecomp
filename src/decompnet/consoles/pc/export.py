"""A Windows PC project's export: the project, and its game's program as source beside it.

The project is the export already (`ninja rebuild` rebuilds the program byte for byte, `ninja relink` links it anew
with Visual C++'s linker). What Export adds is the rest of the program as source, in the project's source/ folder:
every function as MASM, a line per instruction with capstone's text of it as a comment (its C, where it has any,
is in src/ too); the data as C, a file per part of each section (data/: each global at its place by a #pragma
data_seg, a string as a string, a pointer as the address of what it points at, a table of records an array of a
struct of its own; data.h declares every one), the
import tables MASM; the resources, and program.json (tools/relink.py --source writes it). tools/assemble.py makes
the program from that with Visual C++ 6.0's MASM and compiler, and the export checks it's the user's copy, byte for
byte. Each DLL of the game's (functions.json's "modules") is source too, in source/<its folder>/, at the address the
project gives it; assemble.py moves what it makes back to the DLL's own. source/ is
made from the user's copy: the project's .gitignore keeps it out of git, as orig/ is. The C and the data are
annotated for reccmp too, with its project files (reccmp.py).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ... import toolchains
from ...forks.project import ForkError, ForkProject

SOURCE = "source"


def disassembler():
    """capstone's 32-bit x86, as tools/relink.py's write_source wants it: (code, address) -> [(offset, length,
    text)], data it can't read as code skipped."""
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True

    def disassemble(code: bytes, addr: int) -> list[tuple[int, int, str]]:
        return [(i.address - addr, i.size, f"{i.mnemonic} {i.op_str}".strip()) for i in md.disasm(code, addr)
                if i.mnemonic != ".byte"]
    return disassemble


def ml() -> list[str]:
    """Visual C++ 6.0's MASM (ml.exe 6.15, in its service packs' folders) and what runs it."""
    found = sorted(toolchains.path("msvc").glob("6.0SP*/Bin/ml.exe"), reverse=True) \
        if toolchains.installed("msvc") is not None else []
    if not found:
        raise ForkError("the program as source is assembled with Visual C++ 6.0's MASM: install Visual C++ 6.0 in "
                        "Setup (Compilers & tools), then export again")
    runner = [] if sys.platform == "win32" else [str(toolchains.binary("wibo"))]
    return [*runner, str(found[0])]


def export_pc(root: Path, version: str, log=print) -> dict:
    """Write the program as source in `root`/source and check that it makes the user's copy byte for byte."""
    from .scratch import _template_tool

    relink = _template_tool("relink")
    config = root / "config" / version / "functions.json"
    info = json.loads(config.read_text(encoding="utf-8"))
    exe = (root / info["exe"]).read_bytes()
    out = root / SOURCE
    if (out / "program.json").exists():  # (one this wrote before: its files may name functions no longer there)
        shutil.rmtree(out)
    identical, files = True, 0
    try:
        made_of = list(relink.programs(info, exe, root, Path("build") / version))
    except SystemExit as e:  # (the tool says why and stops: here, the export's error)
        raise ForkError(str(e.code)) from None
    for module, linker in made_of:  # (the .exe's in source/, each DLL of the game's in source/<its folder>/)
        folder = out / module
        name = linker.name
        log(f"writing {name} as source (its code MASM, with each instruction's text; its data C)")
        linker.out = root / linker.out  # (its own objects, as `ninja relink` writes them)
        try:
            program = linker.write_source(folder, disassemble=disassembler())
        except SystemExit as e:
            raise ForkError(str(e.code)) from None
        files += len(program["pieces"])
        log(f"assembling and compiling its {len(program['pieces']):,} files with Visual C++ 6.0's MASM and compiler")
        with tempfile.TemporaryDirectory() as tmp:
            made = Path(tmp) / name
            said = subprocess.run([sys.executable, str(Path(relink.__file__).with_name("assemble.py")),
                                   str(folder / "program.json"), str(root / "build" / version / "source" / module),
                                   "--ml", ml()[-1], *(["--wrapper", ml()[0]] if len(ml()) > 1 else []),
                                   "--out", str(made)],
                                  capture_output=True, text=True, errors="replace", timeout=3600)
            same = said.returncode == 0 and made.exists() and made.read_bytes() == (root / program["exe"]).read_bytes()
        identical = identical and same
        log(f"{folder.relative_to(root).as_posix()}/ makes {program['exe']} byte for byte" if same else
            f"{folder.relative_to(root).as_posix()}/ doesn't make {program['exe']}: "
            f"{(said.stdout + said.stderr).strip()[-500:]}")
    # reccmp's annotations and project files (reccmp.py): the project works with the LEGO Island decompilation's tool
    from . import reccmp

    functions, globals_ = reccmp.annotate(root, info)
    reccmp.project_files(root, info, version)
    log(f"annotated {functions:,} functions and {globals_:,} globals for reccmp (reccmp-project.yml; `ninja reccmp` "
        "builds the program and PDB it compares)")
    # the build files again, now with the source: `ninja relink` takes what isn't from C from it, `ninja relink-source`
    # links it alone (a build.ninja written before there was any has neither)
    ok, said = ForkProject(root).reconfigure(version, log=lambda *_: None)
    if not ok:
        log(f"the project's build files weren't written again ({said.strip()[-300:]}): run tools/configure.py")
    ignore = root / ".gitignore"
    text = ignore.read_text(encoding="utf-8") if ignore.exists() else ""
    if f"{SOURCE}/" not in text.split():
        ignore.write_text(text + ("" if text.endswith("\n") or not text else "\n") + f"{SOURCE}/\n", encoding="utf-8")
    return {"path": str(root), "identical": identical, "source": files,
            "functions": sum(len(fns) for fns in info["units"].values())}
