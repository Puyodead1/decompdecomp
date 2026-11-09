"""A Windows PC project's export: the project, and its game's program as source beside it.

The project is the export already (`ninja rebuild` rebuilds the program byte for byte, `ninja relink` links it anew
with Visual C++'s linker). What Export adds is the rest of the program as source, in the project's source/ folder:
every function as MASM, a line per instruction with capstone's text of it as a comment (its C, where it has any,
is in src/ too); the data as C, a file per part of each section (data/: each global at its place by a #pragma
data_seg, a string as a string, a pointer as the address of what it points at, a table of records an array of a
struct of its own; data.h declares every one), the
import tables MASM; the resources, and program.json (tools/relink.py --source writes it). tools/assemble.py makes
the program from that with Visual C++ 6.0's MASM and compiler, and the export checks it's the user's copy, byte for
byte. source/ is
made from the user's copy: the project's .gitignore keeps it out of git, as orig/ is.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ... import toolchains
from ...forks.project import ForkError

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
    log("writing the program as source (its code MASM, with each instruction's text; its data C)")
    linker = relink.Relink(info, relink.Image(exe), root, Path("build") / version)
    linker.out = root / "build" / version / "relink"  # (its own objects, as `ninja relink` writes them)
    try:
        program = linker.write_source(out, disassemble=disassembler())
    except SystemExit as e:  # (the tool says why and stops: here, the export's error)
        raise ForkError(str(e.code)) from None
    log(f"assembling and compiling its {len(program['pieces']):,} files with Visual C++ 6.0's MASM and compiler")
    with tempfile.TemporaryDirectory() as tmp:
        made = Path(tmp) / Path(info["exe"]).name
        said = subprocess.run([sys.executable, str(Path(relink.__file__).with_name("assemble.py")),
                               str(out / "program.json"), str(root / "build" / version / "source"),
                               "--ml", ml()[-1], *(["--wrapper", ml()[0]] if len(ml()) > 1 else []), "--out", str(made)],
                              capture_output=True, text=True, errors="replace", timeout=3600)
        identical = said.returncode == 0 and made.exists() and made.read_bytes() == exe
    log(f"{SOURCE}/ makes {info['exe']} byte for byte" if identical else
        f"{SOURCE}/ doesn't make {info['exe']}: {(said.stdout + said.stderr).strip()[-500:]}")
    ignore = root / ".gitignore"
    text = ignore.read_text(encoding="utf-8") if ignore.exists() else ""
    if f"{SOURCE}/" not in text.split():
        ignore.write_text(text + ("" if text.endswith("\n") or not text else "\n") + f"{SOURCE}/\n", encoding="utf-8")
    return {"path": str(root), "identical": identical, "source": len(program["pieces"]),
            "functions": sum(len(fns) for fns in info["units"].values())}
