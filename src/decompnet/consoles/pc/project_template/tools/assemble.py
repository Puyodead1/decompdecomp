#!/usr/bin/env python3
"""Make the game's program from its source (what `tools/relink.py --source` wrote): every function, the data and the
resources as MASM, the header and what follows the last section as they are, each assembled by Visual C++ 6.0's
MASM (ml.exe 6.15) and put where the program has it, its references filled in, and checked against the SHA-1 the
source names. A project that has the source and not your copy builds from this: it writes orig/<program> when there
is none (and when there is one, says whether the source makes it).

    python tools/assemble.py SOURCE/program.json OBJECTS --ml ML.EXE [--wrapper WIBO] [--out PROGRAM]

Standard library only. Made by decompdecomp.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

DIR32, REL32 = 0x06, 0x14
EXTERNAL, WEAK_EXTERNAL = 2, 105


def _relink():
    spec = importlib.util.spec_from_file_location("relink", Path(__file__).with_name("relink.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assemble(program: dict, source: Path, objects: Path, ml: list[str]) -> bytes:
    """The program, made from its source (`program`: program.json)."""
    relink = _relink()
    objects.mkdir(parents=True, exist_ok=True)
    placed = []  # (piece, the object read, each section's address)
    for piece in program["pieces"]:
        asm = source / piece["asm"]
        obj = objects / (Path(piece["asm"]).stem + ".obj")
        if not obj.exists() or obj.stat().st_mtime < asm.stat().st_mtime:
            # (from the source's folder, by relative paths: ml.exe takes an absolute path off Windows for an option)
            said = subprocess.run([*ml, "/nologo", "/c", "/coff", "/Cp", f"/Fo{os.path.relpath(obj, source)}",
                                   piece["asm"]], capture_output=True, text=True, errors="replace", cwd=source)
            if said.returncode != 0 or not obj.exists():
                sys.exit(f"assemble: {piece['asm']} doesn't assemble:\n{(said.stdout + said.stderr).strip()}")
        read = relink.Compiled(obj.read_bytes())
        at, where = piece["at"], {}
        for number, sec in enumerate(read.sections, 1):
            if sec["name"].startswith(".debug$") or sec["flags"] & 0xA00:
                continue
            where[number] = at
            at += sec["size"]
        placed.append((piece, read, where))
    # every public name's address
    names, aliases = {}, {}
    for _, read, where in placed:
        for s in read.symbols.values():
            if s["cls"] == EXTERNAL and s["section"] in where:
                names[s["name"]] = where[s["section"]] + s["value"]
            elif s["cls"] == EXTERNAL and s["section"] == -1:  # (a number; one named <...>$rva is an RVA, for the
                # linker's relative jumps outside the program: relink.py)
                names[s["name"]] = s["value"] + (program["base"] if s["name"].endswith("$rva") else 0)
            elif s["cls"] == WEAK_EXTERNAL:
                aliases[s["name"]] = read.symbols[struct.unpack_from("<I", s["aux"], 0)[0]]["name"]
    aliases.update(program.get("aliases", {}))  # (written there: ML 6.15 stops on ALIAS)
    for name, default in aliases.items():
        if name not in names and default in names:
            names[name] = names[default]
    base = program["base"]
    end = max(s["addr"] + max(s["vsize"], s["raw_size"]) for s in program["sections"])
    image = bytearray(end - base)
    missing = set()
    for piece, read, where in placed:
        rvas = {piece["at"] + off for off in piece.get("rvas", [])}
        for number, sec in enumerate(read.sections, 1):
            if number not in where:
                continue
            at = where[number]
            body = bytearray(sec["data"] or bytes(sec["size"]))
            for off, index, kind in sec["relocs"]:
                s = read.symbols[index]
                target = where[s["section"]] + s["value"] if s["section"] in where else names.get(s["name"])
                if target is None:
                    missing.add(s["name"])
                    continue
                inline = struct.unpack_from("<i", body, off)[0]
                value = target + inline - (at + off + 4 if kind == REL32 else 0)
                if at + off in rvas:
                    value -= base
                struct.pack_into("<I", body, off, value & 0xFFFFFFFF)
            image[at - base:at - base + len(body)] = body
    if missing:
        sys.exit(f"assemble: {len(missing)} names nothing in the source defines: {', '.join(sorted(missing)[:8])}")
    exe = bytearray((source / "header.bin").read_bytes())
    for s in program["sections"]:
        exe = exe.ljust(s["raw_at"] + s["raw_size"], b"\0")
        size = min(s["vsize"] or s["raw_size"], s["raw_size"])
        exe[s["raw_at"]:s["raw_at"] + size] = image[s["addr"] - base:s["addr"] - base + size]
        if s.get("tail"):
            tail = bytes.fromhex(s["tail"])
            exe[s["raw_at"] + size:s["raw_at"] + size + len(tail)] = tail
    return bytes(exe.ljust(program["size"] - len((source / "overlay.bin").read_bytes()), b"\0")) + \
        (source / "overlay.bin").read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser(description="Makes the game's program from its source")
    parser.add_argument("program", help="the source's program.json")
    parser.add_argument("objects", help="where the assembled objects go")
    parser.add_argument("--ml", required=True, help="Visual C++ 6.0's MASM, ml.exe")
    parser.add_argument("--wrapper", default="", help="what runs it (wibo, off Windows)")
    parser.add_argument("--out", default="", help="where the program goes (default: where functions.json has it)")
    args = parser.parse_args()
    path = Path(args.program)
    program = json.loads(path.read_text(encoding="utf-8"))
    exe = assemble(program, path.parent, Path(args.objects), [*([args.wrapper] if args.wrapper else []), args.ml])
    made = hashlib.sha1(exe).hexdigest()
    out = Path(args.out or program["exe"])
    if made != program["sha1"]:
        aside = out.with_name(out.name + ".differs")  # (to compare with the game's)
        aside.parent.mkdir(parents=True, exist_ok=True)
        aside.write_bytes(exe)
        sys.exit(f"assemble: the source makes a program with the SHA-1 {made}, not {program['sha1']} ({aside})")
    if out.exists():
        same = out.read_bytes() == exe
        print(f"{out}: {'the source makes it byte for byte' if same else 'the source makes another program'}")
        sys.exit(0 if same else 1)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(exe)
    print(f"{out}: made from the source ({len(program['pieces'])} files), byte for byte the game's")


if __name__ == "__main__":
    main()
