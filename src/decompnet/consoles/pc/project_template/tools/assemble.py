#!/usr/bin/env python3
"""Make the game's program from its source (what `tools/relink.py --source` wrote): every function, the import
tables and the resources as MASM, the data as C, the header and what follows the last section as they are, each
assembled by Visual C++ 6.0's MASM (ml.exe 6.15) or compiled by its compiler (CL.EXE, beside it) and put where the
program has it (a global of the C where its #pragma data_seg says), its references filled in, and checked against
the SHA-1 the source names. A project that has the source and not your copy builds from this: it writes orig/<program> when there
is none (and when there is one, says whether the source makes it).

    python tools/assemble.py SOURCE/program.json OBJECTS --ml ML.EXE [--wrapper WIBO] [--out PROGRAM]
    python tools/assemble.py SOURCE/program.json OBJECTS --ml ML.EXE --link LINK.EXE [--wrapper WIBO]

With --link (`ninja relink-source`), Visual C++'s LINK.EXE links the program from the objects instead, as
tools/relink.py links a project's: assembly or C you edited may make a function or a global longer or shorter, and
everything after it moves, what points at it following (writes OBJECTS/../relink-source/<program>).

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

DIR32, DIR32NB, REL32 = 0x06, 0x07, 0x14
EXTERNAL, WEAK_EXTERNAL = 2, 105


def _relink():
    spec = importlib.util.spec_from_file_location("relink", Path(__file__).with_name("relink.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _env() -> dict:
    """The environment CL.EXE and ML.EXE run in: PATH without the folders that stop wibo (tools/compile.py's
    clean_path: under WSL, a Windows folder in /mnt that refuses a look stopped CL.EXE)."""
    spec = importlib.util.spec_from_file_location("compile_tool", Path(__file__).with_name("compile.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {**os.environ, "PATH": module.clean_path(os.environ.get("PATH", ""))}


def compiler(ml: list[str]) -> list[str]:
    """Visual C++ 6.0's compiler, CL.EXE, beside its MASM (the data's C is compiled with it), and what runs it."""
    folder = Path(ml[-1]).parent
    found = next((folder / n for n in ("CL.EXE", "cl.exe", "Cl.exe") if (folder / n).exists()), folder / "CL.EXE")
    return [*ml[:-1], str(found)]


def assembled(program: dict, source: Path, objects: Path, ml: list[str]) -> list[tuple[dict, Path, object]]:
    """Each piece of the source assembled, or compiled (the data's C), when its object is older than it: (piece, its
    object, the object read)."""
    relink = _relink()
    objects.mkdir(parents=True, exist_ok=True)
    out = []
    header = source / "data" / "data.h"
    env = _env()
    for piece in program["pieces"]:
        if "c" in piece:
            c = source / piece["c"]
            obj = objects / (Path(piece["c"]).stem + ".obj")
            newest = max(c.stat().st_mtime, header.stat().st_mtime if header.exists() else 0)
            if not obj.exists() or obj.stat().st_mtime < newest:
                said = subprocess.run([*compiler(ml), "/nologo", "/c", "/Zl", "/Zm500", f"/Fo{os.path.relpath(obj, source)}",
                                       piece["c"]], capture_output=True, text=True, errors="replace", cwd=source,
                                      env=env)
                if said.returncode != 0 or not obj.exists():
                    sys.exit(f"assemble: {piece['c']} doesn't compile:\n{(said.stdout + said.stderr).strip()}")
            out.append((piece, obj, relink.Compiled(obj.read_bytes())))
            continue
        asm = source / piece["asm"]
        obj = objects / (Path(piece["asm"]).stem + ".obj")
        if not obj.exists() or obj.stat().st_mtime < asm.stat().st_mtime:
            # (from the source's folder, by relative paths: ml.exe takes an absolute path off Windows for an option)
            said = subprocess.run([*ml, "/nologo", "/c", "/coff", "/Cp", f"/Fo{os.path.relpath(obj, source)}",
                                   piece["asm"]], capture_output=True, text=True, errors="replace", cwd=source,
                                  env=env)
            if said.returncode != 0 or not obj.exists():
                sys.exit(f"assemble: {piece['asm']} doesn't assemble:\n{(said.stdout + said.stderr).strip()}")
        out.append((piece, obj, relink.Compiled(obj.read_bytes())))
    return out


def _placed(sections: list[dict]) -> list[int]:
    """The numbers of an object's sections that are the program's (not its debug information or linker notes)."""
    return [n for n, sec in enumerate(sections, 1) if not (sec["name"].startswith(".debug$") or sec["flags"] & 0xA00)]


def _where(piece: dict, read) -> dict[int, int]:
    """Each of a piece's sections' address: one after the other from where program.json puts it, or (the data's C)
    as its name says, <section>$<address> (its #pragma)."""
    where, at = {}, piece["at"]
    for n in _placed(read.sections):
        name = read.sections[n - 1]["name"]
        if "c" in piece:
            place = name.partition("$")[2]
            if len(place) == 8 and all(c in "0123456789ABCDEFabcdef" for c in place):
                where[n] = int(place, 16)
            elif read.sections[n - 1]["size"]:
                where[n] = None  # (data of the C's own, with no place in the game: after the game's, when linked)
            continue
        where[n] = at
        at += read.sections[n - 1]["size"]
    return where


def public_names(program: dict, placed: list[tuple[dict, object, dict[int, int]]]) -> dict[str, int]:
    """Every public name's address, each piece where program.json puts it (`placed`: piece, the object read, each
    section's address); the aliases program.json and the objects give, at their default's."""
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
    return names


def assemble(program: dict, source: Path, objects: Path, ml: list[str]) -> bytes:
    """The program, made from its source (`program`: program.json), each piece where program.json puts it."""
    placed = []  # (piece, the object read, each section's address)
    for piece, _, read in assembled(program, source, objects, ml):
        where = _where(piece, read)
        if None in where.values():
            sys.exit(f"assemble: {piece['c']} has data with no place in the game (a global without a #pragma "
                     "data_seg naming its address): it can be linked (--link), not put in the game's places")
        placed.append((piece, read, where))
    names = public_names(program, placed)
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
    return home(program, bytes(exe.ljust(program["size"] - len((source / "overlay.bin").read_bytes()), b"\0")) +
                (source / "overlay.bin").read_bytes())


def home(program: dict, exe: bytes) -> bytes:
    """A DLL of the game's back at its own address, the one its header names (program.json's "home"): its source is
    at the address the project gives it, where functions.json has its functions."""
    return _relink()._sibling("delink").rebase(exe, program["home"]) if program.get("home") else exe


def prepare(program: dict, source: Path, objects: Path, ml: list[str], folder: Path, skip=None) -> dict:
    """The source's objects as Visual C++'s LINK.EXE links them, in `folder`/objects: each piece in the program's
    section it's in (by its name and flags; the part of a section past its bytes in the file is .bss, as a compiler's
    uninitialised data), in the order program.json has them, the words it names as RVAs DIR32NB (MASM 6.15 has no
    IMAGEREL); the base relocations left out (the linker makes them again, for where everything is now). `skip(piece)`:
    a piece another object stands for (tools/relink.py --asm: a unit, whose functions it takes one by one).
    {"paths", "changed" (the pieces whose size isn't the game's), "placed" (each piece where program.json has it),
    "skipped" ({a skipped piece's name: its object, read}), "where" ({each path: its sections' addresses}), "image"
    (the header's settings)}."""
    relink = _relink()
    header = (source / "header.bin").read_bytes()
    image = relink.Image(header)
    table = relink.section_table(header)
    rel_rva = image.dirs[relink.BASE_RELOCATIONS][0] if relink.BASE_RELOCATIONS < len(image.dirs) else 0
    (folder / "objects").mkdir(parents=True, exist_ok=True)
    paths, changed, placed, skipped, where_of = [], [], [], {}, {}
    with_c = any("c" in piece for piece in program["pieces"])  # (the data as C: every part of it in a section named
    # for its place, <section>$<address>, which the linker puts in the order of their names)
    for piece, obj, read in sorted(assembled(program, source, objects, ml), key=lambda p: p[0]["at"]):
        numbers = _placed(read.sections)
        size = sum(read.sections[n - 1]["size"] for n in numbers)
        if size != piece["size"]:
            changed.append(f"{piece.get('asm') or piece['c']} ({piece['size']:,} -> {size:,} bytes)")
        where = _where(piece, read)
        placed.append((piece, read, where))
        if skip is not None and skip(piece):
            skipped[Path(piece["asm"]).stem] = read
            continue
        s = next((s for s in table if s["addr"] <= piece["at"] < s["addr"] + max(s["vsize"], s["raw_size"])), None)
        if s is None:
            sys.exit(f"assemble: {piece['asm']} is at 0x{piece['at']:08X}, in none of the program's sections")
        if rel_rva and s["addr"] <= image.base + rel_rva < s["addr"] + max(s["vsize"], s["raw_size"]):
            continue  # (the base relocations: the linker makes them again, for where everything is now)
        initialised = min(s["vsize"] or s["raw_size"], s["raw_size"])
        flags = (s["flags"] & 0xFE0000E0 & ~0x00F00000) | relink.ALIGN_1  # (where the one before it ends)
        name = s["name"]
        uninitialised = piece["at"] >= s["addr"] + initialised
        if uninitialised:
            name, flags = ".bss", (flags & ~relink.CNT_DATA) | relink.CNT_BSS
        elif name == ".rsrc":
            name = ".rsrc$01"  # (as the resource converter names resources for the linker)
        if with_c and (name != ".rsrc$01" and not flags & relink.CNT_CODE or "c" in piece):
            sections = {}
            for n in numbers:
                sec = read.sections[n - 1]
                if "c" in piece:  # (its own sections: each global's, by its #pragma; the C's own data after the game's)
                    own = sec["name"] if "$" in sec["name"] else sec["name"] + "$~"
                    sections[n] = (own, (sec["flags"] & ~0x00F00000) | relink.ALIGN_1)
                else:
                    sections[n] = (f"{name}${where[n]:08X}", flags)
            made, number = relink.regrouped(read, sections)
            for off_n, new in number.items():  # (the words program.json says are RVAs: DIR32NB)
                rvas = {piece["at"] + off for off in piece.get("rvas", [])}
                made.sections[new - 1]["relocs"] = [
                    (off, symbol, DIR32NB if where[off_n] is not None and where[off_n] + off in rvas else kind)
                    for off, symbol, kind in made.sections[new - 1]["relocs"]]
                if uninitialised and "c" not in piece:
                    made.sections[new - 1]["data"] = None
            path = folder / "objects" / obj.name
            path.write_bytes(made.bytes())
            paths.append(path)
            where_of[str(path)] = {number[n]: a for n, a in where.items() if a is not None}
            continue
        data = bytearray(obj.read_bytes())
        _, count, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, 0)
        rvas, at = set(piece.get("rvas", [])), 0
        for n in range(1, count + 1):
            h = 20 + opt_size + 40 * (n - 1)
            if n not in numbers:
                continue
            sec_size, = struct.unpack_from("<I", data, h + 16)
            reloc_at, = struct.unpack_from("<I", data, h + 24)
            relocs, = struct.unpack_from("<H", data, h + 32)
            for r in range(relocs):  # (a word program.json says is an RVA: DIR32NB, which MASM 6.15 can't write)
                off, = struct.unpack_from("<I", data, reloc_at + 10 * r)
                if at + off in rvas:
                    struct.pack_into("<H", data, reloc_at + 10 * r + 8, DIR32NB)
            data[h:h + 8] = name.encode("latin-1")[:8].ljust(8, b"\0")
            struct.pack_into("<I", data, h + 36, flags)
            if uninitialised:
                struct.pack_into("<I", data, h + 20, 0)
            at += sec_size
        path = folder / "objects" / obj.name
        path.write_bytes(bytes(data))
        paths.append(path)
        where_of[str(path)] = where
    aliases = dict(program.get("aliases", {}))
    if aliases:  # (weak externals, as the linker reads them; ML 6.15 stops on ALIAS)
        coff = relink.Coff()
        for name, default in aliases.items():
            coff.alias(name, default)
        (folder / "objects" / "aliases.obj").write_bytes(coff.bytes())
        paths.append(folder / "objects" / "aliases.obj")
    return {"paths": paths, "changed": changed, "placed": placed, "skipped": skipped, "where": where_of, "image": image}


def link(program: dict, source: Path, objects: Path, ml: list[str], linker: list[str], out: Path) -> dict:
    """The program linked by Visual C++'s LINK.EXE from its source's objects (prepare), as tools/relink.py links a
    project's: a function or global the source makes longer or shorter moves everything after it, and what points at
    it follows. The header is the linker's, set as your copy's is, with its import directories and what follows its
    last section (relink.py's finish). Says which pieces changed size."""
    relink = _relink()
    folder = out.parent
    made = prepare(program, source, objects, ml, folder)
    paths, changed, placed, image = made["paths"], made["changed"], made["placed"], made["image"]
    entry = program.get("entry")
    if entry is None and image.entry:  # (a source written before program.json named it: the public name where the
        # program starts; a DLL may have none, /NOENTRY)
        names = public_names(program, placed)
        entry = next((n for n, a in names.items() if a == image.base + image.entry and not n.startswith("_D_")), None)
        if entry is None:
            sys.exit("assemble: no name in the source is where the program starts")
    out.unlink(missing_ok=True)
    rel = [os.path.relpath(p, folder) for p in paths]  # (relative: LINK.EXE takes an absolute path off Windows for
    # an option)
    # (each program's map and command its own: ninja links the .exe and a DLL beside it at once, into one folder,
    # and a DLL that read the .exe's map put its directories at the .exe's addresses)
    linked_map = f"{out.name}.map"
    argv = [*linker, *relink.link_options(image, entry, Path(linked_map), Path(out.name)), *rel]
    (folder / f"{out.name}.link.txt").write_text(" ".join(argv[len(linker):]) + "\n", encoding="utf-8")  # (to run
    # it again)
    said = subprocess.run(argv, capture_output=True, text=True, errors="replace", cwd=folder)
    output = (said.stdout + said.stderr).strip()
    if said.returncode != 0 or not out.is_file():
        sys.exit(f"assemble: the linker stopped:\n{output}")
    ends = max(s["raw_at"] + s["raw_size"] for s in program["sections"])
    relink.finish(out, image, relink.read_map(folder / linked_map), (source / "overlay.bin").read_bytes(), ends)
    out.write_bytes(home(program, out.read_bytes()))
    return {"program": out, "changed": changed, "linker": output}


def differing(game: bytes, linked: bytes) -> list[str]:
    """The sections of the game's program that the linked one hasn't byte for byte at their addresses (its base
    relocations count as the same when they name the same words: the linker writes them in blocks of its own)."""
    relink = _relink()
    old, new = relink.Image(game), relink.Image(linked)
    out = []
    for s in old.sections:
        same = any(n["name"] == s["name"] and n["addr"] == s["addr"] for n in new.sections) and \
            new.read(s["addr"], s["vsize"]) == old.read(s["addr"], s["vsize"])
        if not same and not (s["name"] == ".reloc" and old.relocated() is not None
                             and new.relocated() == old.relocated()):
            out.append(s["name"])
    return out + (["(the number of sections)"] if len(new.sections) != len(old.sections) else [])


def main() -> None:
    parser = argparse.ArgumentParser(description="Makes the game's program from its source")
    parser.add_argument("program", help="the source's program.json")
    parser.add_argument("objects", help="where the assembled objects go")
    parser.add_argument("--ml", required=True, help="Visual C++ 6.0's MASM, ml.exe")
    parser.add_argument("--wrapper", default="", help="what runs it (wibo, off Windows)")
    parser.add_argument("--out", default="", help="where the program goes (default: where functions.json has it; "
                        "with --link, relink-source/ beside OBJECTS)")
    parser.add_argument("--link", default=None, help="link it with Visual C++'s LINK.EXE instead, so source you edited "
                        "may make a function or global longer or shorter: everything after it moves")
    args = parser.parse_args()
    path = Path(args.program)
    program = json.loads(path.read_text(encoding="utf-8"))
    wrapper = [args.wrapper] if args.wrapper else []
    if args.link == "":  # (configure.py found no linker)
        sys.exit("assemble: it links with Visual C++ 6.0's linker: install Visual C++ 6.0 in decompdecomp's Setup "
                 "(Compilers & tools), then run tools/configure.py again")
    if args.link:
        out = Path(args.out) if args.out else Path(args.objects).parent / "relink-source" / Path(program["exe"]).name
        made = link(program, path.parent, Path(args.objects), [*wrapper, args.ml], [*wrapper, args.link], out)
        print(f"{out}: linked by LINK.EXE from the source ({len(program['pieces'])} files)")
        if made["changed"]:
            print(f"  {len(made['changed'])} files changed size, and what follows them moved: "
                  + ", ".join(made["changed"][:8]) + ("…" if len(made["changed"]) > 8 else ""))
        elif Path(program["exe"]).exists():
            differ = differing(Path(program["exe"]).read_bytes(), out.read_bytes())
            print("  every section byte for byte your copy's (its header is the linker's)" if not differ else
                  f"  these sections differ from your copy's: {', '.join(differ)}")
        return
    exe = assemble(program, path.parent, Path(args.objects), [*wrapper, args.ml])
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
