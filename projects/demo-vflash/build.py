"""Build Demo Quest V.Flash, a V.Flash disc image made only from code we may share: the same Demo Quest game as the
N64 demo (CC0, ../demo-n64/original) with a main loop (vfmain.c) and start-up (crt0.s) as the firmware, FA, and a
game module (module.c) that calls FA's functions by their address, compiled with GCC 3.2.3 for ARM and the flags
V.Flash games were built with, linked by binutils 2.14's ld, and laid out as a V.Flash disc: 0SYSTEM\\BOOT.BIN (a
loader's place, then FA), APP01\\A01.VFF (the module) and the 0ID_<product>_<revision> folder, in an ISO 9660 image.

    uv run python projects/demo-vflash/build.py    ->  build/demoquest.iso (+ build/demo.json for
                                                       tests/test_consoles.py)
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

from decompnet import toolchains

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"
GAME = HERE.parent / "demo-n64" / "original"
CFLAGS = ["-O3", "-mcpu=arm9tdmi", "-fomit-frame-pointer", "-mno-apcs-frame", "-msoft-float"]
FA_AT, MODULE_AT = 0x10A00000, 0x10400000  # each program's first region, which starts with its header
HEADER_BYTES = 0x100
BUILD_ID = 0x5EED1234  # FAPP_CRC: the firmware's build id, which its module repeats
VECTORS_AT, VECTORS_TO = 0x40, 0x1000FF00  # FA's vector block: where it is in the file, where the loader copies it
LDR_PC = 0xE59FF018  # ldr pc, [pc, #0x18]: each vector reads its address 0x20 on
BOOT_LOAD, BOOT_FA = 0x10C00000, 0xC014
PRODUCT = "99000_000"
SECTOR = 2048


def run(argv, cwd=BUILD):
    res = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=cwd)
    if res.returncode != 0:
        sys.exit(f"failed: {' '.join(map(str, argv))}\n{res.stdout}{res.stderr}")
    return res.stdout


LINK = """ENTRY({entry})
SECTIONS {{
  . = 0x{start:08X};
  .text : {{ *(.text*) *(.rodata*) *(.glue_7*) }}
  .data : {{ *(.data*) }}
  . = ALIGN(4);
  __bss_start = .;
  .bss : {{ *(.bss*) *(COMMON) }}
  . = ALIGN(4);
  __bss_end = .;
}}
"""


def link(name: str, objs: list[str], start: int, entry: str, extra: list[str] = ()) -> Path:
    (BUILD / f"{name}.ld").write_text(LINK.format(entry=entry, start=start + HEADER_BYTES), encoding="utf-8")
    out = BUILD / f"{name}.elf"
    run([toolchains.path("gcc-3.2.3-arm-elf") / "bin" / "arm-elf-ld", "-T", f"{name}.ld", *extra, "-o", out.name, *objs])
    return out


def vff(elf: Path, kind: bytes, start: int) -> tuple[bytes, dict[str, int]]:
    """The VFF executable of a linked program: its header, then its code and data, one region from `start`."""
    e = ELFFile(open(elf, "rb"))
    image = bytearray()
    bss = [0, 0]
    for s in e.iter_sections():
        if s.name in (".text", ".data") and s["sh_size"]:
            at = s["sh_addr"] - start - HEADER_BYTES
            image += bytes(at - len(image))
            image += s.data()
        elif s.name == ".bss":
            bss = [s["sh_addr"], s["sh_size"]]
    symbols = {sym.name: sym["st_value"] for sym in e.get_section_by_name(".symtab").iter_symbols()
               if sym["st_info"]["type"] == "STT_FUNC" or sym.name in ("_start",)}
    entry = e.header["e_entry"]
    head = bytearray(HEADER_BYTES)
    data = head + image
    data += bytes(-len(data) % 4)
    if not bss[1]:
        bss[0] = start + len(data)
    third = (VECTORS_AT, VECTORS_TO, 0x40) if kind == b"vfF0" else (entry, 0, 0)
    struct.pack_into("<4sI2I2I2I3II4I", data, 0, kind, BUILD_ID, 0, 0, bss[0], bss[1], 0, 0, *third, 1,
                     start, len(data), 0, 0)
    if kind == b"vfF0":
        struct.pack_into("<8I8I", data, VECTORS_AT, *([LDR_PC] * 8), *([entry] * 8))
    return bytes(data), symbols


# ---------------------------------------------------------------------------------------------------- ISO 9660


def _both16(n: int) -> bytes:
    return struct.pack("<H", n) + struct.pack(">H", n)


def _both32(n: int) -> bytes:
    return struct.pack("<I", n) + struct.pack(">I", n)


DATE = bytes([106, 10, 23, 12, 0, 0, 0])  # 2006-10-23


def _record(name: bytes, lba: int, size: int, folder: bool) -> bytes:
    rec = (bytes(2) + _both32(lba) + _both32(size) + DATE + bytes([2 if folder else 0, 0, 0]) + _both16(1)
           + bytes([len(name)]) + name)
    rec += bytes(len(rec) % 2)
    return bytes([len(rec)]) + rec[1:]


def iso(files: dict[str, bytes], folders: list[str], volume: str) -> bytes:
    """An ISO 9660 image (one level of folders, as V.Flash discs have) of `files` ("0SYSTEM/BOOT.BIN": bytes)."""
    names = sorted(folders)
    root_at, first_dir = 20, 21
    lba = {name: first_dir + i for i, name in enumerate(names)}
    next_lba = first_dir + len(names)
    placed = {}
    for path in sorted(files):
        placed[path] = next_lba
        next_lba += (len(files[path]) + SECTOR - 1) // SECTOR
    total = next_lba
    out = bytearray(total * SECTOR)

    def put(sector: int, data: bytes) -> None:
        out[sector * SECTOR:sector * SECTOR + len(data)] = data

    def directory(here: int, parent: int, entries: list[bytes]) -> bytes:
        return _record(b"\0", here, SECTOR, True) + _record(b"\1", parent, SECTOR, True) + b"".join(entries)
    root = [_record(n.encode(), lba[n], SECTOR, True) for n in names]
    put(root_at, directory(root_at, root_at, root))
    for n in names:
        inside = sorted(p for p in files if p.split("/")[0] == n)
        put(lba[n], directory(lba[n], root_at, [_record(p.split("/")[1].encode() + b";1", placed[p], len(files[p]), False)
                                                for p in inside]))
    for p, at in placed.items():
        put(at, files[p])
    table = bytearray()
    for endian in ("<", ">"):
        t = struct.pack(f"{endian}BBIH", 1, 0, root_at, 1) + b"\0\0"
        for n in names:
            entry = struct.pack(f"{endian}BBIH", len(n), 0, lba[n], 1) + n.encode()
            t += entry + bytes(len(n) % 2)
        table += t
        put(18 if endian == "<" else 19, t)
    pvd = bytearray(SECTOR)
    pvd[0:8] = b"\x01CD001\x01\x00"
    pvd[8:40] = b" " * 32
    pvd[40:72] = volume.encode().ljust(32)
    pvd[80:88] = _both32(total)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(SECTOR)
    pvd[132:140] = _both32(len(table) // 2)
    pvd[140:144] = struct.pack("<I", 18)
    pvd[148:152] = struct.pack(">I", 19)
    pvd[156:190] = _record(b"\0", root_at, SECTOR, True)
    pvd[190:813] = b" " * (813 - 190)
    pvd[813:881] = b"0" * 16 + b"\0" + b"0" * 16 + b"\0" + b"0" * 16 + b"\0" + b"0" * 16 + b"\0"
    pvd[881] = 1
    put(16, bytes(pvd))
    put(17, b"\xffCD001\x01")
    return bytes(out)


def main() -> None:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir()
    for src in (GAME / "game.c", GAME / "game.h", HERE / "vfmain.c", HERE / "module.c", HERE / "crt0.s"):
        shutil.copy(src, BUILD / src.name)
    gcc = toolchains.require("gcc-3.2.3-arm-elf") / "bin"
    for src in ("game.c", "vfmain.c", "module.c"):
        run([gcc / "arm-elf-gcc", "-c", *CFLAGS, "-I.", src])
    run([gcc / "arm-elf-as", "-o", "crt0.o", "crt0.s"])
    fa_elf = link("fa", ["crt0.o", "vfmain.o", "game.o"], FA_AT, "_start")
    fa, fa_symbols = vff(fa_elf, b"vfF0", FA_AT)
    # FA's functions at their addresses, as a module calls them (binutils 2.14's ld stops on -R, just its symbols)
    module_elf = link("a01", ["module.o"], MODULE_AT, "level_run",
                      [f"--defsym={name}=0x{addr:08X}" for name, addr in fa_symbols.items()])
    module, module_symbols = vff(module_elf, b"vfD0", MODULE_AT)
    boot = bytearray(BOOT_FA)
    struct.pack_into("<4sIII", boot, 0, b"BOOT", BOOT_FA + len(fa), BOOT_LOAD, 0x10)
    disc = iso({"0SYSTEM/BOOT.BIN": bytes(boot) + fa, "APP01/A01.VFF": module, f"0ID_{PRODUCT}/README.TXT": b"Demo Quest\n"},
               ["0SYSTEM", "APP01", f"0ID_{PRODUCT}"], PRODUCT)
    (BUILD / "demoquest.iso").write_bytes(disc)
    symbols = {**fa_symbols, **{f"A01:{k}": v for k, v in module_symbols.items() if k not in fa_symbols}}
    (BUILD / "demo.json").write_text(json.dumps({"game": "demoquest.iso", "symbols": symbols}, indent=1), encoding="utf-8")
    print(f"built build/demoquest.iso ({len(disc)} bytes)")


if __name__ == "__main__":
    main()
