"""A V.Flash game from the user's own files: its firmware (FA) and its game modules, out of a disc image, a folder of
the disc's files, or the files themselves. Standard library only.

A V.Flash game is one FA, the game's own copy of the system firmware (kernel, drivers, C/C++ runtime, libraries, the
3D engine and a thin game layer; a `vfF0` executable, about 1.5 MB), and the game modules (`vfD0` executables) that
hold most of the game. FA stays resident; the modules are overlays, loaded one at a time into addresses they share,
and they call FA by absolute address, with no import table. Each module carries FA's build id (its FAPP_CRC), and FA
refuses one that doesn't match: a module is only ever analysed against its own game's FA.

Disc layouts (plain ISO 9660, no Joliet or Rock Ridge):
- every game: `0SYSTEM\\BOOT.BIN` is the vboot loader (0xC014 bytes) then FA; the modules are plain `*.VFF` files, in
  folders whose names vary from game to game (`APP01\\A01.VFF`, `OPENING\\OPENING.VFF`), so they're told by their
  header; `T*.VFF` files holding `///dummy` are placeholders. `0SYSTEM\\FA.VFF`, where there is one, is a copy of
  the FA in BOOT.BIN.
- one game keeps its modules inside `OUTPUT.BIN`, a pack of files, each in a zlib-compressed container.

The formats:
- VFF (little endian): +0 magic, +4 FAPP_CRC (build id), +0x10 BSS start, +0x14 BSS size, +0x18/+0x1C the C++
  static constructors' table (start, end), +0x20 the entry (vfD0) or the vector block's file offset (vfF0), +0x24
  the vector block's destination, +0x28 its size, +0x2C how many regions, +0x30 the regions {address, size, 0, 0}.
  The regions' bytes follow each other from the file's start, so region 0 starts with the header.
- BOOT.BIN: "BOOT", its size, its load address, its entry offset; FA at 0xC014.
- OUTPUT.BIN: u32 where the table ends, then {u32 sector (2048 bytes), u32 size, u32 name length, name} until
  there; names are the disc's (`\\DAPP\\GZ1A.VFF;1`) and padding.
- the compressed container: blocks of 0x4000 bytes, 0x3FF0 of payload and a trailer {0, 0, block number,
  crc32(payload)}; the payload starts {u32 size, u32 kind (0x1111 zlib, 0 stored), u32 0x12345678, u32 0}.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

SECTOR = 2048
RAW_SECTOR = 2352
SYNC = b"\x00" + b"\xff" * 10 + b"\x00"  # a raw sector's first 12 bytes
RAW_MODE_AT, MODE1_DATA_AT, MODE2_DATA_AT = 15, 16, 24  # in a raw sector: its mode, where mode 1's and mode 2 form 1's data start
PVD_SECTOR = 16  # the ISO 9660 primary volume descriptor
VOLUME_ID = slice(40, 72)
ROOT_RECORD = slice(156, 190)
DIR_FLAG = 2
BOOT_FA_OFFSET = 0xC014
FA_MAGIC, MODULE_MAGIC = b"vfF0", b"vfD0"
VFF_HEADER_WORDS = 12
REGIONS_AT, REGION_BYTES = 0x30, 16
MIN_VFF_BYTES = 0x40  # smaller "VFF" files are placeholders (`///dummy`)
RESET_VECTOR = bytes.fromhex("18f09fe5")  # ldr pc, [pc, #0x18]: the vector block's reset slot, FA's start address 0x20 on
CONTAINER_MAGIC = 0x12345678
CONTAINER_BLOCK, CONTAINER_PAYLOAD = 0x4000, 0x3FF0
ZLIB_KIND = 0x1111
FA_NAME = "FA"
ROOT_MARKS = (b"\x070SYSTEM", b"0ID_")  # what a V.Flash disc's root directory holds (records: name length, name)
# ELF, as tools/delink.py and Ghidra read the images: one PT_LOAD per region, then the BSS
ELF_DATA_ALIGN = 0x1000
EM_ARM, ET_EXEC, PT_LOAD = 40, 2, 1
EF_ARM_EABI_VER5 = 0x05000000


class DiscError(ValueError):
    """What the user picked isn't (all of) a V.Flash game: says what to pick instead."""


# ---------------------------------------------------------------------------------------------------- executables


@dataclass
class Image:
    """One V.Flash executable (VFF): FA (`vfF0`) or a game module (`vfD0`)."""
    name: str  # FA_NAME, or the module's file name without .VFF ("GZ1A")
    kind: str  # "vfF0" | "vfD0"
    build: int  # FAPP_CRC: FA's build id, which each of its modules carries
    entry: int
    bss_start: int
    bss_size: int
    init_start: int  # the C++ static constructors' pointer table (ends with a NULL)
    init_end: int
    regions: list[tuple[int, bytes]] = field(default_factory=list)  # (address, bytes); region 0 starts with the header
    source: str = ""  # where it came from: "0SYSTEM\\BOOT.BIN", "OUTPUT.BIN:DAPP\\GZ1A.VFF"
    vff: bytes = b""  # the file as the disc has it (decompressed), what says which game it is

    @property
    def is_fa(self) -> bool:
        return self.kind == FA_MAGIC.decode()

    def contains(self, addr: int) -> bool:
        """Whether an address is one of its regions or its BSS."""
        return any(a <= addr < a + len(d) for a, d in self.regions if d) or \
            self.bss_start <= addr < self.bss_start + self.bss_size

    def read(self, addr: int, n: int) -> bytes:
        for a, d in self.regions:
            if a <= addr < a + len(d):
                return d[addr - a:addr - a + n]
        return b""

    def to_elf(self) -> bytes:
        """An ARM ELF executable with one PT_LOAD per region and one for the BSS, data from 0x1000 on: what Ghidra
        analyses and tools/delink.py cuts functions out of (the same layout as the matching research's ELFs)."""
        loads = [(a, d, len(d), 7) for a, d in self.regions if d]
        if self.bss_size:
            loads.append((self.bss_start, b"", self.bss_size, 6))
        at = (52 + 32 * len(loads) + ELF_DATA_ALIGN - 1) & ~(ELF_DATA_ALIGN - 1)
        body, table = bytearray(), bytearray()
        for addr, data, memsz, flags in loads:
            table += struct.pack("<8I", PT_LOAD, at + len(body) if data else 0, addr, addr, len(data), memsz, flags, 4)
            body += data
            body += bytes(-len(body) % 4)
        head = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack("<HHIIIIIHHHHHH", ET_EXEC, EM_ARM, 1, self.entry, 52, 0,
                                                              EF_ARM_EABI_VER5, 52, 32, len(loads), 40, 0, 0)
        out = bytearray(head + table)
        out += bytes(at - len(out))
        return bytes(out + body)


def parse_vff(data: bytes, name: str = "", source: str = "") -> Image:
    if data[:4] not in (FA_MAGIC, MODULE_MAGIC):
        raise DiscError(f"{name or 'the file'} isn't a V.Flash executable (VFF)")
    w = struct.unpack_from(f"<{VFF_HEADER_WORDS}I", data, 0)
    regions, at = [], 0
    for i in range(w[11]):
        addr, size = struct.unpack_from("<2I", data, REGIONS_AT + REGION_BYTES * i)
        regions.append((addr, data[at:at + size]))
        at += size
    kind, entry = data[:4].decode(), w[8]
    if data[:4] == FA_MAGIC:
        # the vector block vboot copies (+0x20 file offset, +0x24 destination, +0x28 size): its reset slot's
        # `ldr pc, [pc, #0x18]` reads FA's start address
        vectors = data[w[8]:w[8] + w[10]]
        i = vectors.find(RESET_VECTOR)
        entry = struct.unpack_from("<I", vectors, i + 0x20)[0] if i >= 0 else regions[0][0]
    return Image(name, kind, w[1], entry, w[4], w[5], w[6], w[7], regions, source, bytes(data[:at]))


def is_container(data: bytes) -> bool:
    return len(data) >= 16 and struct.unpack_from("<I", data, 8)[0] == CONTAINER_MAGIC


def unpack_container(data: bytes) -> bytes:
    stream = bytearray()
    for index, at in enumerate(range(0, len(data), CONTAINER_BLOCK)):
        payload, trailer = data[at:at + CONTAINER_PAYLOAD], data[at + CONTAINER_PAYLOAD:at + CONTAINER_BLOCK]
        if len(trailer) == 16:
            _, _, block, crc = struct.unpack("<4I", trailer)
            if block != index or crc != zlib.crc32(payload):
                raise DiscError(f"a compressed file's block {index} is damaged: dump the disc again")
        stream += payload
    size, kind, magic, _ = struct.unpack_from("<4I", stream, 0)
    out = zlib.decompress(bytes(stream[16:])) if kind == ZLIB_KIND else bytes(stream[16:16 + size])
    if magic != CONTAINER_MAGIC or len(out) != size:
        raise DiscError("a compressed file's header is damaged: dump the disc again")
    return out


def output_bin_entries(data: bytes):
    """(name, bytes) of every file in an OUTPUT.BIN pack."""
    end = struct.unpack_from("<I", data, 0)[0]
    at = 4
    while at < end:
        sector, size, n = struct.unpack_from("<3I", data, at)
        name = data[at + 12:at + 12 + n].decode("latin-1").split(";")[0].strip("\\\x00")
        at += 12 + n
        yield name, data[sector * SECTOR:sector * SECTOR + size]


def looks_like_output_bin(data: bytes) -> bool:
    if len(data) < 16:
        return False
    end, _, _, n = struct.unpack_from("<4I", data, 0)
    name = data[16:16 + n]
    return 16 < end <= len(data) and 0 < n < 256 and name.lstrip(b"\\").split(b";")[0].isascii() and b";1" in name


# ---------------------------------------------------------------------------------------------------- file systems


class DirFS:
    """A folder holding the disc's files."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.label = self.root.name

    def files(self):
        for dirpath, _, names in os.walk(self.root):
            for n in names:
                p = Path(dirpath) / n
                yield p.relative_to(self.root).as_posix().replace("/", "\\"), p.stat().st_size

    def dirs(self):
        for dirpath, names, _ in os.walk(self.root):
            for n in names:
                yield (Path(dirpath) / n).relative_to(self.root).as_posix().replace("/", "\\")

    def read(self, path: str, length: int | None = None) -> bytes:
        with open(self.root.joinpath(*path.split("\\")), "rb") as f:
            return f.read() if length is None else f.read(length)


class IsoFS:
    """ISO 9660 from an image of 2048-byte sectors (.iso) or raw 2352-byte ones (.bin: mode 1, or mode 2 form 1)."""

    def __init__(self, path: Path):
        self.f = open(path, "rb")
        head = self.f.read(16)
        self.raw = head[:12] == SYNC
        pvd = self.sector(PVD_SECTOR)
        if pvd[1:6] != b"CD001":
            raise DiscError(f"{Path(path).name} isn't a disc image (it has no ISO 9660 file system)")
        self.label = pvd[VOLUME_ID].decode("latin-1").strip()
        self.entries: dict[str, tuple[int, int, bool]] = {}  # path -> (sector, size, is a folder)
        root = pvd[ROOT_RECORD]
        self._walk(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "", set())

    def close(self) -> None:
        self.f.close()

    def sector(self, lba: int) -> bytes:
        if not self.raw:
            self.f.seek(lba * SECTOR)
            return self.f.read(SECTOR)
        self.f.seek(lba * RAW_SECTOR)
        s = self.f.read(RAW_SECTOR)
        at = MODE1_DATA_AT if len(s) > RAW_MODE_AT and s[RAW_MODE_AT] == 1 else MODE2_DATA_AT
        return s[at:at + SECTOR]

    def _walk(self, lba: int, size: int, prefix: str, seen: set[int]) -> None:
        if lba in seen:  # (a damaged image's folder that holds itself)
            return
        seen.add(lba)
        for i in range((size + SECTOR - 1) // SECTOR):
            s = self.sector(lba + i)
            at = 0
            while at < len(s) and s[at]:
                rec = s[at:at + s[at]]
                at += s[at]
                if len(rec) < 34:
                    break
                extent, length, flags, n = struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0], rec[25], rec[32]
                name = rec[33:33 + n]
                if name in (b"\x00", b"\x01"):  # (the folder itself, its parent)
                    continue
                path = prefix + name.decode("latin-1").split(";")[0]
                self.entries[path] = (extent, length, bool(flags & DIR_FLAG))
                if flags & DIR_FLAG:
                    self._walk(extent, length, path + "\\", seen)

    def files(self):
        return ((p, e[1]) for p, e in self.entries.items() if not e[2])

    def dirs(self):
        return (p for p, e in self.entries.items() if e[2])

    def read(self, path: str, length: int | None = None) -> bytes:
        lba, size, _ = self.entries[path]
        size = size if length is None else min(size, length)
        if not self.raw:
            self.f.seek(lba * SECTOR)
            return self.f.read(size)
        out = bytearray()
        while len(out) < size:
            out += self.sector(lba)
            lba += 1
        return bytes(out[:size])


def cue_data_file(cue: Path) -> Path:
    """The .bin file of a .cue's data track (a V.Flash disc's only track)."""
    current = None
    for line in cue.read_text(encoding="latin-1").splitlines():
        m = re.match(r'\s*FILE\s+"?(.+?)"?\s+BINARY', line, re.I)
        if m:
            current = cue.parent / m.group(1)
        if current and re.match(r"\s*TRACK\s+\d+\s+(MODE1|MODE2)/(2048|2352)", line, re.I):
            if not current.is_file():
                raise DiscError(f"{cue.name} names {current.name}, which isn't next to it")
            return current
    raise DiscError(f"{cue.name} has no data track")


# ---------------------------------------------------------------------------------------------------- games


@dataclass
class Game:
    label: str = ""  # the disc's volume id, or the file's or folder's name
    product: str = ""  # from the disc's 0ID_<product>_<revision> folder: "93160_000"
    fa: Image | None = None
    modules: list[Image] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # what's missing or doesn't belong

    def images(self) -> list[Image]:
        return ([self.fa] if self.fa else []) + self.modules

    def sha1(self) -> str:
        """Which game this is: its FA and modules (not the disc's movies and padding, which a re-dump may lay out
        otherwise)."""
        h = hashlib.sha1()
        for img in sorted(self.images(), key=lambda i: (not i.is_fa, i.name)):
            h.update(img.name.encode() + b"\0" + hashlib.sha1(img.vff).digest())
        return h.hexdigest()


def _find(fs, path: str) -> str | None:
    want = path.upper()
    return next((p for p, _ in fs.files() if p.upper() == want), None)


def module_name(path: str) -> str:
    """A module's name from its file: its file name without .VFF, letters and digits only ("GZ1A")."""
    return re.sub(r"[^A-Za-z0-9]", "", path.replace("/", "\\").split("\\")[-1].rsplit(".", 1)[0]).upper() or "MODULE"


def _add_module(g: Game, name: str, data: bytes, source: str) -> None:
    """A module, unless it's a copy of one the game has already (a disc kept the same module in two folders)."""
    if is_container(data):
        data = unpack_container(data)
    if data[:4] != MODULE_MAGIC:
        return
    img = parse_vff(data, name, source)
    if any(m.vff == img.vff for m in g.modules):
        return
    if any(m.name == name for m in g.modules):  # (another folder's module of the same name: its folder tells them apart)
        folder = source.split(":")[-1].replace("/", "\\").rsplit("\\", 2)
        img.name = module_name(folder[-2]) + name if len(folder) > 1 else name
        while any(m.name == img.name for m in g.modules):
            img.name += "X"
    g.modules.append(img)


def load_fs(fs) -> Game:
    g = Game(label=fs.label)
    for d in fs.dirs():
        if (m := re.fullmatch(r"0ID_(\d+(?:_\d+)?)", d.split("\\")[-1], re.I)):
            g.product = m.group(1)
    boot, fa_file = _find(fs, "0SYSTEM\\BOOT.BIN"), _find(fs, "0SYSTEM\\FA.VFF")
    if boot:
        data = fs.read(boot)
        if data[BOOT_FA_OFFSET:BOOT_FA_OFFSET + 4] == FA_MAGIC:
            g.fa = parse_vff(data[BOOT_FA_OFFSET:], FA_NAME, boot)
    if g.fa is None and fa_file:
        g.fa = parse_vff(fs.read(fa_file), FA_NAME, fa_file)
    for path, size in sorted(fs.files()):
        upper = path.upper()
        if upper.endswith(".VFF") and upper != "0SYSTEM\\FA.VFF" and size >= MIN_VFF_BYTES:
            _add_module(g, module_name(path), fs.read(path), path)
        elif upper.split("\\")[-1] == "OUTPUT.BIN":
            for name, blob in output_bin_entries(fs.read(path)):
                if name.upper().endswith(".VFF"):
                    _add_module(g, module_name(name), blob, f"{path}:{name}")
    return g


def is_disc_image(head: bytes) -> bool:
    return head[0x8001:0x8006] == b"CD001" or (head[:12] == SYNC and b"CD001" in head[:0x10000])


def load(path: Path) -> Game:
    """The game in one input: a disc image (.iso, .bin, .cue), a folder of the disc's files, or one of its files:
    0SYSTEM\\BOOT.BIN (or FA.VFF), a module .VFF, OUTPUT.BIN. A BOOT.BIN or FA.VFF in its disc's folder brings the
    whole folder: the game is all of it."""
    path = Path(path)
    if path.is_dir():
        return load_fs(DirFS(path))
    if path.suffix.lower() == ".cue":
        path = cue_data_file(path)
    with open(path, "rb") as f:
        head = f.read(0x10000)
    if is_disc_image(head):
        fs = IsoFS(path)
        try:
            g = load_fs(fs)
        finally:
            fs.close()
        g.label = g.label or path.stem
        return g
    if path.name.upper() in ("BOOT.BIN", "FA.VFF") and path.parent.name.upper() == "0SYSTEM":
        return load(path.parent.parent)
    data = path.read_bytes()
    g = Game(label=path.stem)
    if data[:4] == b"BOOT" and data[BOOT_FA_OFFSET:BOOT_FA_OFFSET + 4] == FA_MAGIC:
        g.fa = parse_vff(data[BOOT_FA_OFFSET:], FA_NAME, path.name)
    elif data[:4] == FA_MAGIC:
        g.fa = parse_vff(data, FA_NAME, path.name)
    elif data[:4] == MODULE_MAGIC or is_container(data):
        _add_module(g, module_name(path.name), data, path.name)
    elif looks_like_output_bin(data):
        for name, blob in output_bin_entries(data):
            if name.upper().endswith(".VFF"):
                _add_module(g, module_name(name), blob, f"{path.name}:{name}")
    else:
        raise DiscError(f"{path.name} isn't a V.Flash disc image, the disc's folder, its BOOT.BIN or FA.VFF, a game "
                        "module (.VFF) or OUTPUT.BIN")
    return g


def check(g: Game) -> Game:
    """What the game lacks, in its notes: FA is needed to analyse any module (they call into it), and the modules
    hold most of the game. A module of another game or revision (its build id isn't FA's) is left out."""
    if g.fa is None:
        g.notes.append("no FA (0SYSTEM\\BOOT.BIN or FA.VFF): the modules call into it, so they can't be analysed without it")
    if not g.modules:
        g.notes.append("no game modules (the *.VFF files; on some discs OUTPUT.BIN): FA alone is the firmware and engine, "
                       "the modules hold most of the game")
    if g.fa:
        others = [m for m in g.modules if m.build != g.fa.build]
        for m in others:
            g.notes.append(f"{m.name} belongs to another game or revision (its build id {m.build:#010x} isn't FA's "
                           f"{g.fa.build:#010x}): left out")
        g.modules = [m for m in g.modules if m.build == g.fa.build]
    return g


def is_vflash(head: bytes, path: Path | None = None) -> bool:
    """A V.Flash game's file, from its first bytes (and, for a disc image on disk, its file system): a disc image
    whose root holds 0SYSTEM and a 0ID_ folder, BOOT.BIN (vboot, then FA), or a VFF executable."""
    if head[:4] == b"BOOT" and head[BOOT_FA_OFFSET:BOOT_FA_OFFSET + 4] == FA_MAGIC:
        return True
    if head[:4] in (FA_MAGIC, MODULE_MAGIC):
        return len(head) >= REGIONS_AT and 0 < struct.unpack_from("<I", head, 0x2C)[0] < 16
    if not is_disc_image(head) or not all(mark in head for mark in ROOT_MARKS):
        return False
    if path is None:
        return True
    try:
        fs = IsoFS(path)
    except (OSError, DiscError, struct.error):
        return False
    try:
        boot = _find(fs, "0SYSTEM\\BOOT.BIN")
        return bool(boot) and fs.read(boot, BOOT_FA_OFFSET + 4)[BOOT_FA_OFFSET:] == FA_MAGIC
    finally:
        fs.close()
