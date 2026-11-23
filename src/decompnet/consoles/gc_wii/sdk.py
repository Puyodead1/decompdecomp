"""Nintendo's SDK (Dolphin, Revolution) and CodeWarrior's libraries found by their code: the signatures decomp-toolkit
carries for its own analysis, read from the dtk decompdecomp installs (toolchains.toml pins its version and checksum),
as the library finder's signatures (Console.library_signatures).

dtk finds a few functions of a stripped game with them (__start, __init_data, OSInit, TRK_main ...) to start its
analysis from; it keeps them in its program as the YAML files of its source (assets/signatures/*.yml), one entry per
function: its code as (instruction, mask) pairs, the mask clearing what a relocation fills in, the symbols its
relocations name, and those relocations. Nothing of them is copied here or in the projects: they're read from the
installed dtk each time the app runs, so they're always the pinned version's (MIT OR Apache-2.0, as dtk is).

A function of the game is the SDK's when its whole code matches an entry's under the mask and its relocations are
the ones the entry has, at the same places: an entry for a short or mostly masked function (a wrapper that only calls
another, li/blr) says too little, and is left out (SHORTEST, FEWEST_BITS). Each entry goes to the library its name
says (libraries.toml's names: CodeWarrior's runtime, MSL, MetroTRK), the rest to Nintendo's SDK.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
from pathlib import Path

SHORTEST = 32  # bytes of code an entry must cover
FEWEST_BITS = 256  # bits of it its mask must keep
ENTRY = b"- symbol: "
# dtk's relocation kinds -> (the ELF type the game's objects have, where it is from the instruction: the 16-bit ones
# fill the instruction's second halfword, which is where an ELF relocation of that type points)
RELOCATIONS = {"Absolute": (1, 0), "PpcAddr16Lo": (4, 2), "PpcAddr16Hi": (5, 2), "PpcAddr16Ha": (6, 2),
               "PpcRel24": (10, 0), "PpcRel14": (11, 0), "PpcEmbSda21": (109, 0)}
SDK = "dolphin-sdk"  # libraries.toml's entry for what no other library's names take


def signatures(libraries: list) -> list:
    """The installed dtk's signatures as libid.Signature, each its library's (`libraries`: the console's catalog);
    [] without dtk, or from a dtk they can't be read from."""
    from ... import toolchains

    try:
        if toolchains.installed("dtk") is None:
            return []
        path = toolchains.binary("dtk")
        st = path.stat()
    except (OSError, toolchains.ToolchainError):
        return []
    owners = tuple((lib.id, tuple(lib.names), tuple(lib.companion_names)) for lib in libraries)
    return list(_signatures(str(path), st.st_size, st.st_mtime_ns, toolchains.get("dtk").source or "dtk", owners))


@functools.lru_cache(maxsize=4)
def _signatures(path: str, size: int, mtime_ns: int, source: str, owners: tuple) -> tuple:
    from ... import libid
    from ...arch import reloc_masks

    masks = reloc_masks()
    try:
        data = Path(path).read_bytes()
    except OSError:
        return ()
    out = []
    for name, (pattern, bits), relocs in read_entries(data):
        if len(pattern) < SHORTEST or sum(bin(b).count("1") for b in bits) < FEWEST_BITS:
            continue
        wild: set[int] = set()
        for offset, kind in relocs:
            elf, delta = RELOCATIONS[kind]
            at, length, _ = masks.get(("ppc", elf), (0, 4, 0))
            wild.update(range(offset + delta + at, offset + delta + at + length))
        out.append(libid.Signature(_owner(name, owners), "", name, len(pattern), pattern,
                                   bytes(1 if b else 0 for b in bits), origin=f"{source}'s signatures",
                                   bits=bits, wild=frozenset(wild)))
    return tuple(out)


def _owner(name: str, owners: tuple) -> str:
    """The library a function so named is: one whose own names have it, else one whose companions do, else the SDK."""
    for which in (1, 2):
        for owner in owners:
            if any(rx.fullmatch(name) for rx in owner[which]):
                return owner[0]
    return SDK


def read_entries(data: bytes) -> list[tuple[str, tuple[bytes, bytes], list[tuple[int, str]]]]:
    """Every whole entry of the signature files in `data` (dtk's program): (the function's name, (its code, the bit
    mask of what's fixed), [(relocation's offset, kind)]). An entry whose code isn't the hash it gives, or whose
    relocations name a kind not known here, is left out. The files follow one another without a newline between
    them, so an entry starts at its "- symbol: " wherever that is."""
    out = []
    starts = []
    at = data.find(ENTRY)
    while at >= 0:
        starts.append(at)
        at = data.find(ENTRY, at + len(ENTRY))
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else min(len(data), start + (1 << 16))
        entry = _entry(data[start + len(ENTRY):end].decode("latin-1").splitlines())
        if entry is not None:
            out.append(entry)
    return out


def _entry(lines: list[str]):
    """One entry's lines (after "- symbol: "), or None."""
    fields: dict[str, str] = {}
    symbols: list[dict] = []
    relocs: list[dict] = []
    part, item = None, None
    try:
        fields["symbol"] = lines[0].strip()
        for line in lines[1:]:
            if line.startswith("  - "):  # a new item of the list it's in
                item = {}
                (symbols if part == "symbols" else relocs if part == "relocations" else []).append(item)
                line = "    " + line[4:]
            if line.startswith("    ") and item is not None and ": " in line:
                key, value = line.strip().split(": ", 1)
                item[key] = value
            elif line.startswith("  ") and not line.startswith("   ") and ":" in line:
                key, _, value = line.strip().partition(":")
                part, item = key, None
                fields[key] = value.strip()
            else:
                break  # (the end of the file it's the last entry of)
        which = int(fields["symbol"])
        code = base64.b64decode(fields["signature"] + "=" * (-len(fields["signature"]) % 4), validate=True)
        symbol = symbols[which]
        size = int(symbol["size"])
    except (KeyError, IndexError, ValueError, binascii.Error):
        return None
    if hashlib.sha1(code).hexdigest() != fields.get("hash") or len(code) != size * 2 or size % 4:
        return None
    pattern = b"".join(code[k:k + 4] for k in range(0, len(code), 8))
    bits = b"".join(code[k + 4:k + 8] for k in range(0, len(code), 8))
    try:
        found = [(int(r["offset"]), r["kind"]) for r in relocs]
    except (KeyError, ValueError):
        return None
    if any(kind not in RELOCATIONS for _, kind in found):
        return None
    return symbol["name"].strip("'\""), (pattern, bits), found
