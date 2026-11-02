"""The processors decompdecomp reads: one module each (mips.py, ppc.py, ppc64.py, x86.py, arm.py) with what depends on the
processor alone, whatever the console: the relocations a match ignores the bits of, how capstone disassembles it,
how to tell code no compiler makes, and which of decompdecomp's readers exist for it.

A console names its processor (consoles/: `arch = "mips"`). The shared code asks the processor here instead of
comparing names: a processor without a reader for a feature (the compiler map, say) leaves that feature out, so
the feature shows as missing on that console, not as an `if` somewhere in the engine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import arm, mips, mips_fields, ppc, ppc64, x86, x86_fields

# What decompdecomp's readers can do with a processor's code (each is a module of its own that reads MIPS, and some
# x86):
COMPILER_MAP = "compiler_map"  # which compiler built each part of a game, from its habits (compilermap.py)
CLASSES = "classes"  # C++ classes from the vtables constructors store (classes.py; x86: from field_accesses' facts)
BOUNDARIES = "boundaries"  # cutting a function where an agent says it really ends (engine/editing.py, rom/split.py)
STRUCTS = "structs"  # struct layouts from the loads and stores through pointers (structs.py, Arch.field_accesses)


@dataclass(frozen=True)
class Arch:
    id: str  # the name ELF objects and the projects table use: "mips", "ppc", "x86", "arm"
    name: str
    capstone: dict[bool, tuple[int, int]]  # big-endian? -> capstone's (architecture, mode)
    reloc_masks: dict[int, tuple[int, int, int]] = field(default_factory=dict)  # see elfobj.mask_relocs
    # why a function's code can't come from a compiler, or None: (code, big_endian, **the console's facts)
    asm_reason: Callable[..., str | None] | None = None
    # its asm_reason needs the console's facts (MIPS: which registers carry arguments depends on the console's ABI,
    # the PS2's EABI passes them in t0-t3 too), so code whose console isn't known (a fork's object) isn't judged
    asm_needs_console: bool = False
    features: frozenset[str] = frozenset()
    # what a function does with pointers, for structs.py: (vram, code, relocs, big_endian=, datum=) -> structs.Facts
    field_accesses: Callable[..., Any] | None = None
    # the float constants a diff row's instruction loads from data by address: text -> [(address, "f" | "d")], so
    # the diff can show their values (forkengine)
    float_operands: Callable[[str], list[tuple[int, str]]] | None = None
    # a decompiler's draft of a method shown as `Class::method`, with `this` (x86: Ghidra's, `this` in ecx):
    # (draft, function's address name, class, name, role, found from) -> the draft, or None (forkengine)
    method_draft: Callable[..., str | None] | None = None
    # variants of it capstone can't decode (Console.cpu_variant) -> their own reader: (code, big_endian) ->
    # [(offset, mnemonic, operands)], for scoring's diffs (MIPS: the PSP's Allegrex, read by rabbitizer)
    variants: dict[str, Callable[[bytes, bool], list[tuple[int, str, str]]]] = field(default_factory=dict)


ARCHES = [
    Arch("mips", "MIPS", mips.CAPSTONE, mips.RELOC_MASKS, mips.asm_reason, True,
         frozenset({COMPILER_MAP, CLASSES, BOUNDARIES, STRUCTS}), mips_fields.read_facts,
         variants={mips.ALLEGREX: mips.allegrex_lines}),
    Arch("ppc", "PowerPC", ppc.CAPSTONE, ppc.RELOC_MASKS, ppc.asm_reason),
    Arch("ppc64", "PowerPC64", ppc64.CAPSTONE, ppc64.RELOC_MASKS, ppc64.asm_reason, features=frozenset({BOUNDARIES})),
    Arch("x86", "x86", x86.CAPSTONE, x86.RELOC_MASKS, features=frozenset({CLASSES, STRUCTS}),
         field_accesses=x86_fields.read_facts, float_operands=x86.float_operands, method_draft=x86.method_draft),
    Arch("x86_64", "x86-64", x86.CAPSTONE_64, x86.RELOC_MASKS_64),
    Arch("arm", "ARM", arm.CAPSTONE, arm.RELOC_MASKS, arm.asm_reason, features=frozenset({BOUNDARIES})),
    Arch("thumb", "Thumb", arm.THUMB_CAPSTONE, arm.THUMB_RELOC_MASKS, arm.asm_reason,
         features=frozenset({BOUNDARIES})),
]
_BY_ID = {a.id: a for a in ARCHES}
UNKNOWN = Arch("", "an unknown processor", {})


def get(arch_id: str | None) -> Arch:
    """The processor by its id; one decompdecomp has no reader for (a public decomp's) has no features."""
    return _BY_ID.get(arch_id or "", UNKNOWN)


def reloc_masks() -> dict[tuple[str, int], tuple[int, int, int]]:
    """(arch, relocation type) -> (byte offset from r_offset, length, bitmask to clear), for every processor."""
    return {(a.id, kind): mask for a in ARCHES for kind, mask in a.reloc_masks.items()}


def capstone_modes() -> dict[tuple[str, bool], tuple[int, int]]:
    """(arch, big-endian) -> capstone's (architecture, mode), for every processor."""
    return {(a.id, big): mode for a in ARCHES for big, mode in a.capstone.items()}


PLAUSIBLE = (1e-6, 1e9)  # a value data probably means as a float: not a pointer's or a small integer's bits


def float_lines(data: bytes, big_endian: bool, shown: int = 8) -> list[str]:
    """read_data's lines on what the bytes are as floating point: 4-byte floats, and 8-byte doubles where those make
    sense (`00 00 00 00 00 00 59 40` is 100.0; shown only as floats it read as 0 and 3.4, and a model on a Linux game
    stopped to decode it with a command of its own, which its CLI ended the session for)."""
    import struct

    e = ">" if big_endian else "<"
    low, high = PLAUSIBLE
    out = []
    floats = [f for (f,) in struct.iter_unpack(e + "f", data[:len(data) // 4 * 4])][:shown]
    if any(low < abs(x) < high for x in floats):
        out.append("as f32: " + ", ".join(f"{x:g}" for x in floats))
    # doubles where the bytes make no sense as floats (a double's low half reads as a denormal or a huge float)
    # and do as doubles: every one zero or of a plausible size
    doubles = [d for (d,) in struct.iter_unpack(e + "d", data[:len(data) // 8 * 8])][:shown]
    nonsense = any(x != 0 and not low < abs(x) < high for x in floats)
    if doubles and nonsense and any(low < abs(x) < high for x in doubles) and \
            all(x == 0 or low < abs(x) < high for x in doubles):
        out.append("as f64 (double): " + ", ".join(f"{x:g}" for x in doubles))
    return out
