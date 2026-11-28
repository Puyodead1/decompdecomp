"""Why a file whose functions match may still not link, read from its object next to the original's before a build
tries it. A link is a whole build of the game and a checksum: a GameCube game's 8 files at 100% failed it for causes
objdiff's scores can't see, each found by hand (#ADDON 4-5):

- the file's own pooled constant declared `extern` (it links only against the original's object, which a linked
  file no longer has);
- a global the original's object defines that yours makes static or leaves out (other files use it), often data the
  split gave this file from another's (an SDK's version string, its globals);
- a data section longer than the split's: data that belongs to the next file, or padding arrays (`gap_...`) written
  to fill the layout;
- a function the original has and yours doesn't: an assembled function nothing calls, which MWCC drops unless the
  project's config lists it under `force_active:`.

`causes` says which, split into what certainly fails a link (the build isn't tried) and what may.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from . import datadiff
from .identity import _MADE_UP

_ALLOC, _EXEC = 0x2, 0x4


@dataclass
class Causes:
    certain: list[str] = field(default_factory=list)  # the link fails: not worth a build
    maybe: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.certain or self.maybe)

    def text(self) -> str:
        return "\n".join(f"- {line}" for line in [*self.certain, *self.maybe])


@dataclass(frozen=True)
class _Sym:
    name: str
    defined: bool
    bind: str
    kind: str
    section: str
    size: int


def _symbols(path: Path) -> tuple[dict[str, _Sym], dict[str, tuple[int, bytes | None]]]:
    """An object's named symbols (defined ones win over references), and its allocated data sections: (size,
    bytes)."""
    elf = ELFFile(BytesIO(Path(path).read_bytes()))
    secs = list(elf.iter_sections())
    out: dict[str, _Sym] = {}
    for symtab in (s for s in secs if isinstance(s, SymbolTableSection)):
        for sym in symtab.iter_symbols():
            kind = sym["st_info"]["type"]
            if not sym.name or kind in ("STT_SECTION", "STT_FILE"):
                continue
            shndx = sym["st_shndx"]
            defined = isinstance(shndx, int) and 0 < shndx < len(secs)
            if sym.name in out and out[sym.name].defined and not defined:
                continue
            out[sym.name] = _Sym(sym.name, defined, sym["st_info"]["bind"], kind,
                                 secs[shndx].name if defined else "", sym["st_size"])
    sections = {s.name: (s["sh_size"], None if s["sh_type"] == "SHT_NOBITS" else s.data()) for s in secs
                if s.name and s["sh_flags"] & _ALLOC and not s["sh_flags"] & _EXEC and s["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS")}
    return out, sections


def _some(names: list[str], most: int = 6) -> str:
    return ", ".join(names[:most]) + (f" and {len(names) - most} more" if len(names) > most else "")


def causes(target: Path, base: Path | None, source: str = "") -> Causes | None:
    """Why the object `base` (built from the file's C) may not link where the original's `target` did. `source` is
    the file's text, to tell a function that isn't written from one the compiler dropped. None: no verdict (an
    object isn't ELF, or yours isn't built)."""
    if base is None or not Path(base).exists() or not Path(target).exists():
        return None
    try:
        theirs, their_secs = _symbols(target)
        yours, your_secs = _symbols(base)
    except (OSError, ELFError, ValueError, IndexError, KeyError):
        return None
    out = Causes()
    real = {n: s for n, s in theirs.items() if not _MADE_UP.match(n)}

    # the file's own data, declared extern: undefined at link time, the original's object being gone
    own = sorted(n for n, s in real.items() if s.defined and s.kind != "STT_FUNC"
                 and n in yours and not yours[n].defined)
    if own:
        out.certain.append(f"it declares {_some(own)} extern, and the original defines {'it' if len(own) == 1 else 'them'} "
                           "in this very file: once linked, nothing does. Write the value (a literal, or a definition "
                           "in this file) instead; where a literal changes the code (the compiler folds `x * 0.0f`), "
                           "a local variable keeps it (`f32 zero = 0.0f;`)")

    # functions the original has and yours doesn't
    missing = sorted(n for n, s in real.items() if s.defined and s.kind == "STT_FUNC"
                     and not (n in yours and yours[n].defined))
    if missing:
        dropped = [n for n in missing if re.search(rf"\b{re.escape(n)}\b", source)]
        if dropped:
            out.certain.append(f"{_some(dropped)} {'is' if len(dropped) == 1 else 'are'} in the C but not in its "
                               "object: the compiler dropped what nothing calls (an asm function). The project's "
                               "config must keep it: `force_active:` in config/<version>/config.yml")
        if rest := [n for n in missing if n not in dropped]:
            out.certain.append(f"the original has {_some(rest)} and yours doesn't: write "
                               f"{'it' if len(rest) == 1 else 'them'}")

    # globals: the original's that yours makes static or leaves out, and yours the original doesn't have
    hidden = sorted(n for n, s in real.items() if s.defined and s.bind == "STB_GLOBAL" and s.kind != "STT_FUNC"
                    and n in yours and yours[n].defined and yours[n].bind == "STB_LOCAL")
    if hidden:
        out.maybe.append(f"{_some(hidden)} {'is' if len(hidden) == 1 else 'are'} global in the original and static in "
                         "yours: other files that use it won't find it")
    gone = sorted(n for n, s in real.items() if s.defined and s.bind == "STB_GLOBAL" and s.kind != "STT_FUNC"
                  and n not in yours)
    if gone:
        out.maybe.append(f"the original defines {_some(gone)} and yours doesn't mention "
                         f"{'it' if len(gone) == 1 else 'them'}: if {'it belongs' if len(gone) == 1 else 'they belong'} "
                         "to another file (an SDK's version string or globals, used only by its code), the split gave "
                         "it to this file by mistake; otherwise define it here")
    extra = sorted(n for n, s in yours.items() if s.defined and s.bind == "STB_GLOBAL" and not _MADE_UP.match(n)
                   and n not in theirs)
    if pads := [n for n in extra if n.startswith("gap_")]:
        out.maybe.append(f"{_some(pads)}: padding written to fill the layout makes it wrong; the split or an "
                         "alignment (`align:` in symbols.txt) is what to fix")
    if extra := [n for n in extra if not n.startswith("gap_")]:
        out.maybe.append(f"yours defines {_some(extra)}, which the original doesn't: another file may define "
                         f"{'it' if len(extra) == 1 else 'them'} too")

    # data sections longer than the split's
    for name, (size, data) in their_secs.items():
        if name not in your_secs or name.startswith(datadiff._SKIP):
            continue
        mine, mdata = your_secs[name]
        if mine <= size:
            continue
        zeros = mdata is not None and not any(mdata[size:]) and mine - size < datadiff.PADDING
        line = (f"{name} is {mine} bytes in yours and {size} in the original"
                + (": the extra bytes are zeros, alignment yours adds" if zeros else
                   ": yours holds data the original doesn't (another file's, or written twice)"))
        (out.maybe if zeros else out.certain).append(line)
    return out
