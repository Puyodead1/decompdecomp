"""Copies of one struct that disagree, across a project's source files and headers.

A match proves only the bytes: a struct whose fields are named and sized wrong compiles to the same code wherever
each function's offsets come out the same. A PC game's files each declared their own copy of the structs they used,
and a reviewer found a PLAYER whose `slots[]` was off by 0x2C from the one another file's function showed (four
0x30-byte popup entries at 0x1BC, a cursor at 0x27C). Two copies that can't both be right are the cheapest sign of
that, and tidying (readable.py) sends a file back for them.

Two fields of two copies of a struct disagree when their bytes overlap and neither is the other's view: the same
field (same offset and size), an element of the same array, or a field inside one element of a struct-typed field.
Gaps (`pad_..`, `unk..`) say nothing. Layouts come from cfields.Header; what it can't lay out for certain is left out.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import cfields

PAD = re.compile(r"^_*(?:pad|unk|gap|reserved|filler|align)", re.I)
SOURCES = ("*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp")
SHOWN = 4  # disagreements told for one struct

_cache: dict[Path, tuple[float, dict]] = {}


def _structs(path: Path) -> dict[str, tuple[cfields.Header, cfields.Struct]]:
    """The structs a file defines (by tag and typedef name), laid out, cached by the file's mtime."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    hit = _cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        text = path.read_text(errors="replace", encoding="utf-8")
    except OSError:
        return {}
    header = cfields.Header(file_scope(text))
    found = {}
    for name in header.bodies:
        try:
            laid = header.struct(name)
        except RecursionError:
            laid = None
        if laid is not None and laid.fields:
            found[name] = (header, laid)
    _cache[path] = (mtime, found)
    return found


def file_scope(text: str) -> str:
    """The text without function bodies: a struct declared inside one (the locals a function keeps in one, to keep
    their order) is that function's own, not a copy of anything."""
    out, pos, depth, start = [], 0, 0, None
    for m in re.finditer(r"[{}]", text):
        if m.group() == "{":
            if depth == 0 and re.search(r"\)\s*(?:const\s*)?$", text[max(0, m.start() - 200):m.start()]):
                start = m.start()
            depth += 1
        else:
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[pos:start] + "{}")
                pos, start = m.end(), None
            depth = max(depth, 0)
    out.append(text[pos:])
    return "".join(out)


def project_files(root: Path) -> list[Path]:
    files = []
    for folder in ("src", "include"):
        for pattern in SOURCES:
            files += (root / folder).rglob(pattern) if (root / folder).is_dir() else []
    return sorted(set(files))


def _inside(outer: cfields.Field, outer_header: cfields.Header, inner: cfields.Field) -> bool:
    """Whether `inner` is a view of part of `outer`: an element of the same array, or within one element of a
    struct-typed field."""
    if outer.size is None or inner.size is None:
        return True  # (not known: no verdict)
    rel = inner.offset - outer.offset
    if rel < 0 or rel + inner.size * max(inner.count, 1) > outer.size * max(outer.count, 1):
        return False
    if outer_header.struct(outer.type) is not None:
        start = rel % outer.size
        return start + inner.size * max(inner.count, 1) <= outer.size
    return inner.size == outer.size and rel % outer.size == 0


def _disagree(a: cfields.Field, ha: cfields.Header, b: cfields.Field, hb: cfields.Header) -> bool:
    if a.size is None or b.size is None or PAD.match(a.name) or PAD.match(b.name) or _raw(a, ha) or _raw(b, hb):
        return False
    a_end, b_end = a.offset + a.size * max(a.count, 1), b.offset + b.size * max(b.count, 1)
    if a_end <= b.offset or b_end <= a.offset:
        return False
    if a.offset == b.offset and a.size == b.size:
        return False
    return not (_inside(a, ha, b) or _inside(b, hb, a))


def _raw(f: cfields.Field, header: cfields.Header) -> bool:
    """Bytes kept as bytes (`char p0[24]`): a gap by another name."""
    return f.count > 1 and header.resolve(f.type) in cfields.BYTE_POINTERS


def _show(f: cfields.Field) -> str:
    each = f" ({f.size:#x} bytes each)" if f.count > 1 else f" ({f.size:#x} bytes)" if f.size else ""
    count = f"[{f.count}]" if f.count > 1 else ""
    return f"{f.name}{count}{each} at {f.offset:#x}"


def conflicts(root: Path, source: str, files: list[Path] | None = None) -> list[str]:
    """The structs `source` defines or names whose copies elsewhere in the project disagree with each other, one line
    each: what two copies say that can't both be right."""
    root = Path(root)
    path = root / source
    try:
        text = path.read_text(errors="replace", encoding="utf-8")
    except OSError:
        return []
    words = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
    files = project_files(root) if files is None else files
    copies: dict[str, list[tuple[str, cfields.Header, cfields.Struct]]] = {}
    for f in files:
        for name, (header, laid) in _structs(f).items():
            if name in words:
                copies.setdefault(name, []).append((str(f.relative_to(root)), header, laid))
    out = []
    for name, found in sorted(copies.items()):
        if len(found) < 2:
            continue
        told = []
        for i, (pa, ha, sa) in enumerate(found):
            for pb, hb, sb in found[i + 1:]:
                if pa == pb:
                    continue
                bad = next(((fa, fb) for fa in sa.fields for fb in sb.fields if _disagree(fa, ha, fb, hb)), None)
                if bad:
                    told.append(f"{pa} has {_show(bad[0])}, {pb} has {_show(bad[1])}")
                if len(told) >= SHOWN:
                    break
            if len(told) >= SHOWN:
                break
        if told:
            out.append(f"struct {name}: " + "; ".join(told))
    return out
