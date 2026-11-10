"""A Windows PC project's files for reccmp (github.com/isledecomp/reccmp, the LEGO Island decompilation's tool, which
compares a recompiled program with the original function by function, and its globals and vtables): written by
Export, so the project works with it and with what is built on it.

- Each function of src/ whose C the project has is annotated as reccmp reads it, the line above its definition:
  `// FUNCTION: GAME 0x00401000` (the program's target, its address in the user's copy; a DLL's at its own base,
  not the project's); each global of source/data/ too, `// GLOBAL: GAME 0x004C6388`.
- reccmp-project.yml names each program a target (its file, its SHA-256), the project its source root.
- reccmp-user.yml says where the user's copies are (orig/), reccmp-build.yml where the program a recompile makes is
  and its PDB, which reccmp reads with Microsoft's cvdump: `ninja reccmp` links it (tools/relink.py --pdb, into
  build/<version>/reccmp/). Both are the user's own and stay out of git.
Annotations written before are replaced, so an export again leaves one of each.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

MARK = re.compile(r"^// (?:FUNCTION|GLOBAL): [A-Z0-9_]+ 0x[0-9a-fA-F]+[ \t]*\r?\n", re.M)
SEG = re.compile(r'^#pragma (?:data|const|bss)_seg\("[^"$]*\$([0-9A-Fa-f]{8})"\)\s*\n', re.M)
AUTO = re.compile(r"func_([0-9A-Fa-f]{8})")


def target(exe: str) -> str:
    """A program's reccmp target: its file's name, as reccmp's projects write them (LEGO1 for LEGO1.DLL)."""
    return re.sub(r"[^A-Z0-9_]", "_", Path(exe).stem.upper()) or "GAME"


def _identifiers(auto: str, real: str | None) -> list[tuple[str | None, str]]:
    """(class, name) a function's C may define it by: its project name, and the real name it was given (`A::f`, a
    Visual C++ name `?f@A@@...`, or a plain one)."""
    out: list[tuple[str | None, str]] = [(None, auto)]
    if real:
        if real.startswith("?") and (m := re.match(r"\?(\w+)@(\w+)@", real)):
            out.append((m.group(2), m.group(1)))
        elif "::" in real:
            cls, _, name = real.rpartition("::")
            out.append((cls.rsplit("::", 1)[-1], name))
        elif re.fullmatch(r"\w+", real):
            out.append((None, real))
    return out


def _definition(text: str, ids: list[tuple[str | None, str]]) -> int | None:
    """Where the line a function's definition starts on begins: `name(` (or `Class::name(`) with its body's `{` after
    its parameters, not a declaration's `;`."""
    for cls, name in ids:
        prefix = rf"\b{re.escape(cls)}\s*::\s*" if cls else r"(?<![\w:])"
        for m in re.finditer(rf"{prefix}{re.escape(name)}\s*\(", text):
            depth, i = 1, m.end()
            while i < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[i], 0)
                i += 1
            rest = text[i:i + 200].lstrip()
            rest = re.sub(r"^(const|throw\s*\([^)]*\))\s*", "", rest)
            if rest.startswith("{") or re.match(r"^:\s*\w", rest):  # (a body, or a constructor's initialisers)
                return text.rfind("\n", 0, m.start()) + 1
    return None


def annotate(root: Path, info: dict) -> tuple[int, int]:
    """Every function's and global's annotation written (module docstring); how many of each."""
    names = info.get("names") or {}
    programs = {"": (info["exe"], 0)}
    for m in info.get("modules") or []:  # (a DLL at the project's address; reccmp reads it at its own)
        programs[m["name"]] = (m["exe"], (m.get("preferred_base") or m["image_base"]) - m["image_base"])
    functions = 0
    for unit, fns in (info.get("units") or {}).items():
        module = unit.rsplit("/", 1)[0] if "/" in unit else ""
        exe, shift = programs.get(module, programs[""])
        files = sorted((root / "src").rglob(f"{Path(unit).name}.c*"))
        files = [f for f in files if f.suffix in (".c", ".cpp", ".cc", ".cxx") and (not module or module in f.parts)]
        for path in files:
            text = MARK.sub("", path.read_text(encoding="utf-8", errors="surrogateescape"))
            places = []
            for fn in fns:
                auto = f"func_{fn['addr']:08X}"
                at = _definition(text, _identifiers(auto, names.get(auto)))
                if at is not None:
                    places.append((at, f"// FUNCTION: {target(exe)} 0x{fn['addr'] + shift:08x}\n"))
            for at, line in sorted(set(places), reverse=True):
                text = text[:at] + line + text[at:]
            functions += len(set(places))
            path.write_text(text, encoding="utf-8", errors="surrogateescape")
    globals_ = 0
    for module, (exe, shift) in programs.items():
        name = target(exe)
        for path in sorted((root / "source" / module / "data").glob("*.c")):
            text = MARK.sub("", path.read_text(encoding="utf-8"))
            text, n = SEG.subn(lambda m, name=name, shift=shift:
                               m.group(0) + f"// GLOBAL: {name} 0x{int(m.group(1), 16) + shift:08x}\n", text)
            globals_ += n
            path.write_text(text, encoding="utf-8")
    return functions, globals_


def project_files(root: Path, info: dict, version: str) -> None:
    """reccmp-project.yml (the project's: in git) and reccmp-user.yml and reccmp-build.yml (where this computer has
    the user's copies and the program `ninja reccmp` makes: not in git)."""
    programs = [info["exe"]] + [m["exe"] for m in info.get("modules") or []]
    lines = ["# reccmp (https://github.com/isledecomp/reccmp): compares the program `ninja reccmp` builds with your copy,",
             "# function by function, by the `// FUNCTION:` and `// GLOBAL:` lines above each in the C. Written by",
             "# decompdecomp's Export.", "targets:"]
    # (paths from the project's folder: one written on Linux or WSL, its absolute paths, didn't load on Windows)
    user, build = ["targets:"], ["project: .", "targets:"]
    for exe in programs:
        copy = root / exe
        sha = hashlib.sha256(copy.read_bytes()).hexdigest() if copy.exists() else ""
        lines += [f"  {target(exe)}:", f"    filename: {Path(exe).name}", "    source-root: .", "    hash:",
                  f"      sha256: {sha}"]
        user += [f"  {target(exe)}:", f"    path: {Path(exe).as_posix()}"]
        made = Path("build") / version / "reccmp" / Path(exe).name
        build += [f"  {target(exe)}:", f"    path: {made.as_posix()}",
                  f"    pdb: {made.with_name(made.name + '.pdb').as_posix()}"]
    (root / "reccmp-project.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "reccmp-user.yml").write_text("\n".join(user) + "\n", encoding="utf-8")
    (root / "reccmp-build.yml").write_text("\n".join(build) + "\n", encoding="utf-8")
    ignore = root / ".gitignore"
    text = ignore.read_text(encoding="utf-8") if ignore.exists() else ""
    missing = [n for n in ("reccmp-user.yml", "reccmp-build.yml") if n not in text.split()]
    if missing:
        ignore.write_text(text + ("" if text.endswith("\n") or not text else "\n") + "\n".join(missing) + "\n",
                          encoding="utf-8")
