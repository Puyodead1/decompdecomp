"""The STL's code in a PC game, found without an agent: each common container's explicit instantiation compiled with
the game's Visual C++ and each file's own flags (one probe file per instantiation, so what a function needs is
known), and the game's open functions matched against what they compile to (runtime.Fingerprints). On a 2003 game
136 functions were such instances, 115 of them open, each an agent's session rebuilding a red-black tree by hand.
ForkEngine.autopilot_instances adds the instantiation to the function's file and names it (name_instance).
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
from pathlib import Path

from . import runtime

# what a probe file includes: the containers' headers, and stand-ins for a game's small structs of the sizes its
# containers hold most (a map of 20- and 24-byte values)
PRELUDE = ("#include <map>\n#include <set>\n#include <list>\n#include <vector>\n#include <deque>\n#include <string>\n"
           "#include <locale>\n"
           "struct STL_P20 { int a[5]; };\nstruct STL_P24 { int a[6]; };\n")
PROBES = (
    "template class std::map<std::string, int>;",
    "template class std::map<std::string, std::string>;",
    "template class std::map<std::string, void*>;",
    "template class std::map<int, int>;",
    "template class std::map<int, void*>;",
    "template class std::map<int, std::string>;",
    "template class std::map<std::string, STL_P20>;",
    "template class std::map<std::string, STL_P24>;",
    "template class std::set<int>;",
    "template class std::set<std::string>;",
    "template class std::set<void*>;",
    "template class std::list<int>;",
    "template class std::list<void*>;",
    "template class std::list<std::string>;",
    "template class std::vector<int>;",
    "template class std::vector<void*>;",
    "template class std::vector<std::string>;",
    "template class std::vector<char>;",
    "template class std::deque<int>;",
    "template class std::deque<void*>;",
    "template class std::basic_string<char>;",
    # a facet's members as a game's stream use makes them: an explicit instantiation inlines what that doesn't (a
    # 2003 game's do_get calls istreambuf_iterator::equal; `template class` put it inline), so a function using it
    *(f"const std::{facet}<char>& stl_{facet}(const std::locale& l) {{ return std::use_facet<std::{facet}<char> >(l); }}"
      for facet in ("num_get", "num_put")),
)
PROBE_SECONDS = 300
_USES = re.compile(r"^const std::(\w+)<char>& stl_")
# a unit's build statement in build.ninja: its object, then its compiler, include folder and flags
_BUILD = re.compile(r"^build (\S+): cl\b.*\n(?:[ \t]+.*\n)*", re.M)


def spoiler(line: str) -> re.Pattern | None:
    """For a probe that uses a facet, the explicit instantiation of it a file may have (an agent's) that makes the
    facet's code otherwise: the probe's code isn't the game's while that line is there too."""
    if (m := _USES.match(line)) is None:
        return None
    return re.compile(rf"^[ \t]*template\s+class\s+std::{m.group(1)}\s*<\s*char\b[^;]*;[^\n]*\n?", re.M)


WINE = "wine"  # a file whose compiler runs through wine (Visual C++ 2015 and newer off Windows): no probes for it


def _args(text: str) -> list[str]:
    """build.ninja's quoted arguments (configure.py's q: list2cmdline on Windows, whose backslashes stay)."""
    return [a.strip('"') for a in shlex.split(text, posix=os.name != "nt")]


def unit_compilers(ninja: str) -> dict[str, tuple[str, str, tuple[str, ...], tuple[str, ...]]]:
    """Each source file's object -> (what runs its compiler: wibo's path, WINE or "", its compiler, its include
    folders, its flags), as build.ninja builds it: the cl rule's flags (CL_FLAGS) and the file's own (cflags). A
    file's `runner` and `includes` (#136); a build.ninja written before them has the rule's --wrapper and one
    `include`."""
    rule = re.search(r"^rule cl\n(?:[ \t]+.*\n)+", ninja, re.M)
    text = rule.group(0).replace("$\n", " ") if rule else ""
    base = re.search(r"\s--\s+(.*?)\s*\$cflags", text, re.S)
    flags = tuple((base.group(1) if base else "/nologo /c /O2 /W3 /GX").split())
    old = re.search(r"--wrapper\s+(\S+)", text)
    out = {}
    for m in _BUILD.finditer(ninja):
        block = m.group(0)
        get = lambda key, block=block: (re.search(rf"^[ \t]+{key} = (.*)$", block, re.M) or [None, ""])[1].strip()  # noqa: E731
        runs = _args(get("runner"))
        run_with = WINE if "--wine" in runs else runs[runs.index("--wrapper") + 1] if "--wrapper" in runs[:-1] else \
            (old.group(1) if old and "$runner" not in text else "")
        includes = _args(get("includes"))
        folders = tuple(includes[k + 1] for k in range(len(includes) - 1) if includes[k] == "--include") or \
            tuple(_args(get("include")))
        out[m.group(1)] = (run_with, get("cl"), folders, flags + tuple(get("cflags").split()))
    return out


def prints(root: Path, compiler: tuple[str, str, tuple[str, ...], tuple[str, ...]], cache: Path,
           log=print) -> runtime.Fingerprints:
    """The probes compiled as `compiler` (unit_compilers') builds a file, each function's `library` its probe's
    index; compiled once per compiler and flags (`cache`). Nothing for a compiler wine runs: its probes would take wine's
    setup, and the STL's code of the games it built is yet to be looked at."""
    run_with, cl, includes, flags = compiler
    if run_with == WINE:
        return runtime.Fingerprints([])
    key = hashlib.sha1(repr((cl, includes, flags, PRELUDE, PROBES)).encode()).hexdigest()[:12]
    folder = cache / key
    folder.mkdir(parents=True, exist_ok=True)
    found: list[runtime.LibraryFunction] = []
    for k, line in enumerate(PROBES):
        obj = folder / f"{k}.obj"
        if not obj.is_file():
            src = folder / f"{k}.cpp"
            src.write_text(PRELUDE + line + "\n", encoding="utf-8")
            # (the source by its path from the project, as its build gives it: CL reads /tmp/... as an option)
            command = [*([run_with] if run_with else []), cl, *[f for f in flags if f not in ("/c",)], "/c", "/W1",
                       *(f"/I{d}" for d in includes), f"/Fo{obj}", src.relative_to(root).as_posix()]
            try:
                subprocess.run(command, cwd=root, capture_output=True, timeout=PROBE_SECONDS)
            except (OSError, subprocess.SubprocessError) as e:
                log(f"an STL probe didn't compile: {e}")
            if not obj.is_file():
                continue
        found += [f for f in runtime.object_functions(obj.read_bytes(), str(k)) if f.name.startswith("?")]
    return runtime.Fingerprints(found)
