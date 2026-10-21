"""Ghidra drafts: decompiled C for platforms m2c doesn't read (x86, AArch64, Xbox 360 PowerPC, SuperH...).

Optional: Ghidra is large (540 MB) and needs Java 21+. Headless Ghidra analyses a unit's target object once
and decompiles all its functions; the result is cached next to the project, so the cost (tens of seconds,
mostly starting the JVM) is paid once per source file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path

from .. import toolchains
from ..limits import capped


def available() -> bool:
    return toolchains.installed("ghidra") is not None and toolchains.java_version() >= 21


def _headless() -> Path:
    base = toolchains.path("ghidra") / "support"
    return base / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")


def _run_script(binary: Path, script: str, timeout: float, *, analyse: bool = True, args: tuple[str, ...] = (),
                keep: Path | None = None) -> list[dict]:
    """Import `binary` into a throwaway Ghidra project, run one of our post-scripts on it and return the JSON objects
    it wrote, one per line ([] when Ghidra failed or took longer than `timeout`). `args`: the script's arguments
    after the output path. `keep`: where the output file goes (and stays) instead of being read back."""
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        src = resources.files("decompnet.forks").joinpath("ghidra_scripts", script)
        (scripts / script).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        out = keep or Path(tmp) / "out.jsonl"
        target = Path(tmp) / binary.name
        shutil.copyfile(binary, target)
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(target), "-scriptPath", str(scripts),
                "-postScript", script, str(out), *args, "-deleteProject", *([] if analyse else ["-noanalysis"])]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return []
        rows = []
        if keep is None and out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        return rows


def decompile_object(obj: Path, cache_dir: Path, timeout: float = 900) -> dict[str, str]:
    """name -> decompiled C for every function in an object file (cached by the object's content)."""
    key = hashlib.sha1(obj.read_bytes()).hexdigest()[:16]
    cache = cache_dir / f"{obj.stem}-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not available():
        return {}
    result = {row["name"]: row["c"] for row in _run_script(obj, "DecompWtfExport.java", timeout)}
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(result), encoding="utf-8")
    return result


def functions(program: Path, timeout: float = 3600) -> list[dict]:
    """Every function Ghidra's analysis finds in a whole program (a Windows .exe: Ghidra reads its imports, exports and
    the C runtime's functions too): {"entry", "end", "name", "source", "purge", "convention", "params", "thunk"}."""
    return _run_script(program, "DecompWtfFunctions.java", timeout)


def program_drafts(program: Path, addresses: list[int], out: Path, timeout: float = 4 * 3600) -> bool:
    """Decompile a whole program's functions at `addresses` (in that order: autopilot gives the smallest first) into
    `out`, one JSON line each (ghidra_scripts/DecompWtfDrafts.java): one analysis of the program for all of them,
    which takes minutes, where a run per object took tens of seconds each. Written whole: `out` appears only when
    Ghidra finished. Whether it did."""
    if not available():
        return False
    out.parent.mkdir(parents=True, exist_ok=True)
    part = out.with_name(out.name + ".part")
    wanted = out.with_name(out.name + ".addresses")
    wanted.write_text("".join(f"{a:08x}\n" for a in addresses), encoding="utf-8")
    try:
        _run_script(program, "DecompWtfDrafts.java", timeout, args=(str(wanted), "0"), keep=part)
        if not part.exists() or part.stat().st_size == 0:
            return False
        os.replace(part, out)
        return True
    finally:
        wanted.unlink(missing_ok=True)
        part.unlink(missing_ok=True)
