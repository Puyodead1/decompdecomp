"""A GameCube/Wii project's build runs its tools when their paths (or the project's) have spaces: the build
generator dtk-template gives (tools/project.py) is patched to quote them (consoles/gc_wii/template_paths.py)."""
import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.consoles.gc_wii import template_paths
from decompnet.forks.project import ForkError

# the lines of the pinned dtk-template's tools/project.py the patch changes, in a generator of a few lines
FRAGMENT = '''
CHAIN = "cmd /c " if is_windows() else ""


def commands(n, dtk, wrapper, mwcc, mwld, sjiswrap, gnu_as):
    n.variable("configure_args", sys.argv[1:])
    n.variable("python", f'"{sys.executable}"')
    return [f"{dtk} dol split $in $out_dir", f"{wrapper} {mwcc} $in", f"{mwld} $in", f"{sjiswrap} $in",
            f"{CHAIN}{gnu_as} dol as $in" + f" && {dtk} dol fixup $in"]
'''


def generator(root, text):
    path = root / "tools" / "project.py"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    template_paths.prepare(root)
    return path


def fake_tool(where: Path, root: Path, result: Path) -> Path:
    """A program at `where` (a folder with a space and a `$` in its path) that adds its arguments to `result`.
    Off Windows a shell script; on Windows Python itself, through a junction (no Developer Mode needed), told to run
    the project's script `dol`, so its arguments start with "dol" as the shell script's do."""
    if os.name != "nt":
        tool = where / "fake dtk"
        where.mkdir()
        tool.write_text(f'#!/bin/sh\nIFS="|"; printf "%s\\n" "$*" >> "{result}"\n')
        tool.chmod(0o755)
        return tool
    import _winapi

    _winapi.CreateJunction(str(Path(sys.base_prefix)), str(where))
    (root / "dol").write_text(f"import sys\nopen({str(result)!r}, 'a').write('|'.join(sys.argv) + '\\n')\n")
    return where / "python.exe"


def ninja() -> str:
    found = shutil.which("ninja") or str(Path(sys.executable).parent / ("ninja.exe" if os.name == "nt" else "ninja"))
    if not Path(found).is_file():
        pytest.skip("needs ninja")
    return found


def test_ninja_runs_tools_and_configure_whose_paths_have_spaces(tmp_path):
    root = tmp_path / "project with spaces"
    root.mkdir()
    namespace = {"sys": sys, "is_windows": lambda: os.name == "nt"}
    exec(generator(root, FRAGMENT).read_text(), namespace)
    result = root / "result.txt"
    tool = fake_tool(tmp_path / "Application Support's $tools", root, result)

    class Writer:
        def __init__(self):
            self.variables = {}

        def variable(self, key, value):
            self.variables[key] = value

    writer, argv = Writer(), sys.argv
    try:
        sys.argv = ["configure.py", "--dtk", str(tool), "--compilers", str(tmp_path / "compiler files")]
        commands = namespace["commands"](writer, *[tool] * 6)
    finally:
        sys.argv = argv
    (root / "config.yml").write_text("")
    # the tool alone, and two tools in one command (through cmd on Windows, whose quote rule broke the first)
    (root / "build.ninja").write_text(f"rule split\n  command = {commands[0]}\nrule as\n  command = {commands[4]}\n"
                                      "build output: split config.yml\n  out_dir = output\nbuild fixed: as config.yml\n")
    run = subprocess.run([ninja(), "-j1", "output", "fixed"], cwd=root, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert result.read_text().splitlines() == ["dol|split|config.yml|output", "dol|as|config.yml", "dol|fixup|config.yml"]
    # and configure.py run again by the build, with its arguments as they were
    (root / "capture.py").write_text("import sys, json\nopen('args.json', 'w').write(json.dumps(sys.argv[1:]))\n")
    (root / "build.ninja").write_text(f"args = {writer.variables['configure_args']}\nrule configure\n"
                                      f"  command = {writer.variables['python']} capture.py $args\nbuild again: configure\n")
    run = subprocess.run([ninja()], cwd=root, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert json.loads((root / "args.json").read_text()) == ["--dtk", str(tool), "--compilers", str(tmp_path / "compiler files")]


def test_the_pinned_template_is_patched_once_and_left_whole(tmp_path):
    if toolchains.installed("dtk-template") is None:
        pytest.skip("needs dtk-template installed")
    original = (toolchains.path("dtk-template") / "tools" / "project.py").read_text(encoding="utf-8")
    path = generator(tmp_path, original)
    patched = path.read_text(encoding="utf-8")
    ast.parse(patched)
    for name in (*template_paths.TOOLS, "mwcc", "mwld"):
        assert "{" + name + "}" not in patched
    assert "{_decomp_shell_arg(mwcc, _DECOMP_MW_VARS)}" in patched and 'CHAIN = "cmd /c cd . && "' in patched
    template_paths.prepare(tmp_path)
    assert path.read_text(encoding="utf-8") == patched
    assert (toolchains.path("dtk-template") / "tools" / "project.py").read_text(encoding="utf-8") == original


def test_the_compiler_version_stays_a_ninja_variable(tmp_path):
    namespace = {}
    exec(template_paths.HELPER, namespace)
    quote = namespace["_decomp_shell_arg"]
    path = tmp_path / "Application Support" / "$mw_version" / "mwcceppc.exe"
    assert "$mw_version" in quote(path, ("mw_version",)) and "$$mw_version" not in quote(path, ("mw_version",))
    assert "$$literal" in quote(tmp_path / "$literal" / "tool")


def test_a_generator_it_does_not_know_is_left_alone(tmp_path):
    path = tmp_path / "tools" / "project.py"
    path.parent.mkdir()
    path.write_text("different generator")
    with pytest.raises(ForkError, match="doesn't know"):
        template_paths.prepare(tmp_path)
    assert path.read_text() == "different generator"
