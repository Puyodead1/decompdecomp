"""Pre-flight: a project is checked to build before helpers spend compiles on it. A project folder copied from
/home/olduser to /home/sam still ran /home/olduser/.local/share/uv/tools/decompnet/bin/python in its build.ninja,
and every compile failed with "/bin/sh: 1: ...: not found" (five compiles, two sessions that then quit)."""

import json
import sys
import types

from decompnet.app import agents as agents_mod
from decompnet.app.engine import RomNetwork
from decompnet.forks.project import ForkProject

GONE = "/home/olduser/.local/share/uv/tools/decompnet/bin/python"


def _project(tmp_path, fixes: bool):
    root = tmp_path / "ws" / "p"
    (root / "tools").mkdir(parents=True)
    (root / "objdiff.json").write_text(json.dumps({"units": []}))
    (root / ".decomp.wtf.json").write_text(json.dumps({"platform": "pc", "setup": [["python", "tools/configure.py"]]}))
    (root / "build.ninja").write_text(f"PY = {GONE}\ncflags = /O2 /G6 /DNDEBUG\nrule cc\n  command = $PY tools/x.py\n")
    py = "sys.executable" if fixes else repr(GONE)
    (root / "tools" / "configure.py").write_text(
        "import sys\nopen('build.ninja', 'w').write('PY = ' + " + py + " + '\\nrule cc\\n  command = $PY x\\n')\n")
    return root


def test_build_problem_finds_programs_build_ninja_runs_that_arent_here(tmp_path):
    root = _project(tmp_path, fixes=True)
    fp = ForkProject(root)
    why = fp.build_problem()
    assert why is not None and GONE in why and "/O2" not in why  # MSVC flags aren't paths
    tool = (root / "tools" / "configure.py").as_posix()  # a program that's here, by absolute path on any system
    (root / "build.ninja").write_text(f"PY = {sys.executable}\nrule cc\n  command = {tool} x\n")
    assert fp.build_problem() is None
    (root / "objdiff.json").unlink()
    assert "objdiff.json" in fp.build_problem()



def test_a_build_set_up_on_windows_is_found_out_on_linux(tmp_path, monkeypatch):
    """A PC project's Decomp folder copied from Windows to a Linux server: its build.ninja ran the Windows install's
    pythonw.exe, on a line ninja_syntax wrapped ("command = $" and the program on the next line), and the check
    passed it as fine."""
    from decompnet.forks import project as project_mod

    root = _project(tmp_path, fixes=True)
    win = r"C:\Users\someone\AppData\Local\Programs\decompdecomp\python\pythonw.exe"
    (root / "build.ninja").write_text(f"rule cl\n  command = $\n      {win} $\n      tools/compile.py --output $out\n")
    monkeypatch.setattr(project_mod.os, "name", "posix")
    why = ForkProject(root).build_problem()
    assert why is not None and win in why
    wrapped = f"rule cc\n  command = $\n      {GONE} $\n      tools/x.py\n"  # (wrapped, on Linux too)
    (root / "build.ninja").write_text(wrapped)
    assert GONE in ForkProject(root).build_problem()

def test_preflight_runs_the_setup_again_and_keeps_what_it_couldnt_fix(tmp_path):
    for fixes in (True, False):
        net = RomNetwork(tmp_path / f"d{fixes}.db", tmp_path / "ws")
        root = _project(tmp_path / str(fixes), fixes)
        net.forks._register("p", "P", "fork", root, {"kind": "fork", "ready": True, "platform": "pc"}, "x")
        why = net.forks.preflight("p")
        if fixes:
            assert why is None and sys.executable in (root / "build.ninja").read_text()
        else:
            assert why is not None and GONE in why
            assert net.forks.overview("p")["build_problem"] == why  # the project's page says so


def test_helpers_dont_start_a_session_on_a_project_that_doesnt_build(tmp_path):
    net = RomNetwork(tmp_path / "d.db", tmp_path / "ws")
    root = _project(tmp_path, fixes=False)
    net.forks._register("p", "P", "fork", root, {"kind": "fork", "ready": True, "platform": "pc"}, "x")
    fake = types.SimpleNamespace(net=net)
    assert GONE in agents_mod.Manager._build_problem(fake, "p")
    (root / "build.ninja").write_text(f"PY = {sys.executable}\n")
    assert agents_mod.Manager._build_problem(fake, "p") is None


def test_the_header_names_a_projects_compiler_as_its_console_does(tmp_path):
    """The page put "CodeWarrior" before every compiler id that wasn't a DS one: a PC project's header read
    "CodeWarrior MSVC/8.0SP1". The overview gives the console's own name for it."""
    net = RomNetwork(tmp_path / "d.db", tmp_path / "ws")
    root = _project(tmp_path, fixes=True)
    net.forks._register("p", "P", "fork", root, {"kind": "fork", "ready": True, "platform": "pc",
                                                  "compiler": "MSVC/8.0SP1"}, "x")
    assert net.forks.overview("p")["compiler_name"] == "Visual C++ 8.0 SP1"
    net.forks._register("q", "Q", "fork", root, {"kind": "fork", "ready": True, "platform": "pc"}, "x")
    assert net.forks.overview("q")["compiler_name"] is None  # (a public decomp's build names none)
