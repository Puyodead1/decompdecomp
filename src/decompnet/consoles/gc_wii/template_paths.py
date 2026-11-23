"""Quote the tool paths in a new project's build generator (tools/project.py), so it builds where paths have spaces.

dtk-template writes each tool's path into Ninja's commands as it is: `{dtk} dol split $in $out_dir`. A shell (or
Windows, splitting a command line) then cut a path with a space in two, and the build failed when the toolchains
were under ~/Library/Application Support (macOS), under a Windows user folder with a space, or when the project
itself was. The generator is patched in the project's copy (never in the installed template) to quote each tool's
path for the shell, escape the `$` Ninja would read, and keep the one Ninja variable a path holds on purpose
(`$mw_version`, which picks each object's CodeWarrior). Paths in build lines (inputs, outputs, dependencies) are
left alone: ninja_syntax escapes those itself.

On Windows the commands that run two tools (`cmd /c {mwcc} ... && {dtk} extab clean ...`) go through cmd, which
strips the first and the last quote of a command that starts with one and has more than two: those start with
`cd . && ` instead, a step that does nothing, so the first tool's quotes are kept.
"""
from pathlib import Path

from ...forks.project import ForkError

MARKER = "# decompdecomp: quote template shell paths v1"
HELPER = f'''

{MARKER}
_DECOMP_MW_VARS = ("mw_version",)


def _decomp_shell_arg(value, ninja_vars=()):
    import os
    import shlex
    import subprocess

    text = os.fspath(value)
    quoted = subprocess.list2cmdline([text]) if os.name == "nt" else shlex.quote(text)
    quoted = quoted.replace("$", "$$")
    for name in ninja_vars:
        quoted = quoted.replace("$$" + name, "$" + name)
    return quoted
'''

# the f-string fields in the pinned dtk-template's commands that are a tool's or a script's path
TOOLS = ("dtk", "wrapper", "sjiswrap", "gnu_as", "objdiff", "download_tool", "decompctx", "transform_dep",
         "configure_script", "changes_fmt", "report_baseline_path")
CONFIGURE_ARGS = 'n.variable("configure_args", sys.argv[1:])'
PYTHON = "n.variable(\"python\", f'\"{sys.executable}\"')"
CHAIN = 'CHAIN = "cmd /c " if is_windows() else ""'


def prepare(root: Path) -> None:
    """Patch `root`'s tools/project.py once (MARKER). A generator this doesn't know is left whole, with an error:
    patched halfway, some commands would quote and others not."""
    path = root / "tools" / "project.py"
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        return
    if any(known not in text for known in (CONFIGURE_ARGS, PYTHON, CHAIN, "{dtk}", "{mwcc}")):
        raise ForkError("the dtk-template decompdecomp installed has a build generator it doesn't know: update "
                        "decompdecomp (or reinstall dtk-template under Compilers & tools), then start the game again")
    text = text.replace(CONFIGURE_ARGS,
                        'n.variable("configure_args", " ".join(_decomp_shell_arg(arg) for arg in sys.argv[1:]))')
    text = text.replace(PYTHON, 'n.variable("python", _decomp_shell_arg(sys.executable))')
    text = text.replace(CHAIN, 'CHAIN = "cmd /c cd . && " if is_windows() else ""')
    for name in TOOLS:
        text = text.replace("{" + name + "}", "{_decomp_shell_arg(" + name + ")}")
    for name in ("mwcc", "mwld"):  # compilers/$mw_version/...: a Ninja variable, not the shell's
        text = text.replace("{" + name + "}", "{_decomp_shell_arg(" + name + ", _DECOMP_MW_VARS)}")
    text += HELPER
    compile(text, str(path), "exec")  # (a SyntaxError here is decompdecomp's bug: the project isn't written)
    path.write_text(text, encoding="utf-8")
