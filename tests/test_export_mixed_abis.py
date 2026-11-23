"""The rebuildable export's link: a game's period compilers tag their objects with the ABI and register width they
used, and GNU ld refuses to mix them. Only that refusal is retried, with --no-warn-mismatch, and the image is
still compared with the original byte for byte."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from decompnet import rom, toolchains

MISMATCH = ("mips-ps2-decompals-ld: build/b.o: linking 32-bit code with 64-bit code\n"
            "mips-ps2-decompals-ld: failed to merge target specific data of file build/b.o\n")


def builder(tmp_path, monkeypatch):
    """The export's build.py, loaded from an export folder of its own (it reads build.json beside it)."""
    shutil.copyfile(Path(rom.__file__).with_name("export_build.py"), tmp_path / "build.py")
    (tmp_path / "build.json").write_text(json.dumps({"image": "baserom", "output": "build/game.bin", "ld_flags": [],
                                                     "functions": [], "segments": []}))
    spec = importlib.util.spec_from_file_location("export_build_under_test", tmp_path / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_abi_and_width_mismatches_are_retried(tmp_path, monkeypatch):
    export_build = builder(tmp_path, monkeypatch)
    assert export_build.only_abi_mismatch(MISMATCH)
    assert export_build.only_abi_mismatch("ld: b.o: ABI mismatch: linking EABI32 module with previous O32 modules\n")
    assert not export_build.only_abi_mismatch(MISMATCH + "ld: build/b.o: undefined reference to `missing'\n")
    assert not export_build.only_abi_mismatch("ld: failed to merge target specific data of file build/b.o\n")
    assert not export_build.only_abi_mismatch("ld: cannot find build/b.o\n")


def test_the_link_runs_again_without_the_check_and_other_failures_still_stop(tmp_path, monkeypatch):
    module = builder(tmp_path, monkeypatch)
    runs = []

    def run(argv, **kwargs):
        runs.append(argv)
        failed = "--no-warn-mismatch" not in argv
        return subprocess.CompletedProcess(argv, int(failed), "", MISMATCH if failed else "")

    monkeypatch.setattr(module.subprocess, "run", run)
    module.run(["ld", "-T", "game.ld"], mixed_abis=True)
    assert runs == [["ld", "-T", "game.ld"], ["ld", "--no-warn-mismatch", "-T", "game.ld"]]
    runs.clear()
    with pytest.raises(SystemExit):
        module.run(["objcopy", "-O", "binary"])  # (any other tool: no retry)
    assert runs == [["objcopy", "-O", "binary"]]
    monkeypatch.setattr(module.subprocess, "run",
                        lambda argv, **_: subprocess.CompletedProcess(argv, 1, "", "ld: undefined reference to `x'\n"))
    with pytest.raises(SystemExit):
        module.run(["ld"], mixed_abis=True)


@pytest.mark.skipif(toolchains.installed("binutils-mips") is None, reason="needs binutils-mips")
def test_objects_of_two_abis_rebuild_the_image_and_a_different_one_still_fails(tmp_path, monkeypatch):
    module = builder(tmp_path, monkeypatch)
    (tmp_path / "build").mkdir()
    todo = []
    for abi, word in [("32", "0x03e00008"), ("eabi", "0")]:
        src, obj = f"{abi}.s", f"build/{abi}.o"
        (tmp_path / src).write_text(f".text\n.word {word}\n")
        subprocess.run([module.binutils("as"), "-EB", "-march=vr4300", f"-mabi={abi}", "-no-pad-sections", "-o", obj,
                        src], cwd=tmp_path, check=True)
        todo.append(("asm", src, obj))
    expected = bytes.fromhex("03e0000800000000")
    (tmp_path / "baserom").write_bytes(expected)
    module.B["ld_flags"] = ["-EB"]
    monkeypatch.setattr(module, "setup", lambda: None)
    monkeypatch.setattr(module, "objects", lambda: (todo, {}, []))
    monkeypatch.setattr(module, "build_objects", lambda _: None)
    monkeypatch.setattr(module, "fill_gaps", lambda _: [])
    monkeypatch.setattr(module, "linker_script", lambda *_: (
        f"SECTIONS {{ .text 0x80000000 : {{ *(.text) }} /DISCARD/ : {{ {module.DISCARD} }} }}"))
    assert module.build()
    assert (tmp_path / "build/game.bin").read_bytes() == expected
    (tmp_path / "baserom").write_bytes(bytes(len(expected)))
    assert not module.build()
