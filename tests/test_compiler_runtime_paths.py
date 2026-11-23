"""SN's EE-GCC 2.95 drivers put an unquoted path to themselves on their own command line: installed under a folder
whose path has spaces (macOS's ~/Library/Application Support), they run from a copy whose path has none."""
import concurrent.futures
import os
import sys

import pytest

from decompnet import toolchains


def pack(root, content="original"):
    root.mkdir(parents=True)
    (root / toolchains.MANIFEST).write_text(content)
    (root / "cc.exe").write_text(content)
    return root


def can_symlink(tmp_path) -> bool:
    try:
        (tmp_path / ".probe").symlink_to(tmp_path)
    except OSError:  # (Windows without Developer Mode)
        return False
    (tmp_path / ".probe").unlink()
    return True


def test_a_path_without_spaces_is_used_as_it_is(tmp_path, monkeypatch):
    root = pack(tmp_path / "compiler")
    monkeypatch.setattr(toolchains.tempfile, "TemporaryDirectory", lambda **kw: pytest.fail("an unneeded copy"))
    assert toolchains._space_free_runtime(root) == root.resolve()


def test_a_path_with_spaces_gets_one_copy_per_install(tmp_path):
    root = pack(tmp_path / "Application Support" / "compiler")
    links = can_symlink(tmp_path)
    if links:
        (tmp_path / "alias").symlink_to(root, target_is_directory=True)
        (root / "helper.exe").symlink_to(root / "cc.exe")
    asked = [root, tmp_path / "alias", root, tmp_path / "alias"] if links else [root] * 4
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        copies = list(pool.map(toolchains._space_free_runtime, asked))
    copied = copies[0]
    assert all(path == copied for path in copies)  # (threads share one copy)
    assert not any(c.isspace() for c in str(copied.resolve()))
    assert copied != root.resolve() and (copied / "cc.exe").read_text() == "original"
    if links:  # the driver asks for its real path: a link would lead it back to the one with spaces
        assert not (copied / "helper.exe").is_symlink() and (copied / "helper.exe").read_text() == "original"
    if sys.platform != "win32":
        assert copied.parent.stat().st_mode & 0o077 == 0  # (private to this user)
    # installed again: a new copy, and a compile still using the old one keeps it
    (root / "cc.exe").write_text("reinstalled")
    manifest = root / toolchains.MANIFEST
    stamp = manifest.stat().st_mtime_ns
    os.utime(manifest, ns=(stamp, stamp + 1_000_000))
    replaced = toolchains._space_free_runtime(root)
    assert replaced != copied and (replaced / "cc.exe").read_text() == "reinstalled"
    assert (copied / "cc.exe").read_text() == "original"


def test_a_failed_copy_is_removed_and_tried_again(tmp_path, monkeypatch):
    root = pack(tmp_path / "compiler files")
    original = toolchains.shutil.copytree
    partial = []

    def fail(source, target):
        target.mkdir()
        partial.append(target)
        raise OSError("disk full")

    monkeypatch.setattr(toolchains.shutil, "copytree", fail)
    with pytest.raises(toolchains.ToolchainError, match="free space"):
        toolchains._space_free_runtime(root)
    assert partial and not partial[0].exists()
    monkeypatch.setattr(toolchains.shutil, "copytree", original)
    assert (toolchains._space_free_runtime(root) / "cc.exe").read_text() == "original"


def test_only_the_marked_packs_run_from_a_copy(tmp_path, monkeypatch):
    primary, runner = tmp_path / "compiler", tmp_path / "runner"
    monkeypatch.setattr(toolchains, "require", lambda tid, *a, **kw: runner if tid == "wibo" else primary)
    copied, seen = tmp_path / "copied", []
    monkeypatch.setattr(toolchains, "_space_free_runtime", lambda directory: seen.append(directory) or copied)
    monkeypatch.setattr(toolchains, "current_platform", lambda: "macos-arm64")
    monkeypatch.setattr(toolchains.wsl, "wanted", lambda: False)
    for tid in ("ee-gcc-2.95.2", "ee-gcc-2.95.3"):
        assert toolchains.get(tid).space_free_runtime
        assert toolchains.runtime_dirs(tid) == (copied, runner)
    assert seen == [primary, primary]
    assert toolchains.runtime_dirs("mwcps2-2.3.3") == (primary, runner)  # (CodeWarrior quotes its paths)
    assert len(seen) == 2
