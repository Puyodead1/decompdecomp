"""The persistent compiled-object cache (compile_cache.py): the same C with the same compiler is compiled once, any
change to what decides the object compiles again, and a damaged entry is a miss, never a wrong object."""

import os
import sys
import textwrap
from pathlib import Path

import pytest

from decompnet import compile_cache, toolchains
from decompnet.compiler import CompilerConfig, compile_source

# A stand-in compiler: its object is its input, its flags and a mark of its own version, and every run is counted (the
# counter's path comes from the environment: a file named on the command line would be part of the compiler's key).
COMPILER = textwrap.dedent("""
    import os, sys
    src, obj, flags = sys.argv[1], sys.argv[2], sys.argv[3:]
    with open(os.environ["FAKE_CC_COUNT"], "a") as f:
        f.write("x")
    text = open(src).read()
    if "syntax error" in text:
        sys.stderr.write("func.c:1: syntax error\\n")
        sys.exit(1)
    open(obj, "wb").write(("VERSION 1\\n" + " ".join(flags) + "\\n" + text).encode())
""")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("DECOMP_OBJECT_CACHE_MB", "64")
    monkeypatch.setenv("DECOMP_HOME", str(tmp_path / "home"))
    count = tmp_path / "count"
    count.write_text("")
    monkeypatch.setenv("FAKE_CC_COUNT", str(count))
    tc = tmp_path / "tc"
    tc.mkdir()
    (tc / "cc.py").write_text(COMPILER)
    (tc / toolchains.MANIFEST).write_text('{"id": "fake-cc", "parts": [{"sha256": "aa"}]}')
    headers = tmp_path / "include"
    headers.mkdir()
    (headers / "types.h").write_text("typedef int s32;\n")

    class Setup:
        root, folder, include = tmp_path, tc, headers

        def config(self, flags=("-O2",), prelude="", include_dirs=None):
            return CompilerConfig(cmd=[sys.executable, str(tc / "cc.py"), "{src}", "{obj}", *flags], sandbox="none",
                                  ro_paths=(str(tc),), prelude=prelude, timeout=60,
                                  include_dirs=(str(headers),) if include_dirs is None else include_dirs)

        def runs(self):
            return len(count.read_text())

        def entries(self):
            return [p for p in compile_cache.directory().rglob("*") if p.is_file() and not p.name.startswith(".")]
    yield Setup()
    compile_cache.wait_for_sweeps()


def test_the_same_compile_is_reused(cache):
    first = compile_source(cache.config(), "int g;", "int f(void) { return 1; }")
    second = compile_source(cache.config(), "int g;", "int f(void) { return 1; }")
    assert first.ok and second.ok and cache.runs() == 1
    assert second.obj == first.obj and second.language == first.language == "c"
    assert len(cache.entries()) == 1
    assert compile_cache.directory().is_relative_to(cache.root / "home")


@pytest.mark.parametrize("change", ["source", "header", "flags", "prelude", "language", "include", "manifest",
                                   "program"])
def test_any_change_to_what_decides_the_object_compiles_again(cache, change):
    base = dict(cfg=cache.config(), header="int g;", source="int f(void) { return 1; }", language=None)
    compile_source(base["cfg"], base["header"], base["source"], language=base["language"])
    changed = dict(base)
    if change == "source":
        changed["source"] = "int f(void) { return 2; }"
    elif change == "header":
        changed["header"] = "int g, h;"
    elif change == "flags":
        changed["cfg"] = cache.config(flags=("-O1",))
    elif change == "prelude":
        changed["cfg"] = cache.config(prelude="#define X 1\n")
    elif change == "language":
        changed["language"] = "c++"
    elif change == "include":
        (cache.include / "types.h").write_text("typedef long s32;\n")
        os.utime(cache.include / "types.h", ns=(1, 1))  # (a new mtime too: the digest memo follows the file's stat)
    elif change == "manifest":
        (cache.folder / toolchains.MANIFEST).write_text('{"id": "fake-cc", "parts": [{"sha256": "bb"}]}')
    elif change == "program":
        (cache.folder / "cc.py").write_text(COMPILER.replace("VERSION 1", "VERSION 2"))
        os.utime(cache.folder / "cc.py", ns=(1, 1))
    again = compile_source(changed["cfg"], changed["header"], changed["source"], language=changed["language"])
    assert again.ok and cache.runs() == 2
    if change == "program":
        assert again.obj.startswith(b"VERSION 2")


def test_failures_are_never_stored(cache):
    for _ in range(2):
        assert not compile_source(cache.config(), "", "syntax error").ok
    assert cache.runs() == 2 and cache.entries() == []


@pytest.mark.parametrize("damage", ["flip", "truncate", "empty", "garbage"])
def test_a_damaged_entry_is_a_miss_never_a_wrong_object(cache, damage):
    good = compile_source(cache.config(), "", "int f(void) { return 1; }")
    [entry] = cache.entries()
    data = entry.read_bytes()
    if damage == "flip":
        data = data[:-1] + bytes([data[-1] ^ 1])  # one bit of the object
    elif damage == "truncate":
        data = data[:len(data) // 2]  # a writer that died half way (os.replace makes it rare, a disk can still)
    elif damage == "empty":
        data = b""
    else:
        data = compile_cache.MAGIC + b"\0" * 40
    entry.write_bytes(data)
    again = compile_source(cache.config(), "", "int f(void) { return 1; }")
    assert again.ok and again.obj == good.obj and cache.runs() == 2
    assert compile_cache.load(compile_cache.key(cache.config(), "none", "", "int f(void) { return 1; }", None)).obj \
        == good.obj  # (stored again, whole)


def test_a_compiler_nothing_pins_is_not_cached(cache):
    (cache.folder / toolchains.MANIFEST).unlink()
    for _ in range(2):
        assert compile_source(cache.config(), "", "int f(void) { return 1; }").ok
    assert cache.runs() == 2 and cache.entries() == []


def test_a_program_found_on_path_is_not_cached(cache):
    cfg = cache.config()
    assert compile_cache.key(cfg, "none", "", "x", None) is not None
    cfg.cmd[0] = "python3"
    assert compile_cache.key(cfg, "none", "", "x", None) is None
    assert compile_cache.key(cache.config(), "wsl", "", "x", None) is None


def test_off_when_the_limit_is_zero(cache, monkeypatch):
    monkeypatch.setenv("DECOMP_OBJECT_CACHE_MB", "0")
    for _ in range(2):
        compile_source(cache.config(), "", "int f(void) { return 1; }")
    assert cache.runs() == 2 and not compile_cache.directory().exists()


def test_a_sweep_removes_the_least_recently_used(cache):
    sources = [f"int f(void) {{ return {n}; }}" for n in range(6)]
    for source in sources:
        compile_source(cache.config(), "", source)
    compile_cache.wait_for_sweeps()
    paths = [compile_cache._path(compile_cache.key(cache.config(), "none", "", s, None)) for s in sources]
    assert all(p.is_file() for p in paths) and len(cache.entries()) == 6
    for age, path in enumerate(paths):  # oldest first, a second apart
        os.utime(path, (1_000_000 + age, 1_000_000 + age))
    compile_source(cache.config(), "", sources[0])  # reading the oldest makes it the most recently used
    assert cache.runs() == 6
    removed = compile_cache.sweep(limit=int(paths[0].stat().st_size * 3.5))
    assert removed == 3
    assert [p.is_file() for p in paths] == [True, False, False, False, True, True]


def test_entries_live_in_the_data_home(cache, tmp_path, monkeypatch):
    other = tmp_path / "other-home"
    monkeypatch.setenv("DECOMP_HOME", str(other))
    assert compile_cache.directory() == Path(other) / ".decomp" / "object-cache" / f"v{compile_cache.FORMAT}"
