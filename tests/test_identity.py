"""A machine pass over the source is kept only when the unit builds to the same object: what objdiff's scores
can't see (an extra function, another order, a constant read through a symbol) is a difference here."""

import pytest

from decompnet import toolchains
from decompnet.compiler import compile_source
from decompnet.forks import identity
from decompnet.project import compiler_config

pytestmark = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None, reason="needs gcc-2.7.2-kmc")

ADD = "int add(int a, int b) {\n    return a + b;\n}\n"
SUB = "int sub(int a, int b) {\n    return a - b;\n}\n"


@pytest.fixture
def build(tmp_path):
    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": "gcc-2.7.2-kmc",
                                                  "flags": ["-G0", "-mips3", "-mgp32", "-mfp32", "-O2"]}})
    n = [0]

    def run(source: str):
        result = compile_source(cfg, "", source)
        assert result.ok, result.log
        n[0] += 1
        path = tmp_path / f"{n[0]}.o"
        path.write_bytes(result.obj)
        return path

    return run


def test_what_doesnt_change_the_object_is_the_same(build):
    a = build(ADD + SUB)
    b = build("/* a comment */\nextern int unused;\n" + ADD + "\n\n" + SUB)
    assert identity.same(a, b) is True


def test_what_objdiffs_scores_miss_is_a_difference(build):
    base = identity.fingerprint(build(ADD + SUB))
    order = identity.fingerprint(build(SUB + ADD))
    assert base != order and any("symbols differ" in d or "bytes differ" in d for d in base.differences(order))
    extra = identity.fingerprint(build("static int helper(int a) {\n    return a * 3;\n}\n"
                                       "int use(int a) {\n    return helper(a);\n}\n" + ADD + SUB))
    assert base != extra and base.differences(extra)
    lit = identity.fingerprint(build("float half(void) {\n    return 0.5f;\n}\n"))
    ext = identity.fingerprint(build("extern float lbl_80001000;\nfloat half(void) {\n    return lbl_80001000;\n}\n"))
    assert lit != ext and any("relocations" in d or "section" in d for d in lit.differences(ext))


def test_an_object_not_elf_gives_no_verdict(tmp_path, build):
    junk = tmp_path / "junk.obj"
    junk.write_bytes(b"\x4c\x01" + b"\0" * 60)
    assert identity.fingerprint(junk) is None and identity.same(junk, build(ADD)) is None
