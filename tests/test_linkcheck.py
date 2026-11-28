"""A file whose functions match may still not link: what its object shows next to the original's is said before a
build of the whole game tries it (forks/linkcheck.py), and a pass that moves the file's own constant into a literal
is judged by its code and where its relocations point, not by the whole object (identity.code_differences)."""

from types import SimpleNamespace

import pytest

from decompnet import toolchains
from decompnet.app.forkengine import ForkEngine
from decompnet.compiler import compile_source
from decompnet.forks import identity, linkcheck
from decompnet.project import compiler_config

pytestmark = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None, reason="needs gcc-2.7.2-kmc")

ADD = "int add(int a, int b) {\n    return a + b;\n}\n"
SUB = "int sub(int a, int b) {\n    return a - b;\n}\n"
# (a double: GCC builds a float like 0.5f in registers, and pools a double, as MWCC pools both)
HALF = "double tenth(void) {\n    return k;\n}\n"
K = "const double k = 0.1;\n"
LITERAL = "double tenth(void) {\n    return %s;\n}\n"


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


def test_the_files_own_constant_declared_extern_certainly_doesnt_link(build):
    original = build(K + HALF)
    found = linkcheck.causes(original, build("extern const double k;\n" + HALF))
    assert found.certain and "extern" in found.certain[0] and "k" in found.certain[0], found
    assert not linkcheck.causes(original, build(K + HALF))


def test_a_function_the_compiler_dropped_is_told_from_one_not_written(build):
    original = build(ADD + SUB)
    yours = build(ADD)
    dropped = linkcheck.causes(original, yours, source=ADD + "asm int sub(int a, int b) { ... }\n")
    assert any("force_active" in c and "sub" in c for c in dropped.certain), dropped
    unwritten = linkcheck.causes(original, yours, source=ADD)
    assert any("write it" in c and "sub" in c for c in unwritten.certain), unwritten


def test_globals_made_static_padding_and_longer_data_are_named(build):
    original = build("int g = 3;\nint t[2] = {1, 2};\nint get(void) {\n    return g + t[1];\n}\n")
    static = linkcheck.causes(original, build("static int g = 3;\nint t[2] = {1, 2};\n"
                                              "int get(void) {\n    return g + t[1];\n}\n"))
    assert not static.certain and any("static in yours" in c for c in static.maybe), static
    padded = linkcheck.causes(original, build("int g = 3;\nint t[2] = {1, 2};\nint gap_0[4] = {5, 6, 7, 8};\n"
                                              "int get(void) {\n    return g + t[1];\n}\n"))
    assert any("gap_0" in c and "padding" in c for c in padded.maybe), padded
    assert any(".data is" in c for c in padded.certain), padded  # (and its .data runs into the next file's)
    assert linkcheck.causes(original, None) is None


def test_a_literal_for_the_files_own_constant_keeps_the_code_and_where_it_points(build):
    original = build(K + HALF)
    extern = build("extern const double k;\n" + HALF)
    literal = build(LITERAL % "0.1")
    other = build(LITERAL % "0.25")
    assert identity.fingerprint(extern) != identity.fingerprint(literal)  # (the whole object differs)
    assert identity.code_differences(extern, literal, also=(original,)) == []
    said = identity.code_differences(extern, other, also=(original,))
    assert said and "points at" in said[0], said
    assert identity.code_differences(extern, literal) != []  # (without the original's object: no bytes to compare)


def test_a_static_renamed_is_the_same_code_and_a_global_renamed_isnt(build):
    use = "int use(int a) {\n    return %s(a);\n}\n"
    helper = "%sint %s(int a) {\n    return a * 3;\n}\n"
    a = build(helper % ("static ", "h") + use % "h")
    b = build(helper % ("static ", "triple") + use % "triple")
    assert identity.fingerprint(a) != identity.fingerprint(b) and identity.code_differences(a, b) == []
    # (GCC calls a function in the same file through its section: another file's, then)
    g, h = build("extern int h(int);\n" + use % "h"), build("extern int triple(int);\n" + use % "triple")
    said = identity.code_differences(g, h)
    assert said and "points at h" in said[0], said


def test_a_pass_that_may_change_the_data_mustnt_take_it_further_from_the_original(build, tmp_path):
    original = build(K + HALF)
    before = build("extern const double k;\n" + HALF)
    unit = SimpleNamespace(target=original, base=build(LITERAL % "0.1"))
    assert ForkEngine._changed_data(unit, before) == []
    # the same code, but a table the original hasn't: the data is further from it than before
    unit.base = build("int extra[8] = {1};\n" + LITERAL % "0.1")
    said = ForkEngine._changed_data(unit, before)
    assert said and "further from the original" in said[0], said
