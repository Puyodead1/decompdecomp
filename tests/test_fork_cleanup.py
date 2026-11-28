"""Machine passes over a finished file (forks/cleanup.py): an extern of the file's own pooled constant becomes the
literal, all of a file's at once; declarations nothing uses go. Text only here; the engine keeps a change only when
the unit's object stays as it must (tests/test_fork_link.py)."""

import struct

from decompnet.forks import cleanup

FILE = """\
#include "types.h"

extern f32 lbl_80001000;
extern f32 lbl_80001004, lbl_80001008; /* half and a third */
extern f64 lbl_80001010;
extern f32 g_other;  /* another file's */

f32 scale(f32 x) {
    return x * lbl_80001000 - lbl_80001004;
}

f64 widen(f32 x) {
    extern f32 lbl_80001008;
    return x + lbl_80001010 + lbl_80001008 + g_other;
}
"""


def held(**values):
    return {name: (struct.pack(">d" if width == 8 else ">f", v), width, False) for name, (v, width) in values.items()}


def test_the_files_own_constants_become_literals_and_their_declarations_go():
    own = cleanup.own_constants(FILE, held(lbl_80001000=(2.0, 4), lbl_80001004=(0.5, 4),
                                        lbl_80001008=(1 / 3, 4), lbl_80001010=(0.1, 8)))
    assert own == {"lbl_80001000": "2.0f", "lbl_80001004": "0.5f", "lbl_80001008": "0.33333334f",
                   "lbl_80001010": "0.1"}
    out = cleanup.with_literals(FILE, own)
    assert "return x * 2.0f - 0.5f;" in out and "return x + 0.1 + 0.33333334f + g_other;" in out, out
    assert "lbl_8000" not in out and "extern f32 g_other;  /* another file's */" in out
    assert "/* half and a third */" in out  # (the comment after a declaration stays)
    assert "    extern" not in out  # (a function's own declaration of it went too)


def test_whats_not_a_files_own_plain_constant_stays():
    text = ("extern f32 a, b, c, d;\nextern f64 conv;\n"
            "void f(f32 *p) {\n    *p = a + b + c + d + (f32)conv;\n    p = &a;\n    b = 1.0f;\n}\n")
    own = cleanup.own_constants(text, {**held(a=(1.0, 4), b=(2.0, 4), d=(4.0, 4)),
                                    "c": (struct.pack(">f", 3.0) + bytes(12), 16, False),  # a vector's head
                                    "conv": (bytes.fromhex("4330000080000000"), 8, False)})  # an int's conversion
    assert own == {"d": "4.0f"}  # (a's address is taken, b is written, c is a vector, conv the compiler's)
    out = cleanup.with_literals(text, own)
    assert "extern f32 a, b, c;" in out and "+ 4.0f +" in out, out


def test_a_constant_the_compiler_would_fold_is_a_local_variable_instead():
    text = "extern f32 zero;\n\nf32 spin(f32 direction) {\n    f32 x;\n    x = direction * zero;\n    return x;\n}\n"
    out = cleanup.with_literals(text, {"zero": "0.0f"}, local={"zero"})
    assert out.startswith("\nf32 spin(f32 direction) {\n    f32 zero = 0.0f;\n    f32 x;"), out
    assert "direction * zero" in out


def test_a_negative_literal_after_a_minus_keeps_its_meaning():
    out = cleanup.with_literals("extern f32 m;\nf32 f(f32 x) {\n    return x - m;\n}\n", {"m": "-1.0f"})
    assert "return x - (-1.0f);" in out, out


def test_literals_are_the_shortest_that_give_the_same_bytes():
    def lit(v, width):
        return cleanup.literal(struct.pack(">f" if width == 4 else ">d", v), width)

    assert [lit(90.0, 4), lit(57.29578, 4), lit(1e-7, 4), lit(0.1, 8), lit(-0.0, 4)] == \
        ["90.0f", "57.29578f", "1.0e-07f", "0.1", "-0.0f"]
    assert cleanup.literal(struct.pack(">f", float("nan")), 4) is None


def test_declarations_nothing_uses_go_and_the_rest_stay():
    text = ("extern int used, unused;\nextern u8 table[];\nvoid helper(int a);\nint Called(void);\n"
            "static ApploaderHeader Header ATTRIBUTE_ALIGN(32);\n#define CALL(x) go(x);\n"
            "typedef void (*Fn)(int);\nextern void (*callback)(void);\n"
            "int f(void) {\n    extern int local;\n    return used + Called();\n}\n")
    out, gone = cleanup.without_unused(text)
    assert gone == ["helper", "table", "unused"], gone
    assert "extern int used;" in out and "int Called(void);" in out and "ATTRIBUTE_ALIGN(32);" in out
    assert "#define CALL(x) go(x);" in out and "typedef void (*Fn)(int);" in out and "(*callback)" in out
    assert "extern int local;" in out  # (inside a function: its own business)
    assert cleanup.without_unused(out) == (out, [])
