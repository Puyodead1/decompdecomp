"""The SDK's own inline functions, read from a header as the console's compiler reads it (kits/inlines.py)."""

from decompnet.kits import inlines

HEADER = """
#ifndef __CASTS_H__
#define __CASTS_H__
#define CAST_U8  0x0004
#define CAST_U16 CAST_U8 + 1   /* a macro of a macro */
#define CAST_OF(x) ((x) << 16) /* function-like: left as it is */
#if defined(GEKKO) && !defined(EMU)
// the console's own
static inline void InitCasts ( void )
{
#ifdef __SN__
    asm volatile ("li 3, 4");
#elif 0
    nope();
#else
    asm
    {
        li      r3, CAST_U8
        oris    r3, r3, CAST_U16
        mtspr   GQR2, r3
    }
#endif
}
static inline int Twice(int x) { return x * 2; }
#else
static inline void InitCasts ( void ) { while (0) {} }
#endif
#endif
"""


def test_the_consoles_branch_of_a_header_with_its_macros_put_in():
    got = inlines.definition(HEADER, "InitCasts", ("GEKKO", "__MWERKS__"))
    assert got.startswith("static inline void InitCasts ( void )")
    assert "li      r3, 0x0004" in got and "oris    r3, r3, 0x0004 + 1" in got and "mtspr   GQR2, r3" in got
    assert "volatile" not in got and "nope" not in got and "while (0)" not in got and "//" not in got
    assert inlines.definition(HEADER, "Twice", ("GEKKO",)) == "static inline int Twice(int x) { return x * 2; }"


def test_another_compilers_branch_and_names_no_header_defines():
    assert "while (0)" in inlines.definition(HEADER, "InitCasts", ())  # (a PC build's)
    assert "asm volatile" in inlines.definition(HEADER, "InitCasts", ("GEKKO", "__SN__"))
    assert inlines.definition(HEADER, "CAST_OF", ("GEKKO",)) is None  # (a macro isn't a function)
    assert inlines.definition(HEADER, "Missing", ("GEKKO",)) is None
