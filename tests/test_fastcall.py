"""A Visual C++ game built with /Gr written as its developers wrote it (consoles/pc/fastcall.py)."""

from decompnet.consoles.pc import fastcall

SOURCE = '''#include "common.h"
#pragma optimize("", off)
extern "C" void memCopy(void* dst, void* src, int size);
extern "C" void __fastcall draw_ui_quad(int sprite, float x, float y);
extern void (*g_callback)(int);
typedef int (__fastcall *Handler)(int);
static int __cdecl compare(const void* a, const void* b) { return 0; }
int S::method(int x) { return x; }
void __fastcall update(Hint* self)
{
    int (*fn)(int) = 0;
    draw_ui_quad(0x379, self->x, self->y);
}
#pragma optimize("", on)
'''


def test_fastcall_is_the_default_and_what_had_none_says_cdecl():
    """/Gr: __fastcall goes (the default), what had no convention says __cdecl (as it was), methods and conventions
    said otherwise stay; the file's #pragma optimize lines go (its flags say /Od)."""
    out = fastcall.convert(SOURCE)
    assert "__fastcall" not in out and "#pragma optimize" not in out
    assert 'extern "C" void __cdecl memCopy(void* dst' in out
    assert 'extern "C" void draw_ui_quad(int sprite' in out and "void update(Hint* self)" in out
    assert "extern void (__cdecl *g_callback)(int);" in out and "typedef int (*Handler)(int);" in out
    assert "static int __cdecl compare(" in out and "int S::method(int x)" in out
    assert "int (__cdecl *fn)(int) = 0;" in out and "draw_ui_quad(0x379, self->x, self->y);" in out
    # a header is included by files built without /Gr too: it only gets its __cdecl
    header = fastcall.convert(SOURCE, header=True)
    assert "void __fastcall draw_ui_quad" in header and "void __cdecl memCopy" in header
    assert '#pragma optimize("", off)' in header


def test_the_conventions_a_file_defines_its_functions_with():
    """What says a game was built with /Gr: its own files define most functions __fastcall."""
    assert fastcall.conventions(SOURCE) == {"__cdecl": 1, "__fastcall": 1}
