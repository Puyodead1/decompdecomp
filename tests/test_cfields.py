"""cfields: the struct fields a header declares by offset, and the offset reads in a function's C they name."""

from decompnet import cfields

DEBUG_HEADER = """
struct SLODGeometry { /* 0xC bytes */
    TGeometry *geometries; /* 0x0 */
    float *switchDist; /* 0x4 */
    int nLevels; /* 0x8 */
};
typedef struct SLODGeometry TLODGeometry;
typedef unsigned short ushort;
struct SModel { /* 0x48 bytes */
    TPFNMdAttach Attach; /* 0x0 */
    float radius; /* 0x1C */
    ushort nJoints; /* 0x2C */
    TLODGeometry *Geometries; /* 0x40 */
    TSkin *Skins; /* 0x44 */
};
typedef struct SModel TModel;
"""

GUESSED_HEADER = """
typedef struct {
    char pad_0000[0x44];
    u32 flags_0x44;
    void (*callback)(int, int);
    struct V3f pos;
    double when;
    int after_when;
} S_00731780;
struct V3f { float x; float y; float z; };
union U { int i; float f; };
"""

MAX_RENDER = """
void hacked_up_maxRender2(TModel *pModel, TObject *pObj)
{
    TGeometry *pGeo;
    pGeo = (TGeometry *)((*(char ***)((char *)pModel + 0x40))[pObj->Geometry * 3] + lod * 0x40);
    x = *(ushort *)((char *)pModel + 0x2c) + *(int *)((char *)pObj + 8) + *(int *)((char *)pModel + 0x41);
}
"""


def test_a_read_through_a_byte_pointer_is_named_by_the_headers_offset_comments():
    """A 2000s Linux game's polished C kept `*(char ***)((char *)pModel + 0x40)` for pModel->Geometries."""
    lines = cfields.named_reads(MAX_RENDER, DEBUG_HEADER)
    assert lines == ["- `*(char ***)((char *)pModel + 0x40)` is pModel->Geometries (TLODGeometry *)",
                     "- `*(ushort *)((char *)pModel + 0x2c)` is pModel->nJoints (ushort)"]
    # (pObj's type isn't in the header, and 0x41 is inside a pointer: neither is named)


def test_offsets_without_comments_come_from_sizes_until_an_alignment_compilers_disagree_on():
    header = cfields.Header(GUESSED_HEADER)
    assert header.name_read("S_00731780", 0x44) == ("->flags_0x44", "u32")
    assert header.name_read("S_00731780", 0x48) == ("->callback", "void *")
    assert header.name_read("S_00731780", 0x50) == ("->pos.y", "float")
    assert header.name_read("S_00731780", 0x4) == ("->pad_0000[4]", "char")
    assert header.name_read("S_00731780", 0x58) is None  # (a double: 0x58 for GCC on x86, 0x58 or 0x60 for MSVC)
    assert header.name_read("S_00731780", 0x60) is None
    assert header.name_read("U", 0) in (("->i", "int"), ("->f", "float"))


def test_a_read_through_a_variable_that_isnt_a_struct_pointer_isnt_named():
    source = "int f(int tex) { return *(unsigned int *)((char *)tex + 0x2c); }"
    assert cfields.named_reads(source, DEBUG_HEADER) == []
    source = "int f(TModel *m) { return *(int *)((short *)m + 0x2); }"  # (not a byte pointer: scaled)
    assert cfields.named_reads(source, DEBUG_HEADER) == []
