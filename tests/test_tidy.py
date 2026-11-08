"""ROM mode's tidy: the declarations matched functions make for themselves, moved into the shared header (tidy.py)."""

from decompnet import tidy

HEADER = """typedef struct { int x; } TObject;
void obInit(TObject *);
extern int g_frame;
"""


def _fn(i, unit, source):
    return {"id": i, "name": f"f{i}", "unit": unit, "matched_source": source}


def test_a_functions_file_scope_declarations_are_read_and_its_definitions_are_not():
    source = """#include "common.h"
#define WAVES 20
extern void *malloc(unsigned int size);
extern int a, *b;
static int counter;
int g_defined;
typedef struct { short pts; short dmg; } TPtsDmg __attribute__((packed));
struct Node { struct Node *next; };
void renOOWTV(count, lookup)
ushort count;
ushort *lookup;
{
  int x;
}
static inline int helper(int v) { return v; }
int f(void) { return a; }
extern int after;
"""
    found = {item.names: item.kind for item in tidy.items(source)}
    assert found == {("malloc",): "extern", ("a", "b"): "extern", ("TPtsDmg",): "type", ("struct Node",): "type",
                     ("after",): "extern"}
    # (parameter names and `extern` say nothing of a declaration's type)
    assert tidy._key("extern void *malloc(unsigned int size);") == tidy._key("void *malloc(unsigned int);")


def test_what_every_function_declares_alike_moves_and_what_they_disagree_on_stays_with_the_others():
    functions = [
        _fn(1, "a.c", "extern void obInit(TObject *);\nextern void sndPlay(int);\nextern int hits;\nvoid f1(void) {}\n"),
        _fn(2, "a.c", "extern void sndPlay(int id);\nextern short hits;\nvoid f2(void) {}\n"),
        _fn(3, "b.c", "extern void sndPlay(int);\nextern int hits;\n#define N 4\nextern int table[N];\n"
                      "typedef struct { int v; } Local;\nextern Local *cur;\nvoid f3(void) {}\n"),
    ]
    plan = tidy.plan(functions, HEADER)
    moved = {name for _, item in plan.moved for name in item.names}
    # the header's own `void obInit(TObject *);` is dropped from f1; sndPlay moves (three alike); `int hits` is the
    # most common, so it moves and f2 keeps its `short`; table needs f3's macro and stays; Local and cur move
    assert moved == {"sndPlay", "hits", "Local", "cur"}
    assert "obInit" not in plan.sources[1] and "sndPlay" not in plan.sources[1]
    assert "extern short hits;" in plan.sources[2]
    assert "extern int table[N];" in plan.sources[3] and "#define N 4" in plan.sources[3]
    header = plan.header(HEADER)
    assert header.index("Local;") < header.index("Local *cur;")  # (types before the externs using them)
    assert "/* a.c */" in header and "/* b.c */" in header
    # a name a function needed its own copy of stays where it is, everywhere
    assert "sndPlay" not in {n for _, item in tidy.plan(functions, HEADER, keep={"sndPlay"}).moved for n in item.names}


def test_a_matched_functions_prototype_moves_only_as_its_definition_has_it():
    """Its callers agreed on `void auditInit();` where it is `int auditInit(void)`: with that in the header, it no
    longer compiled (525 functions of a Linux game, round after round)."""
    functions = [_fn(1, "a.c", "int f1(void)\n{\n    return 0;\n}\n"),
                 _fn(2, "a.c", "extern void f1();\nvoid f2(void) {}\n"),
                 _fn(3, "a.c", "extern void f1();\nvoid f3(void) {}\n")]
    assert not tidy.plan(functions, HEADER).moved
    for f in functions[1:]:
        f["matched_source"] = f["matched_source"].replace("extern void f1();", "extern int f1(void);")
    assert [item.names for _, item in tidy.plan(functions, HEADER).moved] == [("f1",)]
