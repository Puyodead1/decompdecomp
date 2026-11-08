"""A source file made again from its matched functions, as one C file (units.py)."""

import pytest

from decompnet import units
from decompnet.rom.export import CONTEXT_INCLUDE

FUNCTIONS = [
    ("auditOpen", "extern void *hit_audits;\nvoid *malloc(unsigned int size);\nstatic int hit_front;\n\n"
                  "/* Opens the log. */\nint auditOpen(void)\n{\n    hit_front = 0;\n    hit_audits = malloc(32000);\n"
                  "    return hit_audits != 0;\n}\n"),
    ("auditHit", "typedef struct { int frame; } THit;\nextern THit *hit_audits;\nstatic int hit_front;\n"
                 "void *malloc(unsigned int);\nstatic void auditFlush(void);\n"
                 "void auditHit(int frame)\n{\n    if (hit_audits) {\n        hit_audits[hit_front++].frame = frame;\n"
                 "        auditFlush();\n    }\n}\n"),
    ("auditFlush", '#include "context.h"\n#define LIMIT 999\ntypedef struct { short frame; } THit;\n'
                   "static int hit_front;\nstatic void auditFlush(void)\n{\n    if (hit_front > LIMIT) hit_front = LIMIT;\n}\n"
                   "int other_file(int x)\n{\n    return x + 1;\n}\n"),
    ("auditOld", "int auditOld(a, b)\nint a;\nchar *b;\n{\n    return other_file(a) + auditOpen();\n}\n"),
]


def test_a_files_functions_are_one_c_file_with_each_declaration_once():
    """What the functions agree on is written once (a global's extern in the file's header, a static in the file);
    a guess two of them make differently is each one's, inside it; a struct two define differently is renamed in
    the one that differs; the file's functions are declared as their definitions have them; a function of another
    file one of them carried is only declared."""
    merged = units.merge(FUNCTIONS, "common.h", "audit.h", CONTEXT_INCLUDE)
    assert merged.c is not None, merged.problem
    c, header = merged.c, merged.header
    assert c.startswith('#include "common.h"\n') and '#include "audit.h"' in c and "context.h" not in c
    assert c.count("static int hit_front;") == 1
    # two guesses at hit_audits: the first of the most common is the file's; the other is auditHit's own
    # declaration of the same symbol under its own name, which GCC 2.95 and a newer GCC both take
    assert merged.scoped == ["hit_audits", "other_file"]
    assert "extern void *hit_audits;" in header and "hit_audits = malloc(32000);" in c
    assert 'extern THit *hit_audits__auditHit __asm__("hit_audits");' in c
    assert "if (hit_audits__auditHit) {" in c
    # THit: auditHit's and auditFlush's differ, so auditFlush's is its own
    assert "typedef struct { int frame; } THit;" in c and "typedef struct { short frame; } THit_auditFlush;" in c
    # the file's own functions as defined, the static one static, a K&R one without its parameters
    assert "int auditOpen(void);" in header and "void auditHit(int frame);" in header and "int auditOld();" in header
    assert "static void auditFlush(void);" in c and "auditFlush" not in header
    assert "void *malloc(unsigned int size);" in header and header.count("malloc") == 1
    # other_file is another file's: declared, not defined again; auditOld calls it undeclared (as it was compiled)
    assert "int other_file(int x);" in header and "return x + 1" not in c
    assert 'extern int other_file__auditOld() __asm__("other_file");' in c and "other_file__auditOld(a)" in c
    assert "#define LIMIT 999" in c and "/* Opens the log. */\nint auditOpen(void)" in c
    # in the order the file has them
    assert c.index("int auditOpen(void)\n{") < c.index("void auditHit(int frame)\n{") < c.index("auditFlush(void)\n{")


def test_what_cant_be_one_file_says_why():
    two = [("f", "static int n;\nint f(void) { return n; }\n"), ("g", "static short n;\nint g(void) { return n; }\n")]
    merged = units.merge(two, "common.h", "x.h")
    assert merged.c is None and "n" in merged.problem
    assert "once" in units.merge([("f", "int g(void) { return 0; }\n")], "common.h").problem


def test_a_macro_two_functions_define_differently_is_each_ones():
    two = [("f", "#define N 4\nint f(void) { return N; }\n"), ("g", "#define N 8\nint g(void) { return N; }\n")]
    c = units.merge(two, "common.h").c
    assert c.count("#undef N") == 2 and c.index("#define N 4") < c.index("int f(void) {") < c.index("#define N 8")


def test_a_prototype_with_an_attribute_after_it_is_a_declaration():
    """`extern void exit(int) __attribute__((noreturn));` isn't an old-style definition's head; a constructor's
    declaration keeps what it says."""
    found = units.chunks("extern void exit(int) __attribute__((noreturn));\nextern void (*table[])(void);\n"
                         "void setup(void) __attribute__((constructor));\nvoid setup(void) { }\n")
    assert [(c.kind, c.names) for c in found] == [("extern", ("exit",)), ("extern", ("table",)),
                                                  ("extern", ("setup",)), ("func", ("setup",))]
    c = units.merge([("setup", "void setup(void) __attribute__((constructor));\nvoid setup(void) { }\n")], "c.h").c
    assert "__attribute__((constructor))" in c


def test_the_merged_file_compiles_with_the_programs_gcc(tmp_path):
    from decompnet import toolchains
    from decompnet.compiler import compile_source
    from decompnet.project import compiler_config

    if toolchains.installed("gcc-2.95.3-linux") is None:
        pytest.skip("needs gcc-2.95.3-linux")
    merged = units.merge(FUNCTIONS, "common.h", "audit.h", CONTEXT_INCLUDE)
    text = merged.c.replace('#include "common.h"\n', "").replace('#include "audit.h"\n', merged.header)
    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": "gcc-2.95.3-linux", "flags": ["-O2"]}})
    res = compile_source(cfg, "", text, trusted=True)
    assert res.ok, res.log
    # and a newer GCC takes it too (`make port`): no name with two types in one file
    import shutil
    import subprocess

    gcc = shutil.which("gcc")
    if gcc:
        (tmp_path / "audit.c").write_text(text)
        res = subprocess.run([gcc, "-std=gnu89", "-fsyntax-only", "-w", str(tmp_path / "audit.c")],
                             capture_output=True, text=True)
        assert res.returncode == 0, res.stderr


def test_a_files_data_is_defined_where_the_file_had_it_and_its_functions_guesses_read_it():
    """The file's variables (export_data.py) go before the first function after them; a function's own definition of
    one goes, a function that declared it as the definition has it (or `(void)` for `()`) needs nothing, and one that
    guessed another type reads it under its own name for the same symbol."""
    functions = [("first", "static int count;\nint first(void) { return count; }\n"),
                 ("second", "extern int (*hook)(void);\nint second(void) { return hook(); }\n"),
                 ("third", "extern char *hook;\nint third(void) { return *hook; }\n")]
    merged = units.merge(functions, "common.h", None, own_data={"count": "int count;", "hook": "int (*hook)();"},
                         forward="static int count;\nextern int (*hook)();\n",
                         placed=[(15, "int (*hook)() = 0;"), (5, "static int count = 3;")],
                         func_lines={"first": 10, "second": 20, "third": 30})
    c = merged.c
    assert c.count("static int count = 3;") == 1 and "static int count;\nint first" not in c
    assert c.index("static int count = 3;") < c.index("int first(void) {") < c.index("int (*hook)() = 0;") < \
        c.index("int second(void) {")
    assert "hook__second" not in c  # (its `int (*hook)(void)` is the definition's type)
    assert 'extern char *hook__third __asm__("hook");' in c and "return *hook__third;" in c


def test_a_function_that_returned_what_was_left_in_eax_returns_it():
    """GCC 2.95 left a call's value in %eax at the end of a function that never returned it (a texture's id), so
    the game got it; a newer GCC doesn't: the function's last expression returned, where its type isn't void."""
    from decompnet.units import returned

    src = "int texInit(char *name, long flags)\n{\n    if (x) { y(); }\n    load(fix, 0);     /* dropped */\n}\n"
    assert "    return load(fix, 0);" in returned(src, "texInit")
    assert returned("void *f(void) { g(); }\n", "f") == "void *f(void) { return g(); }\n"
    for kept in ("void f(void) { g(); }\n", "int f(void) { return g(); }\n", "int f(void) { if (a) { g(); } }\n",
                 "int f(void) { out: g(); }\n", "int f(void) { int x; }\n", "int f(void) { }\n"):
        assert returned(kept, "f") is None, kept
