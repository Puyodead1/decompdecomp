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
    # C matched without the shared header can't be in a file that starts with it
    alone = units.merge([("f", "int f(void) { return 0; }\n"),
                         ("g", "#pragma decompdecomp no_context\n#include <math.h>\ndouble g(void) { return exp(1); }\n")],
                        "common.h")
    assert alone.c is None and "no_context" in alone.problem


def test_a_functions_file_keeps_only_its_own_definition_of_the_programs_functions():
    """A Linux program: an agent's C for one function defined three more of its file; the judge compares only the
    function judged, and the export defined them twice, one of them never judged ("undefined reference to `sin'")."""
    src = ("double sin(double x);\n\nvoid set_volume(int v)\n{\n    level = v;\n}\n\n"
           "/* a copy */\nfloat wobble(float a, int n)\n{\n    return a * sin(n);\n}\n\n"
           "static int helper(int x)\n{\n    return x + 1;\n}\n")
    out = units.only_own(src, "set_volume", {"set_volume", "wobble", "other"})
    assert "void set_volume(int v)\n{" in out and "return a * sin(n)" not in out
    assert "float wobble(float a, int n);" in out  # (its prototype, for a call)
    assert "static int helper(int x)\n{" in out  # (C of its own: no file of the program's defines it)
    assert units.only_own(src, "set_volume", {"set_volume"}) == src


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


def test_a_functions_locals_as_its_c_declares_them_and_as_the_debug_information_lists_them():
    """A 2001 Linux program's last open functions were each a variable off the game's (extern globals that were the
    function's own statics, a function pointer left out, a tool's temporaries kept in) while every agent took the
    rest for the compiler's: what a function's C declares, and what its debug information lists, side by side."""
    src = ("int f(int a)\n{\n    int i, *p = q, (*rd)();\n    static float x;\n    unsigned char c;\n"
           "    format = 0;\n    i = a * b;\n    g(x);\n    for (i = 0; i < 3; i++) {\n        int tmp = i;\n    }\n"
           "    return i;\n}\n")
    assert units.declared_locals(src, "f") == {"i", "p", "rd", "x", "c", "tmp"}
    assert units.declared_locals(src, "g") is None
    assert units.debug_local_names([
        "int width (the stack, frame offset -0x44, declared on line 251)", "int (*myfread)() (the stack, frame "
        "offset -0x78, declared on line 267)", "float xmin (static, declared on line 98)", "char ch[64] (the stack, "
        "frame offset -0x47c, declared on line 653)", "double __result (register 11, declared on line 445)",
        "float vi (st(1), declared on line 81)", "int k (ebx, declared on line 139)"]) == \
        {"width", "myfread", "xmin", "ch", "vi", "k"}


def test_a_function_not_matched_yet_is_the_c_you_chose_in_the_plain_build(tmp_path):
    """A function no C matches yet is its assembly in its file; the C the user chose for it (Network.set_plain) is
    beside it, `#ifdef NON_MATCHING`, so the plain build compiles C and the matching build the game's code. The
    export takes that C out again (without_plain) where the plain build can't compile it, even with #ifs its passes
    put inside it."""
    import shutil
    import subprocess

    from decompnet.consoles.linux.export import without_plain

    asm = ".globl near\n.type near,@function\nnear:\n\tmovl $2, %eax\n\tret\n"
    funcs = [("first", "int first(void) { return 1; }\n"), ("near", ""), ("last", "int last(void) { return 3; }\n")]
    plain_c = "#ifdef NON_MATCHING\nint near(void) { return 2; }\n#else\nint near(void) { return 0; }\n#endif\n"
    alone = units.merge(funcs, "common.h", asm_pieces={"near": asm}).c
    both = units.merge(funcs, "common.h", asm_pieces={"near": asm}, plain={"near": plain_c}).c
    assert "#ifdef NON_MATCHING\n/* near doesn't match yet" in both and "int near(void) { return 2; }" in both
    assert (both.index("int first(void) {") < both.index("#ifdef NON_MATCHING") < both.index('"near:\\n"')
            < both.index("int last(void) {"))
    assert without_plain(both) == alone and without_plain(both, {"other"}) == both
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    (tmp_path / "common.h").write_text("")
    for defines, want in ((["-DNON_MATCHING"], 2), ([], 2)):
        (tmp_path / "f.c").write_text(both + "int main(void) { return near(); }\n")
        built = subprocess.run(["gcc", *defines, "-o", "f", "f.c"], cwd=tmp_path, capture_output=True, text=True)
        if built.returncode:
            pytest.skip(f"this gcc doesn't build it: {built.stderr[:200]}")
        assert subprocess.run([str(tmp_path / "f")]).returncode == want
