import shutil
import sys
from pathlib import Path

import pytest

from decompnet.compiler import SourceRejected, check_source
from decompnet.network import Network, NetworkError

from .handmade import import_project
from .solutions import SOLUTIONS, WRONG_CLAMP

DEMO = Path(__file__).resolve().parent.parent / "projects" / "demo"
# projects/demo is a toy x86-64 game built with the computer's own gcc into ELF objects: Linux only
HOST_GCC = sys.platform == "linux" and shutil.which("gcc") is not None
needs_host_gcc = pytest.mark.skipif(not HOST_GCC, reason="projects/demo needs a Linux gcc (x86-64 ELF)")


@pytest.fixture
def net(tmp_path):
    if not HOST_GCC:
        pytest.skip(needs_host_gcc.kwargs["reason"])
    n = Network(tmp_path / "test.db")
    import_project(n.store, DEMO, log=lambda *_: None)
    return n


@pytest.fixture
def agents(net):
    a = net.authenticate(net.register_agent("alice-claude", "alice"))
    b = net.authenticate(net.register_agent("bob-claude", "bob"))
    return a, b


def status_of(net, name):
    return net.store.one("SELECT status FROM functions WHERE name=?", name)["status"]


def test_check_source_blocks_cheats():
    for bad in ['void f(void){ asm("nop"); }', "#pragma GLOBAL_ASM(\"x.s\")", "#include <stdio.h>",
                'INCLUDE_ASM("asm", f);', '#include "../../etc/passwd"', "void f(void){ __asm__ volatile(\"\"); }"]:
        with pytest.raises(SourceRejected):
            check_source(bad)
    check_source('// this used to be asm\nint f(void) { const char *s = "asm"; return 0; }')


def test_a_compiler_with_its_systems_headers_lets_c_include_them():
    """A Linux game's outb() came from glibc's <sys/io.h> (inline asm, the system's): its compiler ships those
    headers, pinned, so C may include them. Its own asm, and paths out of the sandbox, stay refused."""
    from decompnet import toolchains

    check_source("#include <sys/io.h>\nvoid f(void) { outb(1, 0x37c); }", system_headers=True)
    for bad in ['void f(void){ __asm__("out %al, %dx"); }', "#include <../../etc/passwd>"]:
        with pytest.raises(SourceRejected):
            check_source(bad, system_headers=True)
    assert toolchains.get("gcc-2.95.3-linux").system_headers and not toolchains.get("gcc-2.7.2-kmc").system_headers


def test_the_shared_header_takes_no_new_asm(net, agents):
    """Agents on a Linux game put x87 instructions in the header as inline functions their C called: the header is
    compiled unchecked with every function, so an edit may not add asm (keeping what it has is fine)."""
    alice, _ = agents
    with pytest.raises(NetworkError, match="inline assembly is not allowed"):
        net.edit_context(alice, "demo", "", 'static inline double q(double x) { __asm__("fsqrt" : "+t"(x)); return x; }',
                         "fast sqrt")
    from decompnet.compiler import added_asm

    assert added_asm('__asm__("frndint" : "+t"(v)); int a;', '__asm__("frndint" : "+t"(v)); int b;') is None


def test_every_solution_matches(net, agents):
    alice, _ = agents
    for name, src in SOLUTIONS.items():
        out = net.compile_and_diff(alice, name, src)
        assert "MATCH" in out, f"{name}:\n{out}"
        assert status_of(net, name) == "matched"


def test_wrong_attempt_gets_scored_diff(net, agents):
    alice, _ = agents
    out = net.compile_and_diff(alice, "clamp_s32", WRONG_CLAMP)
    assert out.startswith("score ")
    assert "TARGET" in out and "YOURS" in out
    assert status_of(net, "clamp_s32") == "open"
    assert net.store.one("SELECT best_score FROM functions WHERE name='clamp_s32'")["best_score"] > 0


def test_compile_error_and_rejection_are_reported(net, agents):
    alice, _ = agents
    assert "COMPILE ERROR" in net.compile_and_diff(alice, "abs_s32", "s32 abs_s32(s32 v) { return v +; }")
    assert "inline assembly" in net.compile_and_diff(alice, "abs_s32", 's32 abs_s32(s32 v) { asm("nop"); return v; }')
    assert "no function named" in net.compile_and_diff(alice, "abs_s32", "s32 other(s32 v) { return v; }")


def test_claims_are_exclusive_and_scheduler_spreads_work(net, agents):
    alice, bob = agents
    a = net.claim(alice)
    b = net.claim(bob)
    fa = a.splitlines()[0].split("/")[-1]
    fb = b.splitlines()[0].split("/")[-1]
    assert fa != fb
    assert fa == "abs_s32"  # easiest first
    with pytest.raises(NetworkError, match="claimed by alice-claude"):
        net.compile_and_diff(bob, fa, SOLUTIONS["abs_s32"])
    with pytest.raises(NetworkError, match="you already hold"):
        net.claim(bob, function=fa)
    net.release(bob, fb, "")
    with pytest.raises(NetworkError, match="claimed by alice-claude"):
        net.claim(bob, function=fa)
    # holding a claim: asking again returns the same function
    assert net.claim(alice).splitlines()[0] == a.splitlines()[0]


def test_release_hands_off_best_attempt_and_notes(net, agents):
    alice, bob = agents
    net.compile_and_diff(alice, "clamp_s32", WRONG_CLAMP)
    net.release(alice, "clamp_s32", "branch order is hi-first in my try; target checks lo first (signed jl)")
    brief = net.claim(bob, function="clamp_s32")
    assert "Best attempt so far" in brief and "(u32)v" in brief
    assert "target checks lo first" in brief
    assert "MATCH" in net.compile_and_diff(bob, "clamp_s32", SOLUTIONS["clamp_s32"])


@needs_host_gcc
def test_expired_claims_are_reclaimable(tmp_path):
    net = Network(tmp_path / "t.db", claim_ttl=-1)  # every claim is born expired
    import_project(net.store, DEMO, log=lambda *_: None)
    alice = net.authenticate(net.register_agent("a"))
    bob = net.authenticate(net.register_agent("b"))
    net.claim(alice, function="abs_s32")
    assert "MATCH" in net.compile_and_diff(bob, "abs_s32", SOLUTIONS["abs_s32"])


def test_context_edits_are_regression_tested(net, agents):
    alice, _ = agents
    net.compile_and_diff(alice, "player_take_damage", SOLUTIONS["player_take_damage"])
    net.compile_and_diff(alice, "entity_update_physics", SOLUTIONS["entity_update_physics"])

    # Changing the Entity layout would silently break matched code -> rejected
    out = net.edit_context(alice, "demo", "/* 0x04 */ s32 x;", "/* 0x04 */ s16 x;", "x is s16?")
    assert "REJECTED" in out and "entity_update_physics" in out
    assert "version 1" in net.get_context("demo")

    # Adding a prototype is safe -> accepted
    out = net.edit_context(alice, "demo", "", "s32 entity_default_hp(s16 type);", "add proto")
    assert "now v2" in out

    # Renaming a field rewrites matched sources too, and they keep matching
    out = net.rename_symbol(alice, "demo", "unk_1C", "hp", "player hp")
    assert "renamed" in out, out
    assert "g_player.hp" in net.store.one("SELECT matched_source FROM functions WHERE name='player_take_damage'")[0]
    assert "s32 hp;" in net.get_context("demo")


def test_scratch_compiles_on_matched_functions_give_no_credit(net, agents):
    alice, bob = agents
    net.compile_and_diff(alice, "abs_s32", SOLUTIONS["abs_s32"])
    out = net.compile_and_diff(bob, "abs_s32", SOLUTIONS["abs_s32"])
    assert "scratch" in out
    row = net.store.one("SELECT a.name FROM functions f JOIN agents a ON a.id=f.matched_agent_id WHERE f.name='abs_s32'")
    assert row["name"] == "alice-claude"


def test_auth(net):
    with pytest.raises(NetworkError):
        net.authenticate("dn_nope")
    with pytest.raises(NetworkError):
        net.register_agent("bad name!")


def test_removing_a_project_removes_everything_in_it(net, agents):
    alice, bob = agents
    net.compile_and_diff(alice, "abs_s32", SOLUTIONS["abs_s32"])
    net.add_note(alice, "demo", "abs is a branchless cmov", "abs_s32")
    net.add_note(bob, "demo", "project-wide tip")
    net.claim(bob)
    assert net.remove_project("demo") == 13
    for table in ("projects", "functions", "attempts", "notes", "events", "context_versions"):
        assert net.store.one(f"SELECT COUNT(*) AS n FROM {table}")["n"] == 0, table


def test_give_ups_are_recounted_once_without_decomp_wtfs_own_expiries(tmp_path):
    """Before 0.10.4 the autopilot's leftover claims counted as agents giving up (see test_forks): opening the
    database counts each function's give-ups again from releases and agents' own expired claims."""
    import sqlite3

    from decompnet.store import Store

    path = tmp_path / "old.db"
    Store(path)
    db = sqlite3.connect(path)
    db.execute("DELETE FROM settings WHERE key='abandons_recounted'")  # a database from before
    db.execute("INSERT INTO agents(id,name,token_hash,created_at) VALUES(1,'autopilot','x',0),(2,'claude-1','y',0)")
    db.execute("INSERT INTO projects(id,slug,root,config) VALUES(1,'p','/','{}')")
    db.execute("INSERT INTO functions(project_id,name,abandons) VALUES(1,'f',5),(1,'g',3)")
    for agent, kind, fn in [(1, "expired", "f"), (1, "expired", "f"), (2, "release", "f"), (1, "expired", "g"),
                            (2, "expired", "g"), (2, "release", "g")]:
        db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(1,?,?,?,0)", (agent, kind, fn))
    db.commit()
    db.close()
    store = Store(path)
    assert {r["name"]: r["abandons"] for r in store.all("SELECT name, abandons FROM functions")} == {"f": 1, "g": 2}
    with store.tx() as tx:
        tx.execute("UPDATE functions SET abandons=7 WHERE name='f'")
    assert Store(path).one("SELECT abandons FROM functions WHERE name='f'")["abandons"] == 7  # once only


def test_big_functions_get_more_compiles_before_the_nudge_to_move_on(net, agents):
    alice, _ = agents
    fn = net.store.one("SELECT id FROM functions WHERE name='clamp_s32'")
    with net.store.tx() as db:
        for score in (50, 60, 60, 70, 80, 90, 95):
            db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,source,created_at) VALUES(?,?,?,?,?,?)",
                       (fn["id"], alice.id, score, 1, "x", 0))
    from decompnet.network import stall_budget

    small = stall_budget(net.store.one("SELECT n_insns FROM functions WHERE id=?", fn["id"])["n_insns"])
    assert small < 6
    assert f"⏭ Move on: no better in 6/{small} compiles (move on at {small})" in net.stall_note(fn["id"], alice.id)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET n_insns=300 WHERE id=?", (fn["id"],))
    # a big one: not before 10, and every result still says where it stands
    assert net.stall_note(fn["id"], alice.id).strip() == "Move-on count: no better in 6/10 compiles (move on at 10)."


def test_the_guide_gives_the_compile_budget_compile_and_diff_keeps():
    """The guide said "stuck after ~20 compiles" while compile_and_diff nudged after 4; later the prompt said "3 ... up
    to 10" and agents guessed which number was theirs. The prompt and guides now point at the function's own number,
    which the brief names."""
    from decompnet import network
    from decompnet.app import tools

    said = network.stall_budget_text()
    assert said in " ".join(tools.guide_text("workflow").split())
    assert "up to 10" not in said and "move on at" in said
    for topic in ("workflow", "fork", "similarity"):
        assert "3 compiles in a row" not in " ".join(tools.guide_text(topic).split()), topic
    assert network.stall_budget(1000) == network.STALL_BUDGET_BIGGEST
    fn = {"n_insns": 100}
    assert f"move on after {network.stall_budget(100)} compiles in a row" in network.move_on_brief(fn)


def test_a_transaction_inside_another_joins_it(tmp_path):
    """The room's sync saves hundreds of the host's matches and notes in one transaction: each function that saves
    one opens its own, which used to be an error and now commits (or rolls back) with the outer one."""
    from decompnet.store import Store

    store = Store(tmp_path / "s.db")
    with store.tx() as db:
        db.execute("INSERT INTO settings(key, value) VALUES('a', '1')")
        with store.tx() as inner:
            inner.execute("INSERT INTO settings(key, value) VALUES('b', '2')")
        assert store.one("SELECT 1 FROM settings WHERE key='b'")  # seen from inside, not yet committed
    assert store.one("SELECT COUNT(*) AS n FROM settings WHERE key IN ('a', 'b')")["n"] == 2
    with pytest.raises(RuntimeError):
        with store.tx() as db:
            db.execute("INSERT INTO settings(key, value) VALUES('c', '3')")
            with store.tx() as inner:
                inner.execute("INSERT INTO settings(key, value) VALUES('d', '4')")
            raise RuntimeError
    assert store.one("SELECT 1 FROM settings WHERE key IN ('c', 'd')") is None  # both rolled back together
    with store.tx() as db:  # and the next transaction starts clean
        db.execute("INSERT INTO settings(key, value) VALUES('e', '5')")
    assert store.one("SELECT 1 FROM settings WHERE key='e'")


def test_a_function_is_found_by_its_address_from_an_index(tmp_path):
    """The room looks up a function by address for every match the host sends. Without an index each lookup read
    every function's assembly: 89 ms for 18,800 functions, hours for a room that has to catch up."""
    from decompnet.store import Store

    store = Store(tmp_path / "s.db")
    plan = store.all("EXPLAIN QUERY PLAN SELECT id, status FROM functions WHERE project_id=? AND vram=?", 1, 0x100000)
    assert "idx_functions_vram" in " ".join(str(r[3]) for r in plan)


def test_a_note_is_found_by_its_function_and_text_from_an_index(tmp_path):
    """A room's host sends every note it has, and each is saved only when the function doesn't have it: without an
    index that look-up read every note saved so far, 3 ms each at 7,000 notes."""
    from decompnet.store import Store

    store = Store(tmp_path / "s.db")
    plan = store.all("EXPLAIN QUERY PLAN SELECT 1 FROM notes WHERE project_id=? AND text=? AND function_id IS ?", 1, "x", 5)
    assert "idx_notes_lookup" in " ".join(str(r[3]) for r in plan)


def test_a_long_header_comes_in_parts_and_its_declarations_by_search(net, monkeypatch):
    """A Linux game's header from its debug info is 13,000 lines: Claude Code saved get_context's answer to a file
    its agent may not read, and the agent gave up reading it. Search returns whole declarations; paging the rest."""
    from decompnet import network

    found = net.get_context("demo", search=r"\bhp\b|struct Entity")
    assert "declarations match" in found and found.count("// line ") >= 1
    assert "typedef struct Entity {" in found and "s32 hp;\n} Entity;" in found  # the struct whole, every field
    assert "nothing in the header matches" in net.get_context("demo", search="no_such_name_here")
    monkeypatch.setattr(network, "CONTEXT_PAGE", 5)
    first = net.get_context("demo")
    assert "lines 1-5 of" in first and "get_context(start=6)" in first and len(first.splitlines()) == 7
    assert "lines 6-10 of" in net.get_context("demo", start=6)


def test_cpp_that_asks_for_no_shared_header_is_compiled_without_it(net):
    """A C++ program's header from its DWARF has glibc's and the C++ library's types too, so the real <string> and
    <map> clashed with it and agents couldn't instantiate std::map's functions. `#pragma decompdecomp no_context`
    compiles the C without the shared header (its own pragma: any other is still refused)."""
    from decompnet.compiler import SourceRejected, check_source

    check_source("#pragma decompdecomp no_context\nint f(void) { return 1; }\n")
    with pytest.raises(SourceRejected):
        check_source("#pragma GCC optimize(\"O0\")\nint f(void) { return 1; }\n")
    proj = net._project("demo")
    clash = "typedef struct Entity { int x; } Entity;\nint f(Entity *e) { return e->x; }\n"  # (the header has an Entity)
    header = net._context(proj["id"])["header"]
    assert "Entity" in header
    assert not net._compile(proj, header, clash).ok
    assert net._compile(proj, header, "#pragma decompdecomp no_context\n" + clash).ok


def test_includes_are_checked_as_the_preprocessor_reads_them():
    """A backslash at a line's end joins it to the next before the preprocessor reads a directive, and a drive or a
    backslash path leaves the sandbox where the compiler runs under Windows (wibo, wine: Z: is /). From decomp.anything."""
    for bad in ['#inc\\\nlude "../../etc/passwd"', '#include ".\\\n./secret.h"', '#include "Z:/etc/passwd"',
                '#include "\\\\server\\share\\x.h"', '#include "..\\..\\x.h"']:
        with pytest.raises(SourceRejected):
            check_source(bad)
    check_source('#define TWO \\\n    2\nint f(void) { return TWO; }')


def test_an_empty_old_text_is_refused_not_searched_for_forever():
    """`old` empty occurs everywhere: counting where it occurred never moved on, and held the file's lock."""
    from decompnet.textedit import replace_once

    for old in ("", "  \n"):
        with pytest.raises(NetworkError, match="empty"):
            replace_once("int a;\nint b;\n", old, "int c;\n", "the header")


def test_a_moved_instruction_marks_one_row_not_every_row_with_its_text():
    """One `pop ebx` of the candidate's two extra ones is the target's, moved: one row says so, the other stays an
    insertion (every row with the text was marked moved). From decomp.anything."""
    from decompnet import scoring
    from decompnet.elfobj import FunctionObj

    ops = {"a": b"\x40", "b": b"\x43", "n": b"\x90", "p": b"\x50", "q": b"\x5b"}

    def fn(s):
        return FunctionObj("f", "x86", False, b"".join(ops[c] for c in s) + b"\xc3")

    rows = scoring.diff(fn("nanbq"), fn("pbqqanapa")).rows
    extra_pops = [m for m, t, c in rows if c == "pop ebx" and not t]
    assert sorted(extra_pops) == [">", "o"]
