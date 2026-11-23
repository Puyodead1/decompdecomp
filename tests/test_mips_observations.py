"""Processor observations (arch/advice.py, arch/mips_observations.py): a few lines on what a MIPS diff shows beyond
its rows, under compile feedback and briefs, ROM mode and project mode alike. Advice only: the score and the verdict
stay the judge's."""

import copy
import json

import pytest

from decompnet import scoring
from decompnet.arch import advice, get, mips_observations
from decompnet.compiler import CompileResult
from decompnet.elfobj import FunctionObj
from decompnet.network import Network

STACK = [("s", "addiu $sp, $sp, -0x28", "addiu $sp, $sp, -0x20"),
         ("s", "sw $ra, 0x20($sp)", "sw $ra, 0x18($sp)"),
         (" ", "jal func_80001000", "jal func_80001000"),
         (" ", "nop", "nop"),
         ("s", "lw $ra, 0x20($sp)", "lw $ra, 0x18($sp)"),
         (" ", "jr $ra", "jr $ra"),
         ("s", "addiu $sp, $sp, 0x28", "addiu $sp, $sp, 0x20")]


def said(rows, **kw):
    return "\n".join(advice.diff_lines("mips", rows, **kw))


def words(values):
    return b"".join(word.to_bytes(4, "big") for word in values)


def test_a_frame_that_differs_only_in_size_says_a_local_is_missing():
    text = said(STACK)
    assert "the target's is 40 bytes, yours 32 (the target's is 8 bytes bigger)" in text
    assert "all by 8 bytes" in text and "The target has 8 more bytes of locals" in text
    yours_bigger = [(m, c, t) for m, t, c in STACK]  # (the other way round)
    assert "Yours has 8 more bytes of locals" in said(yours_bigger)


def test_a_frame_with_other_differences_gives_only_the_sizes():
    rows = [*STACK, ("|", "addu $v0, $a0, $a1", "subu $v0, $a0, $a1")]
    text = said(rows)
    assert "the target's is 40 bytes, yours 32" in text and "all by" not in text
    uneven = [*STACK[:4], ("s", "lw $ra, 0x20($sp)", "lw $ra, 0x1c($sp)"), *STACK[5:]]
    assert "all by" not in said(uneven)


def test_a_frame_only_one_side_makes():
    rows = [("<", "addiu $sp, $sp, -0x18", ""), ("<", "sw $ra, 0x10($sp)", ""), (" ", "jr $ra", "jr $ra")]
    assert "the target makes one of 24 bytes and yours makes none" in said(rows)
    assert "yours makes one of 24 bytes and the target makes none" in said([(">", c, t) for _, t, c in rows])


def test_leading_zero_decimals_are_not_octal():
    rows = [("s", "addiu $sp, $sp, -040", "addiu $sp, $sp, -032"), ("s", "sw $ra, 032($sp)", "sw $ra, 024($sp)"),
            ("s", "addiu $sp, $sp, 040", "addiu $sp, $sp, 032")]
    assert "all by 8 bytes" in said(rows)


def test_registers_shifted_along_a_chain_and_swapped():
    chain = [("r", "addu $t0, $a0, $a1", "addu $t1, $a0, $a1"), (" ", "nop", "nop"),
             ("r", "addu $t1, $t0, $a2", "addu $t2, $t1, $a2")]
    assert "Registers shift along a chain (the target's → yours): $t0 → $t1 → $t2." in said(chain)
    swap = [("r", "move $s0, $a0", "move $s1, $a0"), ("r", "move $s1, $a1", "move $s0, $a1")]
    assert "$s0 and $s1 are swapped" in said(swap)
    # one register for one renaming only: two stretches with other renamings each say their own
    contradicting = [("r", "move $s0, $a0", "move $s1, $a0"), ("r", "move $s0, $a1", "move $s2, $a1")]
    assert said(contradicting) == ""
    # a single renaming is what the row already says
    assert said([("r", "move $s0, $a0", "move $s1, $a0")]) == ""


def test_a_delay_slot_filled_otherwise():
    rows = [(" ", "jal func_80001000", "jal func_80001000"), ("|", "move $a0, $s0", "addiu $a1, $zero, 1")]
    assert "A different instruction fills a delay slot (2 places)" in said(rows)
    assert "delay slot" not in said([(" ", "addu $v0, $a0, $a1", "addu $v0, $a0, $a1"),
                                     ("|", "move $a0, $s0", "addiu $a1, $zero, 1")])


def test_branches_landing_elsewhere_only_with_the_same_instructions():
    rows = [("i", "beqz $v0, .L20", "beqz $v0, .L18"), (" ", "nop", "nop")]
    assert "A branch lands somewhere else" in said(rows)
    # an instruction missing or extra moves every destination after it: nothing more than the rows say
    assert "A branch lands" not in said([*rows, ("<", "nop", "")])


def test_objdiff_rows_are_read_as_the_judges():
    """objdiff marks every operand difference 'i' and writes registers bare: the readers need scoring's terms."""
    stack = [("i", "addiu sp, sp, -0x28", "addiu sp, sp, -0x20"), ("i", "sw ra, 0x20(sp)", "sw ra, 0x18(sp)"),
             ("i", "lw ra, 0x20(sp)", "lw ra, 0x18(sp)"), ("i", "addiu sp, sp, 0x28", "addiu sp, sp, 0x20")]
    assert "all by 8 bytes" in said(stack, objdiff=True)
    chain = [("i", "addu t0, a0, a1", "addu t1, a0, a1"), ("i", "addu t1, t0, a2", "addu t2, t1, a2")]
    assert "$t0 → $t1 → $t2" in said(chain, objdiff=True)
    [(mark, _, _)] = mips_observations.objdiff_rows([("i", "lw a0, 0xc(a2)", "lw a0, 0x10(a2)")])
    assert mark == "i"  # (neither registers nor a stack slot)


def test_objdiff_branch_destinations_count_from_the_functions_start():
    """objdiff writes a branch's destination as a section offset: two functions at other places in their sections
    land at the same place in themselves, and a symbol's digits are no offset."""
    assert mips_observations._objdiff_text("b 0x110", 0x100) == "b 0x10"
    assert mips_observations._objdiff_text("beqz v0, 272", 0x100) == "beqz $v0, 0x10"
    assert mips_observations._objdiff_text("j func_00100108", 0x100) == "j func_00100108"
    same = [("i", "bnez v0, 0x110", "bnez v0, 0x210"), (" ", "nop", "nop")]
    assert "A branch lands" not in said(same, objdiff=True, addresses=(0x100, 0x200))
    other = [("i", "bnez v0, 0x110", "bnez v0, 0x214"), (" ", "nop", "nop")]
    assert "A branch lands" in said(other, objdiff=True, addresses=(0x100, 0x200))
    assert "A branch lands" not in said(other, objdiff=True)  # (without the starts, no destination is compared)


@pytest.mark.parametrize("processor", ["x86", "ppc", "arm", "", None])
def test_other_processors_say_nothing(processor):
    assert get(processor).diff_observations is None
    assert advice.diff_lines(processor, STACK) == []


@pytest.mark.parametrize("rows", [[], [()], [("x", "only two")], [("r", 1, 2)], STACK * 2000,
                                  [(" ", "nop", "nop")]])
def test_unreadable_or_matching_diffs_say_nothing(rows):
    assert advice.diff_lines("mips", rows) == []


def test_the_rows_are_read_not_changed():
    before = copy.deepcopy(STACK)
    advice.diff_lines("mips", STACK)
    advice.diff_lines("mips", STACK, objdiff=True, addresses=(0, 0))
    assert STACK == before


def test_compile_feedback_keeps_the_judges_score_and_verdict(tmp_path, monkeypatch):
    net = Network(tmp_path / "test.db")
    target = words([0x27bdffd8, 0xafbf0020, 0x8fbf0020, 0x03e00008, 0x27bd0028])
    candidate = FunctionObj("f", "mips", True, words([0x27bdffe0, 0xafbf0018, 0x8fbf0018, 0x03e00008, 0x27bd0020]))
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,arch,big_endian,root,config) VALUES(?,?,?,?,?,?)",
                         ("game", "Game", "mips", 1, str(tmp_path), json.dumps({"compiler": {"toolchain": "x"}}))).lastrowid
        db.execute("INSERT INTO context_versions(project_id,version,header,created_at) VALUES(?,1,'',0)", (pid,))
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm) VALUES(?,?,?,?,?,?,?)",
                   (pid, "f", len(target), 5, target, "[]", ""))
    agent = net.authenticate(net.register_agent("helper"))
    monkeypatch.setattr(net, "_compile", lambda *a: CompileResult(True, b"object", ""))
    monkeypatch.setattr(net, "_evaluate", lambda *a: (candidate, False, []))
    expected = scoring.diff(net._target_obj(net._function("f", "game"), net._project("game")), candidate)
    out = net.attempt(agent, "f", "void f(void) {}", "game")
    assert out["score"] == expected.score and out["matched"] is False
    assert "Processor observations" in out["text"], out["text"]
    assert "the target's is 40 bytes, yours 32" in out["text"] and "all by 8 bytes" in out["text"]
    # and the brief of the function says it again while the app keeps that compile's diff
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_source='void f(void) {}', best_score=? WHERE name='f'", (out["score"],))
    brief = net.get_function("f", "game", agent)
    assert "Processor observations on your last compile of it" in brief and "all by 8 bytes" in brief, brief


@pytest.mark.parametrize("platform", ["n64", "ps", "ps2", "psp"])
def test_every_mips_console_reaches_them_through_its_processor(platform):
    """No console names them: a console's processor has the reader, so each MIPS console has them in ROM mode
    (the project's arch) and project mode (forkengine asks the console)."""
    from decompnet import consoles

    reader = get(consoles.get(platform).arch)
    assert reader.diff_observations is not None and reader.objdiff_rows is not None
    assert "all by 8 bytes" in "\n".join(advice.diff_lines(consoles.get(platform).arch, STACK))
