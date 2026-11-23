"""m2c stops with "Label ._m2c_.L...before refers to a delay slot ... add a nop" for a label right after a call's
delay slot that a branch-likely also targets: 48 open functions of an N64 game had no draft for it. The nop it
asks for is added and m2c runs again; a draft that failed before is tried once more."""

import subprocess

import pytest

from decompnet import seeds

ASM = "glabel f\n    jal g\n    nop\n.L80001010:\n    jr $ra\n    nop\n"
REFUSAL = ("Decompilation failure in function f:\n\nLabel ._m2c_.L80001010before refers to a delay slot; "
           "this is currently not supported. Please add a nop to the delay slot.")


@pytest.fixture
def m2c(monkeypatch, tmp_path):
    """run_m2c with m2c answering `answers` in turn; returns (answers, the assembly each run read)."""
    answers, seen = [], []

    def run(argv, **_):
        seen.append(open(argv[-1], encoding="utf-8").read())
        code, out = answers.pop(0)
        return subprocess.CompletedProcess(argv, code, out, "")

    monkeypatch.setattr(seeds, "available", lambda: True)
    monkeypatch.setattr(seeds.toolchains, "path", lambda _: tmp_path)
    monkeypatch.setattr(seeds.subprocess, "run", run)
    return answers, seen


def test_the_nop_m2c_asks_for_goes_before_its_label_and_it_runs_again(m2c):
    answers, seen = m2c
    answers += [(1, REFUSAL), (0, "s32 f(void) {\n    g();\n}")]
    assert seeds.run_m2c(ASM, "f", "mips-gcc-c") == "s32 f(void) {\n    g();\n}"
    assert seen[0] == ASM
    assert seen[1] == ASM.replace(".L80001010:", "nop\n.L80001010:")


def test_any_other_failure_or_a_label_not_in_the_text_stays_a_failure(m2c):
    answers, seen = m2c
    answers += [(1, "Decompilation failure:\n\nUnsupported instruction cfc1")]
    assert seeds.run_m2c(ASM, "f", "mips-gcc-c") is None
    answers += [(1, REFUSAL.replace("80001010", "80002000"))]
    with pytest.raises(seeds.DraftError, match="delay slot"):
        seeds.run_m2c(ASM, "f", "mips-gcc-c", strict=True)
    assert len(seen) == 2


def test_it_stops_after_a_few_labels(m2c):
    answers, seen = m2c
    answers += [(1, REFUSAL)] * (seeds.DELAY_SLOT_NOPS + 1)
    assert seeds.run_m2c(ASM.replace(".L80001010:", ".L80001010:\n" * 20), "f", "mips-gcc-c") is None
    assert len(seen) == seeds.DELAY_SLOT_NOPS + 1


def test_a_failure_from_before_the_last_retry_is_drafted_again_once():
    assert seeds.drafted("/* draft */", "abc", "abc")
    assert not seeds.drafted("", "abc", "abc")  # (failed before the nop: tried again)
    assert seeds.drafted("", seeds.draft_key("abc", ""), "abc")
    assert not seeds.drafted(None, None, None)
    assert not seeds.drafted("", None, None) and seeds.drafted("", seeds.draft_key(None, ""), None)
    assert seeds.draft_key("abc", "/* draft */") == "abc"
