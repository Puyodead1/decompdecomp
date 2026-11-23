"""Processor observations under compile feedback and briefs: a few lines on what a diff shows beyond its rows (the
stack frame's size, registers moved along a chain, a delay slot filled otherwise), from the processor's reader
(Arch.diff_observations: MIPS so far, so every MIPS console has them, ROM mode and project mode alike).

Advice only: the rows are read, never changed, and the score and the verdict are the judge's as before.
"""

from __future__ import annotations

from . import get

MAX_ROWS = 8192
MAX_LINES = 6
HEADING = "Processor observations (clues for your next change, not a verdict):"


def diff_lines(processor: str | None, rows, *, objdiff: bool = False, addresses=(None, None),
               heading: str = HEADING) -> list[str]:
    """The observations a scored diff supports, as lines to append (a blank line and a heading first), or none.
    `objdiff`: the rows are objdiff's (a project's), put in the judge's terms first; `addresses` is where the
    target's and your function start in their sections (FunctionDiff.addresses)."""
    reader = get(processor)
    if reader.diff_observations is None or not rows or len(rows) > MAX_ROWS:
        return []
    if any(not isinstance(row, (list, tuple)) or len(row) != 3 or not all(isinstance(c, str) for c in row)
           for row in rows) or all(row[0] == " " for row in rows):
        return []
    if objdiff:
        if reader.objdiff_rows is None:
            return []
        rows = reader.objdiff_rows(rows, tuple(addresses))
    lines = reader.diff_observations(rows)
    return ["", heading, *("- " + line for line in lines[:MAX_LINES])] if lines else []
