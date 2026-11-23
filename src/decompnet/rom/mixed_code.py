"""Code splat left as data. When a word in a stretch of text isn't an instruction (a jump table, a constant, a
word of microcode), spimdisasm files the whole rest of that stretch as `.word`s, and every function after the word
goes with it: no agent sees them, and the calls to them land on nothing.

A call from a compiled function into such a stretch says where code is. Where the processor's reader
(`Arch.called_code_extent`) finds a plain compiled function there, its start and end become source-file
boundaries in splat's config (a `c` subsegment each), and splat splits again; the functions already found get
boundaries of their own first, so the new files don't change how they're read. A split that loses or moves any
function found before is undone. Explicit data, switch pieces and addresses two segments share are left alone.
Nothing here matches anything: what's found is judged like every other function."""

from __future__ import annotations

import shutil
from bisect import bisect_right
from pathlib import Path

from .. import arch

PASSES = 3  # splits after the first: code found in one pass can call more
CANDIDATES = 512  # calls tried in one pass


def _raw_text(path: Path, name: str, segments, cfg) -> tuple[int, int, object, dict, list] | None:
    """(start, end, segment, its config entry, the c subsegment) of a file of `.word`s in a code subsegment."""
    from . import split

    lines = path.read_text(encoding="utf-8").splitlines()
    if not any(line.startswith("dlabel ") for line in lines):
        return None
    rows = [m for m in map(split._INSN.match, lines) if m]
    if not rows or any(m[4] != ".word" for m in rows):
        return None
    start, end = int(rows[0][1], 16), int(rows[-1][1], 16) + 4
    owners = []
    for segment in segments:
        raw = next(s for s in cfg["segments"] if isinstance(s, dict) and s.get("name") == segment.name)
        names = {segment.name} | {s[2] for s in raw.get("subsegments") or [] if isinstance(s, list) and len(s) > 2}
        if name in names and segment.rom_start <= start < end <= segment.rom_end:
            owners.append((segment, raw))
    if len(owners) != 1:
        return None
    segment, raw = owners[0]
    if any(int(m[1], 16) != start + i * 4 or int(m[2], 16) != segment.vram + start + i * 4 - segment.rom_start
           for i, m in enumerate(rows)):
        return None
    subs = raw.get("subsegments") or []
    for i, sub in enumerate(subs):
        if not isinstance(sub, list) or len(sub) < 3 or sub[1] != "c":
            continue
        limit = next((s[0] if isinstance(s, list) else s.get("start") for s in subs[i + 1:]
                      if (isinstance(s, list) and s) or (isinstance(s, dict) and s.get("start") is not None)),
                     segment.rom_end)
        if sub[0] <= start < end <= limit:
            return start, end, segment, raw, sub
    return None  # (in explicit data or a subsegment of another kind: never read as code)


def refine(config: Path, workdir: Path, image: str, console, log=print, *, visited: set | None = None) -> bool:
    """Source-file boundaries in splat's config around the functions called in text splat left as `.word`s.
    `visited`: the calls tried in earlier passes, not tried again. Returns whether the config changed."""
    import yaml

    from . import split

    reader = arch.get(console.arch).called_code_extent
    if reader is None:
        return False
    visited = visited if visited is not None else set()
    check_cancel = getattr(log, "check_cancel", lambda: None)
    order = "big" if console.big_endian else "little"
    cfg = yaml.safe_load(config.read_text(encoding="utf-8"))
    segments = split.segments_from_config_data(cfg)
    rom = (workdir / image).read_bytes()
    callers, known, dropped = [], [], []
    for path in sorted((workdir / "asm" / "nonmatchings").glob("**/*.s")):
        check_cancel()
        name = path.relative_to(workdir / "asm" / "nonmatchings").parts[0]
        fn = split.parse_function(path, name, console.big_endian)
        if fn is not None:
            split._complete_delay_slot(fn, rom, console.big_endian)
            known.append(fn)
            code = b"".join(line.word.to_bytes(4, order) for line in fn.lines)
            if not console.asm_reason(code) and not any(line.mnemonic.startswith(".") for line in fn.lines):
                callers.append(fn)  # (hand-written code's calls aren't a compiler's: no evidence)
        elif found := _raw_text(path, name, segments, cfg):
            dropped.append(found)
    # a stretch of .words can overlap functions spimdisasm wrote separately: only what no function has is looked in
    unowned = []
    for start, end, segment, raw, sub in dropped:
        if any(f.piece and segment.rom_start <= f.rom < segment.rom_end for f in known):
            continue  # (a switch's pieces are joined back by their file: new files would part them)
        cursor = start
        for fn in sorted(known, key=lambda f: f.rom):
            if fn.rom + fn.size <= cursor or fn.rom >= end:
                continue
            if fn.rom > cursor:
                unowned.append((cursor, fn.rom, segment, raw, sub))
            cursor = max(cursor, fn.rom + fn.size)
        if cursor < end:
            unowned.append((cursor, end, segment, raw, sub))
    if not unowned:
        return False
    unowned.sort(key=lambda row: row[0])
    starts = [row[0] for row in unowned]
    calls = {arch.mips.jump_target(line.word, line.vram)
             for fn in callers for line in fn.lines if line.word >> arch.mips.OPCODE_SHIFT == arch.mips.JAL}
    probes = []
    for target in sorted(calls):
        holders = [s for s in segments if s.contains(target, 4)]
        if len(holders) != 1:
            continue  # (an address two overlays share: no one place it goes)
        segment = holders[0]
        offset = segment.rom_start + target - segment.vram
        i = bisect_right(starts, offset) - 1
        if i < 0 or offset >= unowned[i][1] or unowned[i][2] != segment:
            continue
        if (offset, target, unowned[i][1]) not in visited:
            probes.append((offset, target, unowned[i]))
    accepted = []
    for offset, target, row in probes[:CANDIDATES]:
        check_cancel()
        visited.add((offset, target, row[1]))
        size = reader(rom, offset, row[1], target, big_endian=console.big_endian, cpu=console.cpu_variant,
                      asm_check=console.asm_reason)
        if size and not any(target < other < target + size for other in calls):  # (a call into its middle: not one)
            accepted.append((offset, offset + size, row))
    accepted = [a for a in accepted if not any(a is not b and a[0] < b[1] and b[0] < a[1] for b in accepted)]
    changed, anchored = 0, set()
    for start, end, (_, _, segment, raw, sub) in accepted:
        subs = raw["subsegments"]
        existing = {s[0] for s in subs if isinstance(s, list) and s}
        cuts = {start, end}
        if segment.name not in anchored:  # the functions found so far keep their extents: a file boundary each
            anchored.add(segment.name)
            for fn in known:
                if not (segment.rom_start <= fn.rom < fn.rom + fn.size <= segment.rom_end
                        and fn.vram == segment.vram + fn.rom - segment.rom_start):
                    continue
                for i, part in enumerate(subs):
                    if not isinstance(part, list) or len(part) < 2 or part[1] != "c":
                        continue
                    limit = next((s[0] for s in subs[i + 1:] if isinstance(s, list) and s), segment.rom_end)
                    if part[0] <= fn.rom < fn.rom + fn.size <= limit:
                        cuts.update((fn.rom, fn.rom + fn.size))
                        break
        for at in sorted(cuts):
            if at < segment.rom_end and at not in existing:
                subs.append([at, "c", f"{sub[2]}_{at:06X}"])
                changed += 1
        subs.sort(key=lambda s: s[0] if isinstance(s, list) else s.get("start", segment.rom_end))
    if changed:
        config.write_text(yaml.safe_dump(cfg, sort_keys=False, default_flow_style=None), encoding="utf-8")
        log(f"found {len(accepted)} called function{'s' if len(accepted) != 1 else ''} in code splat had left as data")
    if len(probes) > CANDIDATES:
        log(f"looked at the first {CANDIDATES} calls into code splat left as data; the others weren't looked at")
    return bool(changed)


def entries(workdir: Path, image: str, console) -> set[tuple[int, int, int]]:
    """(ROM offset, address, first word) of every function splat wrote, switch pieces aside."""
    from . import split

    rom = (workdir / image).read_bytes()
    out = set()
    for path in (workdir / "asm" / "nonmatchings").glob("**/*.s"):
        fn = split.parse_function(path, path.parent.name, console.big_endian)
        if fn is not None and not fn.piece:
            split._complete_delay_slot(fn, rom, console.big_endian)
            out.add((fn.rom, fn.vram, fn.lines[0].word))
    return out


def run(config: Path, workdir: Path, image: str, console, log=print) -> str:
    """After splat's split: refine and split again, up to PASSES times; a split that loses or moves a function found
    before is undone (the config as it was, split again). Returns splat's output."""
    from . import split

    if arch.get(console.arch).called_code_extent is None:
        return ""
    before, found, visited, out = config.read_bytes(), None, set(), ""
    for _ in range(PASSES):
        if not refine(config, workdir, image, console, log, visited=visited):
            break
        found = found if found is not None else entries(workdir, image, console)
        shutil.rmtree(workdir / "asm")  # (splat's output: nothing of the project's is in it yet)
        out += "\n" + split._splat(["split", config.name], workdir, log)
        if not found <= entries(workdir, image, console):
            config.write_bytes(before)
            shutil.rmtree(workdir / "asm")
            out += "\n" + split._splat(["split", config.name], workdir, log)
            log("splitting again around code splat had left as data moved a function it had found; "
                "kept the first split")
            break
    return out
