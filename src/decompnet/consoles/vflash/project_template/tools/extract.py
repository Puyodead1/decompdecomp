#!/usr/bin/env python3
"""Make the programs the build cuts functions out of (orig/VERSION/*.elf) from your copy of the game.

    python tools/extract.py VERSION

Put your copy of the game in orig/VERSION/ first: its disc image (.iso, or .bin with its .cue), or the disc's files
(the 0SYSTEM folder and the game modules, *.VFF; on some discs OUTPUT.BIN). This reads the game's firmware (FA) and
its game modules out of it (tools/vflash.py) and writes each as an ELF, checking that each is the one this project
was made from (config/VERSION/functions.json). Standard library only. Made by decompdecomp.
"""

import hashlib
import json
import sys
from pathlib import Path

import vflash  # (tools/vflash.py, beside this file: decompdecomp's reader of V.Flash discs)

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    version = sys.argv[1]
    info = json.loads((ROOT / "config" / version / "functions.json").read_text(encoding="utf-8"))
    folder = ROOT / "orig" / version
    wanted = info["programs"]
    have = {p: (ROOT / w["elf"]) for p, w in wanted.items()}
    if all(f.exists() and hashlib.sha1(f.read_bytes()).hexdigest() == wanted[p]["sha1"] for p, f in have.items()):
        return  # (made already)
    inputs = [p for p in sorted(folder.iterdir()) if p.suffix.lower() != ".elf"] if folder.is_dir() else []
    if (folder / "0SYSTEM").is_dir():
        inputs = [folder]  # (the disc's files: the folder is the disc)
    game = vflash.Game()
    for path in inputs:
        try:
            part = vflash.load(path)
        except (OSError, ValueError):
            continue
        game.fa = game.fa or part.fa
        game.modules += [m for m in part.modules if m.name not in {x.name for x in game.modules}]
    found = {"FA": game.fa} if game.fa else {}
    found.update({m.name: m for m in game.modules})
    missing = []
    for program, w in wanted.items():
        img = found.get(program)
        data = img.to_elf() if img else None
        if data is None or hashlib.sha1(data).hexdigest() != w["sha1"]:
            missing.append(program)
            continue
        have[program].parent.mkdir(parents=True, exist_ok=True)
        have[program].write_bytes(data)
    if missing:
        sys.exit(f"orig/{version}/ doesn't hold {', '.join(missing)} as this project has them: put your copy of the "
                 "game there (its disc image, or the disc's files)")


if __name__ == "__main__":
    main()
