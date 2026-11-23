"""Write the N64's library fingerprint tables (Console.library_prints): libultra rebuilt from public source, and
n_audio from the user's own SDK archives.

    git clone https://github.com/decompals/ultralib.git <dir> && git -C <dir> checkout <ULTRALIB_COMMIT below>
    uv run python -m decompnet.consoles.n64.signatures ultralib <dir>
    uv run python -m decompnet.consoles.n64.signatures naudio <SDK>/2.0K/.../libgn_audio.a [...]

Without the user's own SDK, library detection had nothing to compare a game's functions with: a computer with no N64
SDK found 2 library functions in a racing game where one with six SDK folders found 152. ultralib rebuilds Nintendo's
archives byte for byte from public C and assembly, so the fingerprints of its objects are the SDK's, made without it.
`ultralib` builds each version and archive ultralib vouches for (its README's table) with the app's own pinned
compilers (gcc-2.7.2-kmc and ido-5.3, the ones ultralib's tools/Makefile fetches), keeps the objects each archive holds
(base/<version>/<archive>.txt) and writes every function's fingerprint (twins._key: masked code and relocation layout,
a SHA-1), size, name and the builds it came from. Linux only (ultralib's Makefile, and links to the compilers).

n_audio (`libgn_audio.a`) isn't in ultralib, and no public C rebuilds it as the SDK shipped it, so `naudio` reads the
user's own archives where they are (never copied), less the fingerprints the ultralib table already names: n_audio
keeps libultra's audio code under `n_` names, and those keep libultra's.

No code is written either way: a table is hashes, sizes and names, like decomp-toolkit's GameCube corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ULTRALIB_COMMIT = "e24c836796df4bf520ff8b11a5c9d2cea3a66cbd"
VERSIONS = ("I", "J", "K", "L")
# ultralib's README: every archive of 2.0I-2.0L builds but IDO's libultra_d
ARCHIVES = ("libultra", "libultra_rom", "libgultra", "libgultra_d", "libgultra_rom")
ULTRALIB = Path(__file__).with_name("ultralib_signatures.tsv")
NAUDIO = Path(__file__).with_name("naudio_signatures.tsv")
NAUDIO_NAME = re.compile(r"libgn_audio(_d)?\.a", re.I)
HEADER = "# fingerprint\tsize\tname\tbuilds"


def _prints(data: bytes) -> dict:
    from ...app.twins import object_prints

    return object_prints(data)


def _tools(checkout: Path) -> None:
    """ultralib's tools/gcc and tools/ido, as links to the app's pinned copies of the same compilers."""
    from ... import toolchains

    for folder, pack, extra in (("gcc", "gcc-2.7.2-kmc", {"strip-2.7": "strip"}), ("ido", "ido-5.3", {})):
        source = Path(toolchains.ensure(pack, log=print))
        target = checkout / "tools" / folder
        target.mkdir(parents=True, exist_ok=True)
        for item in source.iterdir():
            if not (target / item.name).exists():
                (target / item.name).symlink_to(item)
        for name, of in extra.items():
            if not (target / name).exists():
                (target / name).symlink_to(source / of)


def _build(checkout: Path, version: str, archive: str) -> dict[str, tuple[str, int]]:
    """{function: (fingerprint, size)} of the objects the archive holds, built without the original to compare."""
    from ...app.twins import ACROSS_MIN_BYTES

    # AR_OLD=true: the archive itself isn't needed, only its objects (and ultralib's IDO ar wants binutils)
    done = subprocess.run(["make", "-k", f"-j{os.cpu_count() or 4}", "COMPARE=0", f"VERSION={version}",
                           f"TARGET={archive}", "AR_OLD=true"], cwd=checkout, capture_output=True, text=True)
    # by name in any case, as ultralib's Makefile finds them (`find -iname`): IDO's lists name drvrNew.o, the file
    # is drvrnew.o
    members = {m.lower() for m in (checkout / "base" / version / f"{archive}.txt").read_text().split()}
    found: dict[str, tuple[str, int]] = {}
    built = set()
    for obj in sorted((checkout / "build" / version / archive).rglob("*.o")):
        if obj.name.lower() not in members:
            continue
        built.add(obj.name.lower())
        for name, p in _prints(obj.read_bytes()).items():
            if p.size >= ACROSS_MIN_BYTES:
                found[name] = (p.key, p.size)
    if missing := sorted(members - built):
        print(f"  2.0{version} {archive}: {len(missing)} of {len(members)} objects didn't build: {missing[:8]}"
              + (f"\n{done.stderr[-1500:]}" if done.returncode else ""))
    return found


def ultralib_table(checkout: Path) -> list[str]:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=checkout, capture_output=True, text=True).stdout.strip()
    if head != ULTRALIB_COMMIT:
        sys.exit(f"{checkout} is at {head or 'no commit'}: check out {ULTRALIB_COMMIT}, the commit this table pins")
    _tools(checkout)
    rows: dict[tuple[str, int, str], list[str]] = defaultdict(list)
    for version in VERSIONS:
        for archive in ARCHIVES:
            found = _build(checkout, version, archive)
            print(f"2.0{version} {archive}: {len(found)} functions")
            for name, (key, size) in found.items():
                rows[key, size, name].append(f"2.0{version}/{archive}")
    lines = [f"# decompals/ultralib {ULTRALIB_COMMIT}, rebuilt by consoles/n64/signatures.py with the app's pinned "
             "compilers", HEADER]
    return lines + [f"{key}\t{size}\t{name}\t{','.join(builds)}" for (key, size, name), builds in sorted(rows.items())]


def _label(path: Path) -> str:
    """`2.0K/libgn_audio` for an archive in an SDK folder of 2.0K."""
    version = re.search(r"2\.0([A-L])", str(path), re.I)
    if not version or not NAUDIO_NAME.fullmatch(path.name):
        sys.exit(f"{path}: choose a libgn_audio.a or libgn_audio_d.a in an SDK folder named for its version "
                 "(2.0J, 2.0K, 2.0L)")
    return f"2.0{version[1].upper()}/{path.name.lower()[:-2]}"


def archive_prints(data: bytes) -> set[tuple[str, int, str]]:
    """{(fingerprint, size, function)} of an archive's objects: every object's copy, since a static function can be
    in two (n_audio's `__n_setUsptFromTempo`, in both sequence players)."""
    from elftools.common.exceptions import ELFError

    from ...app.engine.libraryid import archive_members
    from ...app.twins import ACROSS_MIN_BYTES

    found = set()
    for _, member in archive_members(data):
        try:
            items = _prints(member).items()
        except (ELFError, ValueError, KeyError):
            continue  # an archive's symbol table, a member that isn't an object
        found |= {(p.key, p.size, name) for name, p in items if p.size >= ACROSS_MIN_BYTES}
    return found


def known(path: Path) -> set[str]:
    """The fingerprints a table names (n_audio's leaves out the ultralib table's: one fingerprint with two names in
    the tables says neither)."""
    return {line.split("\t")[0] for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith("#")}


def naudio_table(archives: list[Path], skip: set[str] = frozenset()) -> list[str]:
    rows: dict[tuple[str, int, str], set[str]] = defaultdict(set)
    sources = []
    for path in sorted(set(archives)):
        build = _label(path)
        data = path.read_bytes()
        found = archive_prints(data)
        print(f"{build}: {len(found)} functions ({path})")
        sources.append(f"{build} sha256:{hashlib.sha256(data).hexdigest()[:12]}")
        for row in found:
            if row[0] not in skip:
                rows[row].add(build)
    versions = sorted({s.split("/")[0] for s in sources})
    lines = [f"# n_audio {versions[0]}-{versions[-1]}, fingerprints of the SDK's own archives by "
             f"consoles/n64/signatures.py (hashes, sizes and names; no code): {'; '.join(sorted(set(sources)))}",
             HEADER]
    return lines + [f"{key}\t{size}\t{name}\t{','.join(sorted(builds))}" for (key, size, name), builds in sorted(rows.items())]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="table", required=True)
    one = sub.add_parser("ultralib", help="libultra, rebuilt from a clone of decompals/ultralib")
    one.add_argument("checkout", type=Path, help=f"a clone of decompals/ultralib at {ULTRALIB_COMMIT}")
    one.add_argument("--out", type=Path, default=ULTRALIB)
    two = sub.add_parser("naudio", help="n_audio, from your own SDK's libgn_audio.a and libgn_audio_d.a")
    two.add_argument("archives", type=Path, nargs="+")
    two.add_argument("--out", type=Path, default=NAUDIO)
    two.add_argument("--ultralib", type=Path, default=ULTRALIB, help="the table whose fingerprints to leave out")
    args = parser.parse_args()
    if args.table == "ultralib":
        lines = ultralib_table(args.checkout.resolve())
    else:
        lines = naudio_table([p.resolve() for p in args.archives], known(args.ultralib))
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(lines) - 2} signatures written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
