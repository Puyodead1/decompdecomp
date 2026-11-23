"""A room asks its computers for one room protocol, not one version (collab.ROOM_PROTOCOL), so a release that changes
nothing between them doesn't send a whole room to update. That only holds while the protocol is bumped whenever what
crosses between host and member changes, and a forgotten bump is a room that breaks quietly: a member's call the host
doesn't know, a key one side sends and the other never reads.

This test keeps a record of what crosses: the host's /collab calls and the keys the room's code sends and reads
(collab.py and forkroom.py, read as code: every key of a dict it writes, every key it looks up, every argument it
names in a call to the host), with the protocol it belongs to, in tests/room_protocol.json. When either changes, it
fails and says what changed. Then:
- if what the computers send each other changed, bump ROOM_PROTOCOL, then record it again:
  `uv run python tests/test_room_protocol.py`;
- if it didn't (a key only one computer uses, a config field), record it again without a bump.
How the host judges a member's match is part of the protocol too, and no record sees it: CONTRIBUTING.md, "Rooms".
"""

import ast
import json
import sys
from pathlib import Path

from decompnet.app import collab

SRC = Path(collab.__file__).parent
FILES = ("collab.py", "forkroom.py")
RECORD = Path(__file__).with_name("room_protocol.json")


def _routes(tree: ast.AST) -> list[str]:
    """The host's calls: each Route's path and methods ("POST /collab/claim")."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Route" and node.args:
            path = node.args[0]
            if not (isinstance(path, ast.Constant) and str(path.value).startswith("/collab/")):
                continue
            methods = next((k.value for k in node.keywords if k.arg == "methods"), None)
            names = [m.value for m in methods.elts] if isinstance(methods, ast.List) else ["GET"]
            out += [f"{m} {path.value}" for m in names]
    return sorted(out)


def _keys(tree: ast.AST) -> set[str]:
    """Every key the code writes in a dict, looks up (`x["k"]`, `x.get("k")`), or names in a call to the host."""
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys |= {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            keys.add(node.slice.value)
        elif isinstance(node, ast.Call):
            attr = getattr(node.func, "attr", "")
            if attr in ("get", "pop", "setdefault") and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                keys.add(node.args[0].value)
            if any(isinstance(a, ast.Constant) and str(a.value).startswith("/collab/") for a in node.args):
                keys |= {k.arg for k in node.keywords if k.arg}
    return keys


def current() -> dict:
    routes, keys = [], set()
    for name in FILES:
        tree = ast.parse((SRC / name).read_text(encoding="utf-8"))
        routes += _routes(tree)
        keys |= _keys(tree)
    return {"protocol": collab.ROOM_PROTOCOL, "routes": sorted(routes), "keys": sorted(keys)}


def test_what_crosses_between_a_rooms_computers_changes_only_with_its_protocol():
    recorded = json.loads(RECORD.read_text(encoding="utf-8"))
    now = current()
    if now == recorded:
        return
    changed = []
    for part in ("routes", "keys"):
        added = sorted(set(now[part]) - set(recorded[part]))
        gone = sorted(set(recorded[part]) - set(now[part]))
        changed += [f"{part} added: {', '.join(added)}"] * bool(added) + [f"{part} gone: {', '.join(gone)}"] * bool(gone)
    if now["protocol"] != recorded["protocol"]:
        changed.append(f"ROOM_PROTOCOL is {now['protocol']}, recorded {recorded['protocol']}")
    raise AssertionError(
        "what a room's computers send each other may have changed:\n  " + "\n  ".join(changed) +
        f"\nIf it did, bump collab.ROOM_PROTOCOL (now {now['protocol']}) so a member and a host that differ are told "
        "to update instead of sharing a room that breaks quietly. Either way, record it again: "
        "uv run python tests/test_room_protocol.py")


def test_one_protocol_shares_a_room_whatever_the_versions():
    """Different versions and commits on one protocol: let in. Different protocols: refused, saying who's behind."""
    p = collab.ROOM_PROTOCOL
    collab.check_same(("1.0.0", "aaaaaaaaaaaa", p), ("1.0.1+puyo.2", "bbbbbbbbbbbb", str(p)))  # (a header is text)
    try:
        collab.check_same(("1.0.1", "", p + 1), ("1.0.0", "", p))
    except collab.NetworkError as e:
        assert collab.SAME_PROTOCOL in str(e) and f"room protocol {p + 1}" in str(e) and "Update this computer" in str(e)
    else:
        raise AssertionError("a member on an older room protocol was let in")


def test_a_copy_from_before_the_protocol_needs_the_same_version():
    """One that sends no protocol (or nonsense) is held to the exact version and commit, as every room was."""
    p = collab.ROOM_PROTOCOL
    collab.check_same(("1.0.0", "", p), ("1.0.0", "", None))
    for theirs in (("0.9", "", None), ("0.9", "", "x"), ("0.9",)):
        try:
            collab.check_same(("1.0.0", "", p), theirs)
        except collab.NetworkError as e:
            assert collab.SAME_VERSION in str(e)
        else:
            raise AssertionError(f"{theirs} was let in without a protocol")


if __name__ == "__main__":  # (records what crosses now, with the current ROOM_PROTOCOL)
    RECORD.write_text(json.dumps(current(), indent=1) + "\n", encoding="utf-8")
    print(f"recorded room protocol {collab.ROOM_PROTOCOL} in {RECORD}", file=sys.stderr)
