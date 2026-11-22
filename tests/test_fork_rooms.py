"""Rooms for git projects: a host and a member, each with their own copy of Demo Quest PC (a PC game started from
scratch, so a git source tree) and their own compilers. The member gets the host's tree as git bundles, builds it
with their own copy, and works with the room: claims through the host, matches confirmed and committed there, edits
of shared files made there, and the host's commits followed."""

import json
import re
import subprocess
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from decompnet.app import collab
from decompnet.app.engine import RomNetwork
from decompnet.forks import csource
from decompnet.network import NetworkError

from .test_pc import DEMO, EXE, GAME, _map, needs_tools

pytestmark = needs_tools  # Visual C++ (proprietary), Ghidra and objdiff


def _names() -> tuple[dict, callable]:
    """(symbol -> address, a function that writes the demo's names as the project's automatic ones)."""
    syms = _map()
    rename = {re.sub(r"^[_@]|@\d+$", "", s): (f"func_{a:08X}" if a < 0x402000 else f"D_{a:08X}")
              for s, a in syms.items() if not s.startswith("??") and s != "__fltused"}
    pattern = re.compile(r"\b(" + "|".join(sorted(rename, key=len, reverse=True)) + r")\b")
    return syms, lambda text: pattern.sub(lambda m: rename[m.group(1)], text)


def _work(name: str) -> tuple[str, str]:
    """(the project's name of a demo function, its C as an agent would write it)."""
    syms, sub = _names()
    decorated = next(s for s in syms if re.sub(r"^[_@]|@\d+$", "", s) == name)
    source = GAME.read_text() + (DEMO / "pcmain.c").read_text()
    return decorated.replace(name, sub(name)), sub(csource.get(source, name))


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True).stdout.strip()


@pytest.fixture(scope="module")
def room(tmp_path_factory):
    if not EXE.exists():
        import sys

        subprocess.run([sys.executable, str(DEMO / "build.py")], check=True)
    h = tmp_path_factory.mktemp("host")
    host = RomNetwork(h / "d.db", h)
    slug = host.import_rom(EXE, confirmed=True, log=lambda *_: None)
    host.rooms[slug] = collab.Room(host, slug)
    code = host.rooms[slug].open_invite()
    client = TestClient(collab.host_app(host, host.rooms), base_url="https://abc.trycloudflare.com", headers={collab.VERSION_HEADER: collab.__version__})
    g = tmp_path_factory.mktemp("guest")
    guest = RomNetwork(g / "d.db", g)
    link = f"https://abc.trycloudflare.com/join/{code}#room={slug}"
    said = []
    gslug = collab.join_room(guest, link, "alex", EXE, log=said.append, client=client, start=False)
    return host, slug, guest, gslug, client, link, said


def test_the_member_gets_the_tree_and_builds_it_with_their_own_copy(room):
    host, slug, guest, gslug, client, link, said = room
    hroot, groot = Path(host.project_row(slug)["root"]), Path(guest.project_row(gslug)["root"])
    assert _git(groot, "rev-parse", "HEAD") == _git(hroot, "rev-parse", "HEAD")  # the host's commits, as they are
    assert list((groot / "orig").glob("*.exe"))  # the member's own copy, placed by the member's setup
    tracked = _git(groot, "ls-files").split()
    assert not [f for f in tracked if f.startswith(("orig/", "build/"))]  # no game data ever came with the tree
    gov, hov = guest.overview(gslug), host.overview(slug)
    assert gov["ready"] and gov["functions"] == hov["functions"] >= 19
    assert gov["room"]["role"] == "guest" and any("building the project" in s for s in said)


def test_joining_needs_the_same_game(room, tmp_path):
    host, slug, guest, gslug, client, link, said = room
    other = RomNetwork(tmp_path / "o.db", tmp_path)
    changed = bytearray(EXE.read_bytes())
    changed[0x1010] ^= 0xFF  # a byte of the program's code
    (tmp_path / "other.exe").write_bytes(bytes(changed))
    with pytest.raises(NetworkError, match="same game"):
        collab.join_room(other, link, "eve", tmp_path / "other.exe", log=lambda *_: None, client=client, start=False)


def test_state_and_bundles_carry_work_never_the_game(room):
    host, slug, guest, gslug, client, link, said = room
    tok = guest.links[gslug].token
    st = client.get(f"/collab/state?room={slug}", headers={"authorization": f"Bearer {tok}"}).json()
    assert st["head"] and st["members"][0]["name"] == "alex" and "functions" not in st and "context" not in st
    assert client.get(f"/collab/bundle?room={slug}", headers={"authorization": "Bearer dn_nope"}).status_code == 400
    r = client.get(f"/collab/bundle?room={slug}&have={st['head']}", headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 204  # up to date: nothing to send


def test_a_members_match_is_confirmed_and_committed_by_the_host(room):
    host, slug, guest, gslug, client, link, said = room
    agent, _ = guest.local_agent("claude-1")
    hroot = Path(host.project_row(slug)["root"])
    # the game's types first: an edit of a shared header, made and checked by the host, followed here
    _, sub = _names()
    types = (GAME.parent / "game.h").read_text().split("#define NULL ((void *)0)", 1)[1].rsplit("#endif", 1)[0]
    out = guest.forks.edit_file(agent, gslug, "include/common.h", "", sub(types), "the game's types")
    assert out.startswith("✅"), out
    assert "Edited by alex.claude-1" in _git(hroot, "log", "-1", "--format=%B")  # the host made the commit
    groot = Path(guest.project_row(gslug)["root"])
    assert sub("g_player") in (groot / "include" / "common.h").read_text()  # and this copy has it already

    fn, source = _work("clamp_s32")
    brief = guest.forks.claim(agent, gslug, fn)
    assert "CLAIMED" in brief
    assert [c["agent"] for c in host.live(slug)["claims"]] == ["alex.claude-1"]  # held in the room, not just here
    res = guest.attempt(agent, fn, source, gslug)
    assert res["matched"] and "host confirmed" in res["text"], res["text"]
    assert host._function(fn, slug)["status"] == "matched"
    assert re.search(r"^Match ", _git(hroot, "log", "-1", "--format=%s"))
    guest.links[gslug].sync()
    assert _git(groot, "rev-parse", "HEAD") == _git(hroot, "rev-parse", "HEAD")


def test_the_hosts_work_reaches_the_member(room):
    host, slug, guest, gslug, client, link, said = room
    agent, _ = host.local_agent("claude-host")
    fn, source = _work("entity_default_hp")
    assert host.forks.claim(agent, slug, fn)
    assert host.attempt(agent, fn, source, slug)["matched"]
    guest.links[gslug].sync()
    groot, hroot = Path(guest.project_row(gslug)["root"]), Path(host.project_row(slug)["root"])
    assert _git(groot, "rev-parse", "HEAD") == _git(hroot, "rev-parse", "HEAD")
    row = guest._function(fn, gslug)
    assert row["status"] == "matched"  # measured in this copy, after its build
    who = guest.store.one("SELECT name FROM agents WHERE id=?", row["matched_agent_id"])
    assert who and who["name"] in ("@claude-host", "@host")


def test_work_in_progress_survives_following_the_host(room):
    host, slug, guest, gslug, client, link, said = room
    other, source = _work("player_take_damage")
    gagent, _ = guest.local_agent("claude-2")
    # the member works on another function than the host's next match (the demo's code is all one file)
    fn, mine = _work("entity_points")
    wip = mine.replace("return 75;", "return 76;")
    guest.forks.claim(gagent, gslug, fn)
    res = guest.attempt(gagent, fn, wip, gslug)  # an attempt, not a match: stays in its file
    assert not res["matched"], res["text"]
    groot = Path(guest.project_row(gslug)["root"])
    src = next(p for p in (groot / "src").rglob("*") if p.suffix in (".c", ".cpp") and "return 76;" in p.read_text())
    hagent, _ = host.local_agent("claude-host2")
    host.forks.claim(hagent, slug, other)
    assert host.attempt(hagent, other, source, slug)["matched"]
    guest.links[gslug].sync()
    assert "return 76;" in src.read_text()  # the member's attempt is still there, on top of the host's commits
    assert guest._function(other, gslug)["status"] == "matched"
    assert _git(groot, "rev-parse", "HEAD") == _git(Path(host.project_row(slug)["root"]), "rev-parse", "HEAD")
    guest.forks.release(gagent, gslug, fn, "")
    assert not host.live(slug)["claims"]


def test_the_hosts_version_wins_where_both_changed_the_same_lines(room):
    host, slug, guest, gslug, client, link, said = room
    hroot, groot = Path(host.project_row(slug)["root"]), Path(guest.project_row(gslug)["root"])
    rel = "include/common.h"
    (groot / rel).write_text((groot / rel).read_text() + "\n#define MEMBER_ONLY 1\n")  # unsaved work here
    hagent, _ = host.local_agent("claude-host3")
    assert host.forks.edit_file(hagent, slug, rel, "", "#define HOST_SIDE 2", "a constant").startswith("✅")
    guest.links[gslug].sync()
    text = (groot / rel).read_text()
    assert "HOST_SIDE" in text and "MEMBER_ONLY" not in text and "<<<<<<<" not in text
    assert _git(groot, "rev-parse", "HEAD") == _git(hroot, "rev-parse", "HEAD")
    assert not _git(groot, "stash", "list")  # nothing left behind


def test_reconnecting_keeps_the_place_in_the_tree(room):
    host, slug, guest, gslug, client, link, said = room
    head = json.loads(guest.project_row(gslug)["config"])["link"]["head"]
    assert head == _git(Path(host.project_row(slug)["root"]), "rev-parse", "HEAD")
    assert collab.join_room(guest, link, "alex", b"", log=lambda *_: None, client=client, start=False) == gslug
    assert guest.links[gslug].head == head


def test_a_members_try_compiler_runs_on_the_hosts_copy(room):
    """A GameCube room's member agent found an SDK function whose prologue wanted another CodeWarrior, and its
    try_compiler was refused ("the host's project decides each file's compiler"): the host tries it now."""
    from decompnet import consoles

    host, slug, guest, gslug, client, link, said = room
    agent, _ = guest.local_agent("claude-2")
    fn, source = _work("clamp_s32")
    _, fp, cfg = host.forks.get(slug)
    unit = fp.unit(host._function(fn, slug)["unit"])
    own = consoles.get(cfg["platform"]).file_compiler(fp, unit.source)
    try:
        out = guest.forks.try_compiler(agent, gslug, fn, own, source=source)
    except collab.Refused as e:  # (it matches already: the host's own answer, from its copy)
        out = str(e)
    assert "decides each file's compiler" not in out and ("already matches" in out or unit.source in out), out


def test_a_members_report_library_counts_on_the_host_and_the_room_follows(room):
    """A GameCube room's member agents had report_library refused ("the room's host decides what's library code"):
    the SDK's functions stayed open for them, one agent after another. Their word counts on the host now, as its own
    agents' does; the set-aside is committed there and the member's copy follows."""
    host, slug, guest, gslug, client, link, said = room
    fn, _ = _work("mix_score")
    one, _ = guest.local_agent("claude-lib1")
    two, _ = guest.local_agent("codex-lib2")
    out = guest.report_library(one, fn, "the demo's runtime", "a mixing routine the runtime ships", gslug)
    assert "1 of 2" in out, out
    out = guest.report_library(two, fn, "the demo's runtime", "the runtime's mixing routine", gslug)
    assert "set aside as" in out, out
    assert host._function(fn, slug)["status"] == "asm"
    hroot, groot = Path(host.project_row(slug)["root"]), Path(guest.project_row(gslug)["root"])
    assert _git(groot, "rev-parse", "HEAD") == _git(hroot, "rev-parse", "HEAD")  # the commit came with it
    assert guest._function(fn, gslug)["status"] == "asm"


def test_a_busy_index_is_waited_out_when_following_the_host(tmp_path, monkeypatch):
    """A Windows member's "git stash failed: could not write index" ended following the host, and its agents' claims:
    a moment's busy index is tried again; another failure isn't."""
    from types import SimpleNamespace

    from decompnet.app import forkroom

    said = iter([SimpleNamespace(returncode=128, stdout="", stderr="error: could not write index"),
                 SimpleNamespace(returncode=0, stdout="ok\n", stderr="")])
    monkeypatch.setattr(forkroom.subprocess, "run", lambda *a, **k: next(said))
    monkeypatch.setattr(forkroom, "INDEX_WAIT", 0)
    assert forkroom._git(tmp_path, "stash", "push") == "ok"
    monkeypatch.setattr(forkroom.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="fatal: bad revision"))
    with pytest.raises(NetworkError, match="bad revision"):
        forkroom._git(tmp_path, "rev-parse", "nope")
    import os
    assert os.environ.get("GIT_OPTIONAL_LOCKS") == "0"  # (reads leave the index alone: forks/project.py)


def test_a_function_the_host_hands_out_is_open_in_the_members_copy_too(room):
    """The host measured functions again and reopened them; a member's copy still had them matched, refused each
    claim with "already matched" while the host held it for the agent, and its agents got only such functions."""
    host, slug, guest, gslug, client, link, said = room
    agent, _ = guest.local_agent("claude-3")
    fn, _ = _work("clamp_s32")
    with host.store.tx() as db:  # (the host reopened it; this copy still says matched)
        db.execute("UPDATE functions SET status='open' WHERE name=? AND project_id=?", (fn, host.project_row(slug)["id"]))
    with guest.store.tx() as db:
        db.execute("UPDATE functions SET status='matched' WHERE name=? AND project_id=?", (fn, guest.project_row(gslug)["id"]))
    brief = guest.forks.claim(agent, gslug, fn)
    assert "CLAIMED" in brief and guest._function(fn, gslug)["status"] == "open"


def test_a_members_rename_is_made_on_the_host_and_the_room_follows(room):
    """A GameCube room's guest polishing a function had every rename_symbol refused ("the host's project is the one
    to rename in"), so the `unk0`/`unk18` names the readability check asks for could never be given, and the helper
    gave the function up. The host renames it now, with its own checks, and the guest's copy follows its commit."""
    host, slug, guest, gslug, client, link, said = room
    agent, _ = guest.local_agent("claude-polish")
    fn, _ = _work("rng_next")
    out = guest.forks.rename_symbol(agent, gslug, fn, "Rng_Next")
    assert out.startswith("✅"), out
    hroot, groot = Path(host.project_row(slug)["root"]), Path(guest.project_row(gslug)["root"])
    assert _git(hroot, "log", "-1", "--format=%s") == f"Rename {fn} to Rng_Next"  # made and committed there
    assert _git(groot, "rev-parse", "HEAD") == _git(hroot, "rev-parse", "HEAD")  # and the guest's copy has it
