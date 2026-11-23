"""Private rooms: friends who each own the same game decompile it together.

The host's decompdecomp is the hub. It serves a small, separate HTTP app (only /collab routes; never the GUI or the
agents' MCP endpoint) that a quick tunnel makes reachable. A friend joins with the invite link *and their own copy of
the game*: the ROM's SHA-1 must equal the host's, checked on both sides. No ROM bytes or assembly ever cross the
wire. Each side reads the code from its own copy; what travels is the work: claims (so nobody does the same function
twice), C attempts, matches, names, struct/prototype edits, notes. The host re-compiles every attempt it accepts
against its own ROM, so a match always means the same thing.

Host side: `host_app()`. Guest side: `Link`, which RomNetwork consults for every collaborative action.
Projects that are git source trees (GameCube, Wii, DS, forks of public decomps) work the same way, with the host's
tree as the room's truth: see forkroom.py.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from decompnet.hostenv import NO_WINDOW

from .. import __version__, toolchains
from ..network import Agent, NetworkError, hash_token
from . import forkroom

NAME = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
MAX_BODY = 256 * 1024
TUNNEL_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
# what the host answers someone it hasn't let in; the guest's screen says which (gui.py: the room's state)
WAITING = "waiting for the host to let you in"
NOT_MEMBER = "not a member of this room"
ROOM_CLOSED = "this room is closed"
SAME_VERSION = "everyone in a room runs the same version"
SAME_PROTOCOL = "everyone in a room needs the same room protocol"
EVENTS_PAGE = 500  # events per answer; a guest that's behind asks again at once
MATCHED_PAGE = 200  # matched functions' C per /collab/matched answer
LET_IN_WAIT = 30 * 60  # longest a git project's join waits to be let in: it needs the host's files before anything
LET_IN_EVERY = 3  # seconds between its looks
ROOM_QUIET = 15  # seconds without an answer from the host before the guest's screen says it's away
HEARTBEAT_EVERY = 5  # independent of importing matches or rebuilding a source project
HEARTBEAT_TIMEOUT = 10
# A member's request is answered within ANSWER_WITHIN seconds; work that takes longer (a GameCube file rebuilt and
# checked behind 20 agents' turns on its lock) goes on at the host as a job the member asks after. Held open, the
# answer passed the member's 60 seconds and a tunnel's 100: "the room's host isn't reachable right now" for every
# make_readable and edit_file, the host doing it anyway, and the agents trying again until they gave up.
ANSWER_WITHIN = 20
JOB_WAIT = 3600  # how long a member waits for one job before it gives up on it
JOB_KEEP = 900  # how long the host keeps a finished job's answer nobody came for
logger = logging.getLogger("decompdecomp")


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _check_name(name: str) -> None:
    """The host's rule too: a name it will refuse is caught before a join does any slow work."""
    if not NAME.match(name or ""):
        raise NetworkError("pick a name of up to 24 letters, digits, - or _")


# ---------------------------------------------------------------------------------------------- host

# Every computer in a room must agree on what crosses between them: the host and its members each judge, build and
# sync work, and a fix one side had and the other hadn't broke rooms quietly (a laptop's helpers, named by an older
# host, shared one claim). The member sends its version with every request, and the host says its own.
VERSION_HEADER = "x-decomp-version"
# A copy installed from a branch has one version through many commits, whose rooms can differ (new calls between
# host and member, new things the host sends): its commit is sent too, and two that both know theirs must agree. A
# release's copy knows none, and its version says it.
COMMIT_HEADER = "x-decomp-commit"
# Refusing every other version made each small release (a fix to the GUI, to a console's drafts) send a whole room
# to update at once. What has to agree is only what crosses between the computers: the /collab calls and what they
# send and answer, the work the host syncs to members, and how the host judges a member's match. ROOM_PROTOCOL counts
# changes to those, and two copies on one protocol share a room whatever their versions and commits. Bump it with any
# such change (CONTRIBUTING.md, "Rooms"); tests/test_room_protocol.py fails when a call or a key it sends changes
# without a bump. A copy from before the protocol sends none, and is held to the exact version as before.
ROOM_PROTOCOL = 1
PROTOCOL_HEADER = "x-decomp-room-protocol"


@functools.lru_cache(maxsize=1)
def own_commit() -> str:
    """The commit this copy was installed from (a branch install's, updates.installed), "" when it doesn't know."""
    from . import updates

    return str(updates.installed().get("commit") or "")[:12]


def _auth(token: str, room: str) -> dict:
    """A member's request headers: its token, the room, its room protocol and its version (and commit)."""
    return {"authorization": f"Bearer {token}", "x-room": room, VERSION_HEADER: __version__,
            PROTOCOL_HEADER: str(ROOM_PROTOCOL), **({COMMIT_HEADER: own_commit()} if own_commit() else {})}


def own() -> tuple[str, str, int]:
    """This copy, as rooms compare it: (version, commit, room protocol)."""
    return __version__, own_commit(), ROOM_PROTOCOL


def _protocol(value) -> int:
    """A room protocol as the other side sent it; 0 when it sent none (a copy from before rooms had one)."""
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _build(version: str | None, commit: str | None) -> str:
    return f"{version or 'an older version'}" + (f" (commit {commit[:12]})" if version and commit else "")


def check_same(host: tuple, member: tuple) -> None:
    """Refuse a host and a member that can't share a room. Each is (version, commit[, room protocol]). Two that both
    send a protocol need the same one, whatever their versions; otherwise (one is from before the protocol) they
    need the same version, and the same commit when both know theirs."""
    (hv, hc, hp), (mv, mc, mp) = (*host, None, None)[:3], (*member, None, None)[:3]
    hp, mp = _protocol(hp), _protocol(mp)
    if hp and mp:
        if hp != mp:
            raise NetworkError(same_protocol((hv, hp), (mv, mp)))
        return
    if hv != mv or (hc and mc and hc[:12] != mc[:12]):
        raise NetworkError(same_version(_build(hv, hc), _build(mv, mc)))


def same_protocol(host: tuple[str | None, int], member: tuple[str | None, int]) -> str:
    """Why a room refused: the host and the member speak different room protocols."""
    (hv, hp), (mv, mp) = host, member
    behind = "this computer" if mp < hp else "the host"
    return (f"this room's host runs decompdecomp {hv or 'an older version'} (room protocol {hp}) and this computer "
            f"{mv or 'an older version'} (room protocol {mp}): {SAME_PROTOCOL}, since what they send each other "
            f"changed between them. Update {behind}; the room carries on once both do")


def same_version(host: str | None, member: str | None) -> str:
    """Why a room refused: the host and the member run different versions (or commits of one)."""
    return (f"this room's host runs decompdecomp {host or 'an older version'} and this computer "
            f"{member or 'an older version'}: {SAME_VERSION}. Update the one that's behind; the room carries on once "
            "both run the same")


MEMBER_LABEL = 48  # characters of a member's agent's name kept on the host; a longer one ends in a digest of all of it


def member_label(label: str) -> str:
    # (dots stay: opencode-minimax-m3.1 became m31 here, another model than the host's own m3.1, network.model_of)
    label = re.sub(r"[^A-Za-z0-9_.-]", "", str(label or "agent")).lstrip(".") or "agent"
    if len(label) <= MEMBER_LABEL:
        return label
    return label[:MEMBER_LABEL - 7] + "-" + hashlib.sha1(label.encode()).hexdigest()[:6]

class Room:
    """Host-side state for one shared project."""

    def __init__(self, net, slug: str):
        self.net, self.slug = net, slug
        self.proj = net.project_row(slug)
        self.fork = bool(net.fork_slug(slug))  # a git source tree (forkroom.py)
        self._hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=900))
        self._members: tuple[float, list] = (0.0, [])  # cached: every member polls, the list changes slowly
        self.versions: dict[str, str] = {}  # each member's decompdecomp, as its last request said (the host's list)

    @property
    def settings(self) -> dict:
        """visibility: private (an invite link is needed) or public (the room's address is enough); approve: the
        host lets each new member in."""
        c = self.cfg.get("collab") or {}
        return {"visibility": c.get("visibility", "private"), "approve": bool(c.get("approve", False))}

    def configure(self, visibility: str | None = None, approve: bool | None = None) -> dict:
        cfg = self.cfg
        c = cfg.setdefault("collab", {})
        if visibility is not None:
            if visibility not in ("private", "public"):
                raise NetworkError("visibility is private or public")
            c["visibility"] = visibility
        if approve is not None:
            c["approve"] = bool(approve)
        with self.net.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE slug=?", (json.dumps(cfg), self.slug))
        return self.settings

    def pending(self) -> list[dict]:
        return [dict(r) for r in self.net.store.all(
            "SELECT name, created_at FROM agents WHERE origin=? AND owner IS NULL ORDER BY created_at", self.origin + ":pending")]

    def approve(self, name: str, ok: bool = True) -> None:
        with self.net.store.tx() as db:
            row = db.execute("SELECT id FROM agents WHERE name=? AND origin=?", (name, self.origin + ":pending")).fetchone()
            if row is None:
                raise NetworkError(f"nobody called {name} is waiting")
            if ok:
                db.execute("UPDATE agents SET origin=? WHERE id=?", (self.origin, row["id"]))
                self.net._event(db, self.proj["id"], None, "collab", f"{name} joined")
            else:
                db.execute("UPDATE agents SET origin=?, token_hash=? WHERE id=?",
                           (self.origin + ":declined", "declined:" + secrets.token_hex(16), row["id"]))
        self._members = (0.0, [])

    @property
    def cfg(self) -> dict:
        return json.loads(self.net.project_row(self.slug)["config"])

    def open_invite(self, keep: bool = False, **where) -> str:
        """Open the room and return its invite code: a new one, or with `keep` the current one (the room reopening
        after the app restarted, so links people already have keep working). `where`: how it's shared
        (mode="tunnel" or mode="address" with address and port), remembered for reopening."""
        cfg = self.cfg
        old = cfg.get("collab") or {}
        code = old.get("code") if keep and old.get("code") else secrets.token_urlsafe(16)
        cfg["collab"] = {**old, **where, "invite": _hash(code), "code": code, "open": True,
                         "since": old.get("since") or time.time()}
        with self.net.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE slug=?", (json.dumps(cfg), self.slug))
        return code

    def remove(self, name: str) -> None:
        """Take a member out of the room: their token stops working and their claims are freed."""
        with self.net.store.tx() as db:
            row = db.execute("SELECT id FROM agents WHERE name=? AND origin=? AND owner IS NULL", (name, self.origin)).fetchone()
            if row is None:
                raise NetworkError(f"{name} isn't a member of this room")
            db.execute("UPDATE agents SET token_hash=? WHERE id=?", ("removed:" + secrets.token_hex(16), row["id"]))
            db.execute("DELETE FROM claims WHERE agent_id IN (SELECT id FROM agents WHERE owner=? AND origin=?)",
                       (name, self.origin))
            db.execute("UPDATE agents SET origin=? WHERE id=?", (self.origin + ":removed", row["id"]))
            self.net._event(db, self.proj["id"], None, "collab", f"{name} was removed from the room")
        self._members = (0.0, [])

    def close(self) -> None:
        cfg = self.cfg
        if "collab" in cfg:
            cfg["collab"]["open"] = False
            with self.net.store.tx() as db:
                db.execute("UPDATE projects SET config=? WHERE slug=?", (json.dumps(cfg), self.slug))

    def invite_ok(self, code: str) -> bool:
        c = self.cfg.get("collab") or {}
        if not c.get("open"):
            return False
        return c.get("visibility") == "public" or secrets.compare_digest(c.get("invite", ""), _hash(code or ""))

    @property
    def origin(self) -> str:
        return f"collab:{self.slug}"

    def members(self) -> list[dict]:
        at, cached = self._members
        if time.time() - at < 3:
            return cached
        out = self._members_now()
        self._members = (time.time(), out)
        return out

    def _members_now(self) -> list[dict]:
        # in the order they joined: each member's colour on every computer's screen (agents.js: computerColour)
        rows = self.net.store.all("SELECT id, name, created_at, last_seen FROM agents WHERE origin=? AND owner IS NULL "
                                  "ORDER BY created_at, id", self.origin)
        out = []
        for r in rows:
            agents = self.net.store.all("SELECT id, name FROM agents WHERE origin=? AND owner=?", self.origin, r["name"])
            ids = [a["id"] for a in agents] or [-1]
            matched = self.net.store.one(
                f"SELECT COUNT(*) AS n FROM functions WHERE matched_agent_id IN ({','.join('?' * len(ids))})", *ids)["n"]
            working = [c["name"] for c in self.net.store.all(
                f"SELECT f.name FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id IN "
                f"({','.join('?' * len(ids))})", *ids)]
            out.append({"name": r["name"], "joined": r["created_at"], "last_seen": r["last_seen"],
                        "online": bool(r["last_seen"]) and time.time() - r["last_seen"] < 30,
                        "agents": [a["name"].split(".", 1)[1] for a in agents], "matched": matched, "working": working,
                        "version": self.versions.get(r["name"], "")})
        return out

    def join(self, name: str, sha1: str) -> tuple[str, str]:
        """New member: (token, the name they got; a taken name gets a number)."""
        _check_name(name)
        cfg = self.cfg
        want = forkroom.project_identity(cfg)
        if want and sha1 != want:
            what = (f"{cfg['rom']['title']}, {cfg['rom']['game_code']}" if not self.fork
                    else f"{self.proj['name']}, {cfg.get('version') or 'the same version'}")
            raise NetworkError("that isn't the same game: everyone in a room needs their own copy of exactly this "
                               f"game ({what}, same version)")
        token = "dn_" + secrets.token_urlsafe(24)
        waiting = self.settings["approve"]
        with self.net.store.tx() as db:
            # #80: a join that stopped after the host registered it (an import failed, or the app quit) left its
            # member behind with a token nobody kept. The next join with that name takes the empty member over
            # instead of becoming "name2". Only a member of this room that never connected and has no work of its
            # own is reused; a connected, removed or declined one keeps its place, and the name gets a number.
            reuse = db.execute(
                "SELECT id, name FROM agents WHERE lower(name)=lower(?) AND owner IS NULL AND last_seen IS NULL "
                "AND origin IN (?, ?)", (name, self.origin, self.origin + ":pending")).fetchone()
            if reuse is not None and (
                    db.execute("SELECT 1 FROM agents WHERE origin=? AND owner=?", (self.origin, reuse["name"])).fetchone()
                    or db.execute("SELECT 1 FROM functions WHERE matched_agent_id=?", (reuse["id"],)).fetchone()):
                reuse = None
            base, n = name, 2
            if reuse is not None:
                name = reuse["name"]
            else:
                while db.execute("SELECT 1 FROM agents WHERE lower(name)=lower(?)", (name,)).fetchone():
                    name, n = f"{base}{n}", n + 1
            if reuse is not None:
                db.execute("UPDATE agents SET token_hash=?, created_at=?, origin=? WHERE id=?",
                           (hash_token(token), time.time(),
                            self.origin + (":pending" if waiting else ""), reuse["id"]))
            else:
                db.execute("INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin) VALUES(?,?,?,?,1,?)",
                           (name, None, hash_token(token), time.time(), self.origin + (":pending" if waiting else "")))
            if waiting:
                self.net._event(db, self.proj["id"], None, "collab", f"{name} asks to join")
            else:
                self.net._event(db, self.proj["id"], None, "collab", f"{name} joined")
        self._members = (0.0, [])
        return token, name

    def member(self, request: Request, counted: bool = True) -> Agent:
        """The member asking. `counted`: their request counts toward "slow down"; the heartbeat doesn't, since a
        refused one shows the host as gone to everyone in the room."""
        version = request.headers.get(VERSION_HEADER)
        check_same(own(), (version, request.headers.get(COMMIT_HEADER), request.headers.get(PROTOCOL_HEADER)))
        token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        try:
            agent = self.net.authenticate(token or None)
        except NetworkError:  # declined or taken out: their token was retired ("invalid API token" said nothing)
            raise NetworkError(NOT_MEMBER) from None
        row = self.net.store.one("SELECT origin, owner FROM agents WHERE id=?", agent.id)
        if row["origin"] == self.origin + ":pending":
            raise NetworkError(WAITING)
        if row["origin"] != self.origin or row["owner"] is not None:
            raise NetworkError(NOT_MEMBER)
        self.versions[agent.name] = version or ""
        if not counted:
            return agent
        hits = self._hits[agent.name]
        now = time.time()
        hits.append(now)
        if len(hits) == hits.maxlen and now - hits[0] < 60:
            raise NetworkError("slow down")
        return agent

    def agent_for(self, member: Agent, label: str) -> Agent:
        """The host-side identity of one of a member's agents, e.g. alex.claude-1. One per agent: names cut to 24
        characters made a laptop's opencode-deepseek-v4.1-flash-high-1, -2, -3... one agent on the host, which holds
        one claim, so each of them was handed the others' function back and released what another was working on."""
        label = member_label(label)
        name = f"{member.name}.{label}"
        row = self.net.store.one("SELECT id FROM agents WHERE name=?", name)
        if row is None:
            with self.net.store.tx() as db:
                aid = db.execute("INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin) VALUES(?,?,?,?,1,?)",
                                 (name, member.name, "remote:" + secrets.token_hex(16), time.time(), self.origin)).lastrowid
            return Agent(aid, name, member.name, True)
        return Agent(row["id"], name, member.name, True)

    def _events(self, e: int, fresh: bool) -> dict:
        """The events after the guest's cursor, a page at a time, and how many more wait (`behind`: the guest's
        "getting the host's work" counts it down). A guest that just joined (`fresh`) starts at the newest: the
        room's whole history landed in its feed and notifications as if it had all just happened."""
        pid, store = self.proj["id"], self.net.store
        if fresh:
            last = store.one("SELECT COALESCE(MAX(id), 0) AS m FROM events WHERE project_id=?", pid)["m"]
            return {"e": last, "events": [], "behind": 0}
        events = [dict(ev) for ev in store.all(
            "SELECT e.id, e.kind, e.detail, e.created_at, a.name AS agent FROM events e LEFT JOIN agents a "
            "ON a.id=e.agent_id WHERE e.project_id=? AND e.id>? ORDER BY e.id LIMIT ?", pid, e, EVENTS_PAGE)]
        last = events[-1]["id"] if events else e
        behind = store.one("SELECT COUNT(*) AS n FROM events WHERE project_id=? AND id>?", pid, last)["n"] \
            if len(events) == EVENTS_PAGE else 0
        return {"e": last, "events": events, "behind": behind}

    def state(self, e: int, a: int, ctx_version: int, member: Agent, fresh: bool = False, compiler: str = "",
              aside: str = "", readable: str = "", matched: str = "", layout: str = "", n: int = 0) -> dict:
        """What changed since the guest's cursors: work product only, never ROM-derived data. `compiler`, `aside`,
        `readable` and `layout`: digests of the room's compiler settings, set-aside functions, readable functions and
        function layout as the guest last had them; `matched`: the digest of the guest's own matched functions; `n`:
        the newest note it has. Each is sent again when it changed.

        The guest's copy follows these, not the events: a match was sent only with its "match" event, so one renamed
        before the guest read the event (a guest catching up after a while away), one the host opened again (Check
        again, a compiler change) or polished C tidied later never reached it, nor did notes (they have no event) or
        a boundary cut (its event wasn't one of the layout's)."""
        if self.fork:
            return self._fork_state(e, a, member, fresh, readable, aside, n)
        pid = self.proj["id"]
        net = self.net
        with net.store.tx() as db:
            net._expire_claims(db)
        out: dict = self._events(e, fresh)
        if (digest := _digest(items := matched_items(net.store, pid))) != matched:
            out["matched_set"] = {"digest": digest, "items": items}
        out.update(self._best(a))
        functions = [dict(r) for r in net.store.all(
            "SELECT name, vram, size FROM functions WHERE project_id=? ORDER BY vram, name", pid)]
        symbols = sorted(net.layout_symbols(pid), key=lambda s: (s["address"], s["name"]))
        if (digest := _digest([functions, symbols])) != layout:
            out["layout"] = {"digest": digest, "functions": functions, "symbols": symbols}
        ctx = net._context(pid)
        if ctx["version"] != ctx_version:
            out["context"] = {"version": ctx["version"], "header": ctx["header"]}
        out.update(self._notes(n))
        out["claims"] = [dict(r) for r in net.store.all(
            "SELECT f.name, f.vram, a.name AS agent FROM claims c JOIN functions f ON f.id=c.function_id JOIN agents a "
            "ON a.id=c.agent_id WHERE f.project_id=?", pid)]
        cfg = net.cfg(net.project_row(self.slug))
        settings = {"compiler": cfg["compiler"], "compiler_ranges": cfg.get("compiler_ranges") or []}
        if (digest := _digest(settings)) != compiler:
            out["compiler"] = settings | {"digest": digest}
        out.update(self._set_aside(aside))
        out.update(self._readable(readable))  # (their C is the matched C, in `matched_set`)
        out["members"] = self.members()
        return out

    def _best(self, a: int) -> dict:
        """Open functions' best attempts made since the guest's cursor `a`, by name (overlays share addresses). The
        cursor is read first: an attempt committed between the two reads was skipped for good."""
        pid, store = self.proj["id"], self.net.store
        last = store.one("SELECT MAX(t.id) AS m FROM attempts t JOIN functions f ON f.id=t.function_id "
                         "WHERE f.project_id=?", pid)["m"] or 0
        rows = store.all("SELECT f.name, f.best_score, f.best_source FROM attempts t JOIN functions f "
                         "ON f.id=t.function_id WHERE f.project_id=? AND t.id>? AND t.id<=? AND f.status='open' "
                         "AND f.best_source IS NOT NULL AND f.best_score IS NOT NULL GROUP BY f.id", pid, a, last)
        return {"a": max(a, last),
                "best": [{"name": r["name"], "score": r["best_score"], "source": r["best_source"]} for r in rows]}

    def _notes(self, n: int) -> dict:
        """Notes newer than the guest's newest (`n`). They were sent only with a "note" event, which nothing makes:
        a guest got the notes there were when it joined, and none after."""
        rows = self.net.store.all(
            "SELECT n.id, n.text, n.created_at, f.name AS function, a.name AS agent FROM notes n LEFT JOIN functions f "
            "ON f.id=n.function_id LEFT JOIN agents a ON a.id=n.agent_id WHERE n.project_id=? AND n.id>? ORDER BY n.id",
            self.proj["id"], n)
        return {"notes": [dict(r) for r in rows], "n": rows[-1]["id"] if rows else n}

    def _readable(self, readable: str) -> dict:
        names = [r["name"] for r in self.net.store.all(
            "SELECT name FROM functions WHERE project_id=? AND status='matched' AND readable=1 ORDER BY name",
            self.proj["id"])]
        if (digest := _digest(names)) == readable:
            return {}
        return {"readable": {"digest": digest, "names": names}}

    def _set_aside(self, aside: str) -> dict:
        """{"set_aside": the host's set-aside functions, each with why} when the guest's digest (`aside`) differs. By
        name: overlays share addresses (a GameCube game's REL modules, an N64 game's overlays), and by vram an open
        twin was set aside on the guest."""
        from .engine.rooms import SET_ASIDE_WHY

        rows = self.net.store.all("SELECT name AS k, meta FROM functions WHERE project_id=? AND status='asm' "
                                  "ORDER BY name", self.proj["id"])
        if (digest := _digest([r["k"] for r in rows])) == aside:
            return {}
        return {"set_aside": {"digest": digest, "functions": [
            [r["k"], {k: v for k, v in json.loads(r["meta"] or "{}").items() if k in SET_ASIDE_WHY}] for r in rows]}}

    def _fork_state(self, e: int, a: int, member: Agent, fresh: bool = False, readable: str = "", aside: str = "",
                    n: int = 0) -> dict:
        """A git project's room: events, matches (by name), claims and notes; the tree itself travels as bundles
        (GET /collab/bundle) when `head` moves."""
        pid, net = self.proj["id"], self.net
        with net.store.tx() as db:
            net._expire_claims(db)
        out: dict = self._events(e, fresh)
        events = out["events"]
        names = {ev["detail"] for ev in events if ev["kind"] == "match"}
        if e == 0 or fresh or names:
            rows = net.store.all("SELECT f.name, a.name AS agent FROM functions f LEFT JOIN agents a ON a.id=f.matched_agent_id "
                                 "WHERE f.project_id=? AND f.status='matched'", pid)
            out["matched"] = [dict(r) for r in rows if e == 0 or fresh or r["name"] in names]
        out.update(self._notes(n))
        # best attempts aren't committed, so no bundle carried them: a member's agent started from nothing on a
        # function another member's had at 98%
        out.update(self._best(a))
        out["claims"] = [dict(r) for r in net.store.all(
            "SELECT f.name, f.vram, a.name AS agent FROM claims c JOIN functions f ON f.id=c.function_id JOIN agents a "
            "ON a.id=c.agent_id WHERE f.project_id=?", pid)]
        out["head"] = forkroom.head(Path(self.proj["root"]))
        out["branch"] = forkroom.branch(Path(self.proj["root"]))
        out["members"] = self.members()
        out.update(self._readable(readable))  # (the readable C itself comes with the host's commits)
        # what the host set aside (assembly, a library's code, what agents agreed no C makes): never sent, a GameCube
        # room's guest counted it as open code, and its progress read well below the host's
        out.update(self._set_aside(aside))
        return out


def host_app(net, rooms: dict[str, Room]) -> Starlette:
    """The public side of a shared project, served through the tunnel."""

    def room_for(request: Request) -> Room:
        slug = request.query_params.get("room") or request.headers.get("x-room", "")
        if not slug and len(rooms) == 1:  # a public room's bare address
            slug = next(iter(rooms))
        room = rooms.get(slug)
        if room is None:
            raise NetworkError(ROOM_CLOSED)
        return room

    async def body(request: Request) -> dict:
        # read up to the limit, whatever Content-Length says: a chunked request has none, and the whole of it was
        # buffered and parsed before anyone asked who sent it
        data = bytearray()
        async for chunk in request.stream():
            data += chunk
            if len(data) > MAX_BODY:
                raise NetworkError("request too large")
        try:
            data = json.loads(data or b"{}")
        except ValueError:
            raise NetworkError("invalid request") from None
        if not isinstance(data, dict):
            raise NetworkError("invalid request")
        return data

    import anyio

    # A GameCube room went "waiting for the host" whenever its guest's polishing helpers ran, and came back when
    # they stopped, with nothing in the host's log. Every room request and every one of the host's own helpers' tool
    # calls shared anyio's default 40 threads; each polishing rewrite rebuilt the whole project under its lock, and
    # the calls waiting for that lock held all 40, so the guest's heartbeat (whoami) queued past its 10 seconds. The
    # room's work has threads of its own now, and who's asking is checked on a few nothing slow ever holds.
    checks = anyio.CapacityLimiter(8)  # (room.member: a token and a row; and whoami)
    work = anyio.CapacityLimiter(40)
    # a member's better attempts, sent in the background as they come: each is recorded under the project's lock,
    # which a polishing rebuild holds for a while, and enough of them waiting held all 40 of `work` and the room's
    # state, claims and matches queued past the guests' timeout
    reports = anyio.CapacityLimiter(4)

    jobs: dict[str, tuple[str, asyncio.Future, float]] = {}  # job id -> (the member's name, its work, when it ended)

    def answer(task: asyncio.Future) -> JSONResponse:
        e = task.exception()
        if e is None:
            return JSONResponse(task.result())
        if isinstance(e, NetworkError):
            return JSONResponse({"error": str(e)}, status_code=400)
        if isinstance(e, (TypeError, ValueError, sqlite3.InterfaceError, sqlite3.ProgrammingError)):
            # a value of the wrong kind (a list for a name, a word for a score): the member's request, not the
            # host, is wrong, and "host answered 500" said neither
            return JSONResponse({"error": f"invalid request: {e}"}, status_code=400)
        logger.error("room request failed", exc_info=e)
        return JSONResponse({"error": "the host's app failed doing this; its log says why"}, status_code=500)

    async def within(task: asyncio.Future, member, key: str = "", what: str = "") -> JSONResponse:
        """The answer when the work ends within ANSWER_WITHIN seconds; otherwise a job to ask after (202). The work
        goes on either way: a member that stopped waiting doesn't undo what the host did."""
        try:
            await asyncio.wait_for(asyncio.shield(task), ANSWER_WITHIN)
        except asyncio.TimeoutError:
            if not key:  # (the log says which requests take long: a room's host logged no times, nor nginx)
                key = secrets.token_urlsafe(12)
                began = time.monotonic() - ANSWER_WITHIN  # (it began that long ago)
                logger.info("%s: %s took over %ss; answered when it ends", member.name if member else "a member",
                            what, ANSWER_WITHIN)
                task.add_done_callback(lambda _t: logger.info("%s: %s ended after %.0fs", member.name if member else
                                                               "a member", what, time.monotonic() - began))
            jobs[key] = (member.name if member else "", task, 0.0)
            return JSONResponse({"job": key}, status_code=202)
        except Exception:  # noqa: BLE001 (its exception is the answer)
            pass
        jobs.pop(key, None)
        return answer(task)

    def forget_old_jobs() -> None:
        now = time.time()
        for k, (who, task, ended) in list(jobs.items()):
            if task.done() and not ended:
                jobs[k] = (who, task, now)
            elif ended and now - ended > JOB_KEEP:
                jobs.pop(k, None)

    def endpoint(fn, auth: bool = True, quick: bool = False, limiter=None):
        """`quick`: the answer is as cheap as the check (whoami), so it is made with it, never behind the room's
        work."""
        async def handler(request: Request):
            try:
                room = room_for(request)
                data = await body(request) if request.method == "POST" else dict(request.query_params)
                member = (await anyio.to_thread.run_sync(room.member, request, not quick, limiter=checks)
                          if auth else None)
                if quick:
                    return JSONResponse(fn(room, member, data))
            except NetworkError as e:
                return JSONResponse({"error": str(e)}, status_code=400)
            except (TypeError, ValueError, sqlite3.InterfaceError, sqlite3.ProgrammingError) as e:
                return JSONResponse({"error": f"invalid request: {e}"}, status_code=400)
            forget_old_jobs()
            task = asyncio.ensure_future(anyio.to_thread.run_sync(lambda: fn(room, member, data),
                                                                  limiter=limiter or work))
            return await within(task, member, what=request.url.path)
        return handler

    async def job(request: Request):
        """A member asking after its job: the answer once the work ends, or 202 again after ANSWER_WITHIN."""
        try:
            room = room_for(request)
            member = await anyio.to_thread.run_sync(room.member, request, False, limiter=checks)
        except NetworkError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        key = request.query_params.get("id", "")
        held = jobs.get(key)
        if held is None or held[0] != member.name:
            return JSONResponse({"error": "the host has no such job (it restarted, or answered it already): see "
                                          "whether it was done, and ask again if not"}, status_code=400)
        return await within(held[1], member, key)

    def hello(room, member, q):
        if not room.invite_ok(q.get("invite", "")):
            raise NetworkError("this invite link is no longer valid")
        cfg = room.cfg
        ov = net.overview(room.slug)
        if room.fork:
            return {"room": room.slug, "app_version": __version__, "app_commit": own_commit(), "room_protocol": ROOM_PROTOCOL, **forkroom.hello(net, room.slug), "functions": ov["functions"],
                    "matched": ov["matched"], "members": len(room.members()), **room.settings}
        return {"room": room.slug, "app_version": __version__, "app_commit": own_commit(), "room_protocol": ROOM_PROTOCOL, "kind": "rom", "title": cfg["rom"]["title"], "game_code": cfg["rom"]["game_code"],
                "region": cfg["rom"]["region"], "sha1": cfg["rom"]["sha1"], "compiler": cfg["compiler"],
                "functions": ov["functions"], "matched": ov["matched"], "members": len(room.members()),
                **room.settings}

    def join(room, member, d):
        if not room.invite_ok(str(d.get("invite", ""))):
            raise NetworkError("this invite link is no longer valid")
        check_same(own(), (d.get("version"), d.get("commit"), d.get("protocol")))
        token, name = room.join(str(d.get("name", "")), str(d.get("sha1", "")))
        return {"token": token, "room": room.slug, "name": name, "waiting": room.settings["approve"]}

    def whoami(room, member, q):
        return {"name": member.name, "room": room.slug, "app_version": __version__}

    def state(room, member, q):
        return room.state(_count(q.get("e")), _count(q.get("a")), _count(q.get("v")), member,
                          q.get("fresh") == "1", str(q.get("k") or ""), str(q.get("s") or ""), str(q.get("r") or ""),
                          str(q.get("m") or ""), str(q.get("l") or ""), _count(q.get("n")))

    def matched(room, member, d):
        """The matching C of the functions a guest asked for by name (what `matched_set` says it lacks or has
        otherwise), a few hundred at a time."""
        names = d.get("names")
        if not isinstance(names, list) or not all(isinstance(x, str) for x in names):
            raise NetworkError("invalid request: names is a list of function names")
        rows = net.store.all(
            "SELECT f.name, f.matched_source, a.name AS agent FROM functions f LEFT JOIN agents a "
            "ON a.id=f.matched_agent_id WHERE f.project_id=? AND f.status='matched' AND f.name IN "
            f"({','.join('?' * len(names[:MATCHED_PAGE]))})", room.proj["id"], *names[:MATCHED_PAGE]) if names else []
        return {"functions": [dict(r) for r in rows]}

    def suggest(room, member, d):
        """A member's agent's suggestion: the host's compiler settings are the room's, so it's the host's to check."""
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.suggest(agent, room.slug, str(d.get("text", "")), str(d.get("compiler") or ""),
                                    str(d.get("flags") or ""), d.get("function") or None, str(d.get("ranges") or ""),
                                    str(d.get("source") or ""))}

    def wait(room, member, d):
        """A member's agent released a function saying it needs another done first: the host hands out the
        functions, so it keeps the wait (that one first, this one after everything else until it matches)."""
        agent = room.agent_for(member, d.get("agent"))
        fn, need = net._function(str(d.get("function", "")), room.slug), net._function(str(d.get("needs", "")), room.slug)
        if fn["id"] != need["id"] and need["status"] == "open":
            net.wait_for(agent, fn, need)
        return {"ok": True}

    def readable(room, member, d):
        """A member's agent polishing: the host hands out what to polish (functions, then files to tidy and review),
        judges each rewrite on its copy and keeps it for the room, as its own agents'. A guest's was its own copy's
        alone: none of its readable C reached the room, and two agents could polish one function."""
        agent = room.agent_for(member, d.get("agent"))
        polish, what = net.readability, d.get("what")
        if what == "claim":
            text = polish.claim(agent, room.slug)
        elif what == "submit":
            text = polish.submit(agent, room.slug, str(d.get("function", "")), str(d.get("source", "")))
        elif what == "tidy_done":
            text = polish.tidy_done(agent, room.slug, str(d.get("unit", "")), str(d.get("summary", "")))
        elif what == "review_done":
            text = polish.review_done(agent, room.slug, str(d.get("unit", "")), str(d.get("findings", "")),
                                      bool(d.get("fixed")))
        else:
            raise NetworkError("polishing: claim, submit, tidy_done or review_done")
        return {"text": text}

    def knowledge(room, member, d):
        """What agents learn about the game, the room's: kept by the host. A member's agents propose and back it
        here (`model`: the model behind the agent, as its own app knows it), and their prompts read it from here."""
        what = d.get("what")
        if what == "prompt":
            return {"text": net.knowledge.for_prompt(room.slug)}
        if what == "list":
            return net.knowledge.listing(room.slug)
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.knowledge.share(agent, room.slug, str(d.get("text") or ""), int(d.get("supports") or 0),
                                            model=str(d.get("model") or ""))}

    def claim(room, member, d):
        agent = room.agent_for(member, d.get("agent"))
        if isinstance(d.get("selection"), dict):
            # the member's work selection for this agent (its order, match percentage, tries, sizes), set on its own
            # app: the host hands out the functions, so the host keeps it. A guest's "untried first" was never sent,
            # and its agent got a function five agents had compiled 25 times
            try:
                net.set_selection(room.slug, agent.name, d["selection"])
            except NetworkError:
                pass  # (one this version can't read: the agent's own strategy, as before)
        fn = net.claim_row(agent, room.slug, d.get("function") or None, str(d.get("strategy") or "easiest"))
        if fn is None:  # what's left and why, as the host's own agents hear it (functions this agent said no C makes,
            # its own releases; the user told when only verdicts are left): a guest got a bare "nothing left"
            return {"function": None, "vram": None, "why": net.nothing_to_claim(agent, net._project(room.slug))}
        return {"function": fn["name"], "vram": fn["vram"]}

    def attempt(room, member, d):
        agent = room.agent_for(member, d.get("agent"))
        if room.fork and d.get("prelude"):  # (autopilot's draft: the declarations it needs, after the includes)
            res = net.forks.attempt(agent, room.slug, str(d.get("function", "")), str(d.get("source", "")),
                                    prelude=str(d["prelude"]))
        else:
            res = net.attempt(agent, str(d.get("function", "")), str(d.get("source", "")), room.slug)
        return {"score": res["score"], "matched": res["matched"]}

    def best(room, member, d):
        """A member's attempt got better: kept as the function's best so far, as reported (no compile here: the host
        only spends its CPU on verifying matches)."""
        agent = room.agent_for(member, d.get("agent"))
        net.apply_reported_best(room.slug, str(d.get("function", "")), int(d.get("score", 0)), str(d.get("source", ""))[:65536], agent)
        return {"ok": True}

    def release(room, member, d):
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.release(agent, str(d.get("function", "")), str(d.get("notes", "")), room.slug,
                                     bool(d.get("not_c")))}

    def context(room, member, d):
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.edit_context(agent, room.slug, str(d.get("old", "")), str(d.get("new", "")),
                                         str(d.get("message", "")), d.get("function") or None)}

    def rename(room, member, d):
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.rename_symbol(agent, room.slug, str(d.get("old", "")), str(d.get("new", "")),
                                          str(d.get("message", "")))}

    def split(room, member, d):
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.split_function(agent, room.slug, str(d.get("function", "")), str(d.get("at", "")),
                                           str(d.get("new_name", "")))}

    def boundary(room, member, d):
        """A member's agent says a function runs on past its end: counted with the host's agents' reports, and cut
        here once enough agree (a ROM project's report waits for the host's user instead)."""
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.request_boundary(agent, room.slug, str(d.get("function", "")), str(d.get("end", "")),
                                             str(d.get("reason", "")))}

    def join_functions(room, member, d):
        """A member's agent says two functions are one: counted with the host's agents' proposals, joined here once
        enough agree (ForkEngine.propose_join)."""
        if not room.fork:
            raise NetworkError("this room's project has no functions to join")
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.forks.propose_join(agent, room.slug, str(d.get("function", "")),
                                               str(d.get("with_function", "")), str(d.get("reason", "")))}

    def join_files(room, member, d):
        if not room.fork:
            raise NetworkError("this room's project has no files to join")
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.forks.join_files(agent, room.slug, str(d.get("path", "")), str(d.get("with_path", "")))}

    def note(room, member, d):
        """A note on a function; one on no function is knowledge for every agent, so it needs two models' agreement
        like any agent's (knowledge.py), a member's agents included."""
        agent = room.agent_for(member, d.get("agent"))
        if not d.get("function"):
            return {"text": net.knowledge.share(agent, room.slug, str(d.get("text", "")))}
        return {"text": net.add_note(agent, room.slug, str(d.get("text", "")), d["function"])}

    def edit(room, member, d):
        """A member's edit of a git project's file (a header, a new or shared source file): made and checked here."""
        if not room.fork:
            raise NetworkError("this room's project has no files to edit")
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.forks.edit_file(agent, room.slug, str(d.get("path", "")), str(d.get("old", "")),
                                            str(d.get("new", "")), str(d.get("message", "")),
                                            more=d.get("more") if isinstance(d.get("more"), list) else None)}

    def try_compiler(room, member, d):
        """A member's agent's try_compiler, on the host's copy: its build is the room's."""
        if not room.fork:
            raise NetworkError("this room's project has no files of their own compilers")
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.forks.try_compiler(agent, room.slug, str(d.get("function", "")), str(d.get("compiler", "")),
                                               str(d.get("flags", "")), str(d.get("source", "")))}

    def sdk_inline(room, member, d):
        """A member's agent's sdk_inline, from the host's SDK copy into the host's tree: the member's follows."""
        if not room.fork:
            raise NetworkError("this room's project has no source files to put an SDK function in")
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.forks.sdk_inline(agent, room.slug, str(d.get("name", "")), str(d.get("path", "")))}

    def report_library(room, member, d):
        """A member's agent's word that a function is a known library's code: counted here with the host's own
        agents' (LIBRARY_AGENTS), and set aside here, so every copy in the room follows."""
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.report_library(agent, str(d.get("function", "")), str(d.get("library", "")),
                                           str(d.get("why", "")), room.slug)}

    def split_file(room, member, d):
        if not room.fork:
            raise NetworkError("this room's project has no files to split")
        agent = room.agent_for(member, d.get("agent"))
        return {"text": net.forks.split_file(agent, room.slug, str(d.get("path", "")), str(d.get("at", "")),
                                             str(d.get("new_name", "")), str(d.get("data", "")))}

    async def get_bundle(request: Request):
        """The host's commits a member doesn't have yet (a git bundle: tracked files only, never the game)."""
        try:
            room = room_for(request)
            await anyio.to_thread.run_sync(room.member, request, limiter=checks)
            if not room.fork:
                raise NetworkError("this room's project isn't a git tree")
            data = await anyio.to_thread.run_sync(lambda: forkroom.bundle(Path(room.proj["root"]),
                                                                           request.query_params.get("have", "")),
                                                  limiter=work)
        except NetworkError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return Response(data, media_type="application/octet-stream", status_code=200 if data else 204)

    def leave(room, member, d):
        with net.store.tx() as db:
            db.execute("DELETE FROM claims WHERE agent_id IN (SELECT id FROM agents WHERE owner=? AND origin=?)",
                       (member.name, room.origin))
        return {"ok": True}

    async def landing(request: Request):
        return HTMLResponse("<!doctype html><meta charset=utf-8><title>decompdecomp room</title>"
                            "<body style='font:16px system-ui;max-width:36em;margin:4rem auto;padding:0 1rem'>"
                            "<h1>decompdecomp room</h1><p>This is an invite to decompile a game together. Open "
                            "<b>decompdecomp</b>, choose <b>Join a friend</b>, and paste this page's address. "
                            "You'll need your own copy of the game.</p><p>Don't have the app? "
                            "<a href='https://github.com/n-delic/decompdecomp'>decompdecomp</a></p>")

    routes = [
        Route("/", landing), Route("/join/{code}", landing),
        Route("/collab/hello", endpoint(hello, auth=False)),
        Route("/collab/join", endpoint(join, auth=False), methods=["POST"]),
        Route("/collab/state", endpoint(state)),
        Route("/collab/whoami", endpoint(whoami, quick=True)),
        Route("/collab/job", job),
        Route("/collab/matched", endpoint(matched), methods=["POST"]),
        Route("/collab/claim", endpoint(claim), methods=["POST"]),
        Route("/collab/attempt", endpoint(attempt), methods=["POST"]),
        Route("/collab/best", endpoint(best, limiter=reports), methods=["POST"]),
        Route("/collab/release", endpoint(release), methods=["POST"]),
        Route("/collab/suggest", endpoint(suggest), methods=["POST"]),
        Route("/collab/wait", endpoint(wait), methods=["POST"]),
        Route("/collab/knowledge", endpoint(knowledge), methods=["POST"]),
        Route("/collab/readable", endpoint(readable), methods=["POST"]),
        Route("/collab/context", endpoint(context), methods=["POST"]),
        Route("/collab/rename", endpoint(rename), methods=["POST"]),
        Route("/collab/split", endpoint(split), methods=["POST"]),
        Route("/collab/note", endpoint(note), methods=["POST"]),
        Route("/collab/boundary", endpoint(boundary), methods=["POST"]),
        Route("/collab/join_functions", endpoint(join_functions), methods=["POST"]),
        Route("/collab/join_files", endpoint(join_files), methods=["POST"]),
        Route("/collab/leave", endpoint(leave), methods=["POST"]),
        Route("/collab/edit", endpoint(edit), methods=["POST"]),
        Route("/collab/split_file", endpoint(split_file), methods=["POST"]),
        Route("/collab/try_compiler", endpoint(try_compiler), methods=["POST"]),
        Route("/collab/report_library", endpoint(report_library), methods=["POST"]),
        Route("/collab/sdk_inline", endpoint(sdk_inline), methods=["POST"]),
        Route("/collab/bundle", get_bundle),
    ]
    return Starlette(routes=routes)


class Tunnel:
    """A Cloudflare quick tunnel (free, no account) to the collab server."""

    def __init__(self, port: int):
        self.port, self.proc, self.url = port, None, None

    def start(self, log=print, timeout: float = 45) -> str:
        if toolchains.installed("cloudflared") is None:
            toolchains.install("cloudflared", log=log)
        exe = toolchains.path("cloudflared") / "cloudflared"
        self.proc = subprocess.Popen([str(exe), "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{self.port}"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                     errors="replace", creationflags=NO_WINDOW)
        found = threading.Event()

        def read():
            for line in self.proc.stderr:
                m = TUNNEL_URL.search(line)
                if m and not self.url:
                    self.url = m.group(0)
                    found.set()
        threading.Thread(target=read, daemon=True).start()
        if not found.wait(timeout):
            self.stop()
            raise RuntimeError("couldn't open a tunnel (is the internet reachable?)")
        log(f"tunnel open: {self.url}")
        return self.url

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        self.proc, self.url = None, None


# --------------------------------------------------------------------------------------------- guest

def parse_invite(link: str) -> tuple[str, str]:
    """(base url, invite code) from a link like https://abc.trycloudflare.com/join/CODE#room=slug"""
    link = link.strip().rstrip("/")
    if re.match(r"^https?://[^/\s]+$", link):  # a public room's bare address
        return link, "open"
    m = re.match(r"^(https?://[^/\s]+(?::\d+)?)/join/([A-Za-z0-9_-]{4,})(?:#room=([\w-]+))?$", link)
    if not m:
        raise NetworkError("That isn't an invite link. Ask the room's host for theirs: it looks like "
                           "https://….trycloudflare.com/join/….")
    return m.group(1), m.group(2) + (f"#{m.group(3)}" if m.group(3) else "")


class Refused(NetworkError):
    """The host answered, and said no: not let in yet, taken out of the room, a claim someone else has."""

    @property
    def room_wide(self) -> bool:
        """No to anything this member asks (not let in, out, the room closed), not to this one request."""
        return str(self) in (WAITING, NOT_MEMBER, ROOM_CLOSED) or str(self).startswith("no project ")


def _saved_progress_rows(candidates: list[dict], best_comparable: bool):
    """The queue's table rows: what to send for each candidate, and enough of its function to check the host's
    layout after a restart."""
    for candidate in candidates:
        if candidate.get("status") == "matched":
            kind, source, score = "match", candidate.get("matched_source"), None
        else:
            kind, source, score = "best", candidate.get("best_source"), candidate.get("best_score")
        if source is None:
            continue
        yield (candidate["name"], kind, source, score, candidate.get("vram"), candidate.get("size"),
               int(best_comparable))


def _saved_progress_candidate(row) -> dict:
    matched = row["kind"] == "match"
    return {"name": row["name"], "vram": row["vram"], "size": row["size"],
            "status": "matched" if matched else "open",
            "matched_source": row["source"] if matched else None,
            "best_score": None if matched else row["score"],
            "best_source": row["source"] if not matched else None}


def _drop_old_saved_progress(net, proj, db=None) -> None:
    """Remove the queue from projects.config (the old place for it), keeping its rows in the new table."""
    cfg = json.loads(proj["config"])
    link = cfg.get("link")
    if not link or "saved_progress" not in link:
        return
    link.pop("saved_progress", None)
    if db is not None:
        db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        return
    with net.store.tx() as tx:
        tx.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))


def _queued_saved_progress(net, proj, info: dict, room: str, url: str) -> tuple[list[dict], bool] | None:
    """This project's waiting queue: its table rows, or a queue an older version kept in the link's config, moved
    into the table once here so an in-flight queue from before the update isn't lost. A queue for another room
    stays with that room (the old config queue was dropped the same way when the link changed)."""
    old = info.get("saved_progress")
    store = getattr(net, "store", None)
    try:
        pid = proj["id"]
    except (KeyError, IndexError, TypeError):
        pid = None
    if pid is None or store is None or not hasattr(store, "all"):
        return (list(old["candidates"]), bool(old.get("best_comparable"))) if old and old.get("candidates") else None
    rows = store.all("SELECT name, kind, source, score, vram, size, best_comparable, room, url FROM saved_progress "
                     "WHERE project_id=? ORDER BY name", pid)
    if rows and (rows[0]["room"] != room or rows[0]["url"] != url):
        with store.tx() as db:
            db.execute("DELETE FROM saved_progress WHERE project_id=?", (pid,))
        rows = []
    if rows:
        if old is not None:
            _drop_old_saved_progress(net, proj)
        return [_saved_progress_candidate(row) for row in rows], bool(rows[0]["best_comparable"])
    if old and old.get("candidates"):
        candidates = [dict(c) for c in old["candidates"]]
        best_comparable = bool(old.get("best_comparable"))
        with store.tx() as db:
            db.executemany("INSERT OR REPLACE INTO saved_progress(project_id,room,url,name,kind,source,score,vram,"
                           "size,best_comparable) VALUES(?,?,?,?,?,?,?,?,?,?)",
                           [(pid, room, url, *row) for row in _saved_progress_rows(candidates, best_comparable)])
            _drop_old_saved_progress(net, proj, db)
        return candidates, best_comparable
    if old is not None:
        _drop_old_saved_progress(net, proj)
    return None


class Link:
    """The guest's connection to a host's room."""

    def __init__(self, net, slug: str, url: str, room: str, token: str, member: str, client: httpx.Client | None = None):
        self.net, self.slug, self.url, self.room, self.token, self.member = net, slug, url.rstrip("/"), room, token, member
        self.client = client or httpx.Client(timeout=httpx.Timeout(60, connect=15))
        proj = net.project_row(slug)
        try:
            self.project_id = proj["id"]
        except (KeyError, IndexError, TypeError):
            self.project_id = None
        info = json.loads(proj["config"]).get("link") or {}
        # kept with the link: from 0 after every restart, the room's whole history came again, twice in the feed
        self.cursor = {"e": 0, "a": 0, "v": 0, "k": "", "s": "", "r": "", "l": "", "n": 0} | (info.get("cursor") or {})
        self.saved = dict(self.cursor)
        self.claims: list[dict] = []
        self.members: list[dict] = []
        self.error = ""
        self.refused = False  # the host's last answer to our sync was no (`error` says why)
        self.host_version = ""  # the host's decompdecomp, as its heartbeat says (the guest's screen)
        self.last_ok = 0.0
        self.last_contact = 0.0  # a heartbeat can answer while applying the host's work is still busy
        self.behind = 0  # events the host still has for us
        self.received = 0  # events caught up so far (with `behind`, how far "getting the host's work" is)
        self.synced = False  # caught up with the host since the app started
        self.saved_progress = _queued_saved_progress(net, proj, info, self.room, self.url)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._saved_progress_lock = threading.RLock()
        self.fork = bool(net.fork_slug(slug))  # a git source tree: follows the host's commits (forkroom.py)
        self.head = info.get("head", "")

    # -- transport

    def _req(self, method: str, path: str, data: dict | None = None) -> dict:
        headers = _auth(self.token, self.room)
        try:
            if method == "GET":
                r = self.client.get(f"{self.url}{path}", params={**(data or {}), "room": self.room}, headers=headers)
            else:
                r = self.client.post(f"{self.url}{path}?room={self.room}", json=data or {}, headers=headers)
        except httpx.HTTPError as e:
            self.error = f"can't reach the host ({type(e).__name__})"
            raise NetworkError(f"the room's host isn't reachable right now: {self.error}") from None
        out = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code == 202 and isinstance(out, dict) and out.get("job"):
            r, out = self._wait_for_job(out["job"])
        if r.status_code != 200:
            said = out.get("error") if isinstance(out, dict) else None
            if not said or r.status_code >= 500 or said == "slow down" or SAME_VERSION in said or SAME_PROTOCOL in said:
                # not the host saying no: a tunnel's error page, the host's own failure, too many requests at once,
                # or one side updated before the other. Each passes by itself; as a refusal it covered the project
                # with "You're not in this room" and dropped the saved work being sent.
                self.error = said or f"the host couldn't answer ({r.status_code})"
                raise NetworkError(f"the room's host couldn't answer right now: {self.error}")
            raise Refused(said)
        self.error, self.last_ok = "", time.time()
        return out

    def _wait_for_job(self, key: str):
        """Ask after work the host goes on with (host_app's jobs) until it ends. A moment the host can't be reached
        doesn't end it: the work goes on there."""
        until, misses = time.time() + JOB_WAIT, 0
        while not self._stop.is_set():
            try:
                r = self.client.get(f"{self.url}/collab/job", params={"id": key, "room": self.room},
                                    headers=_auth(self.token, self.room))
            except httpx.HTTPError as e:
                misses += 1
                if misses > 5 or time.time() > until:
                    self.error = f"can't reach the host ({type(e).__name__})"
                    raise NetworkError("the room's host isn't reachable right now, and it may have done this: see "
                                       f"whether it was done before asking again ({self.error})") from None
                self._stop.wait(min(30, 2 ** misses))
                continue
            misses = 0
            out = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            if r.status_code != 202:
                return r, out
            if time.time() > until:
                raise NetworkError("the room's host is still working on this after an hour: see whether it was done "
                                   "before asking again")
            self.last_ok = time.time()  # (the host answers: busy, not away)
        raise NetworkError("left the room while the host worked on this")

    def _raw(self, path: str, params: dict) -> bytes:
        headers = _auth(self.token, self.room)
        try:
            r = self.client.get(f"{self.url}{path}", params={**params, "room": self.room}, headers=headers,
                                timeout=httpx.Timeout(600, connect=15))
        except httpx.HTTPError as e:
            self.error = f"can't reach the host ({type(e).__name__})"
            raise NetworkError(f"the room's host isn't reachable right now: {self.error}") from None
        if r.status_code == 204:
            return b""
        if r.status_code != 200:
            raise NetworkError((r.json() if r.headers.get("content-type", "").startswith("application/json")
                                else {}).get("error") or f"host answered {r.status_code}")
        self.error, self.last_ok = "", time.time()
        return r.content

    # -- actions, called by RomNetwork for a linked project

    def claim(self, agent: Agent, function: str | None, strategy: str,
              selection: dict | None = None) -> tuple[str | None, str]:
        """(the function the host handed out, or None; and then why: what the host says is left, "" from a host
        that doesn't say). `selection`: the agent's work selection on this computer, which the host applies."""
        said = self._req("POST", "/collab/claim", {"agent": agent.name, "function": function, "strategy": strategy,
                                                   **({"selection": selection} if selection is not None else {})})
        return said["function"], ("" if said["function"] else str(said.get("why") or ""))

    def attempt(self, agent: Agent, function: str, source: str, prelude: str = "") -> dict:
        return self._req("POST", "/collab/attempt", {"agent": agent.name, "function": function, "source": source,
                                                     **({"prelude": prelude} if prelude else {})})

    def call(self, route: str, agent: Agent, /, **data) -> str:
        return self._req("POST", route, {"agent": agent.name, **data}).get("text", "")

    def follow(self) -> str:
        """After the host did what an agent here asked (✅): this copy follows it now, or at the next sync. A pull
        that failed here (a file held open on Windows, the host gone a moment) turned the host's ✅ into an error,
        and the agent did it again on top of the host's change."""
        try:
            self.sync()
        except NetworkError as e:
            logger.info("%s: following the host failed: %s", self.slug, e)
            return f"\n(This copy follows the host's change at the next sync: {e})"
        return ""

    # -- mirroring the host's work into the local project

    def sync(self) -> None:
        with self._lock:
            ask = self.cursor | ({"fresh": 1} if not self.cursor["e"] else {})
            if not self.fork:  # (what this copy has matched: the host sends its own list when they differ)
                ask["m"] = _digest(matched_items(self.net.store, self._pid()))
            try:  # never synced: from the newest event, without the room's history (Room._events)
                st = self._req("GET", "/collab/state", ask)
            except Refused as e:  # not let in yet, or out: the screen says which (status)
                self.error, self.refused = str(e), True
                raise
            self.refused = False
            self.apply(st)
            self.behind = int(st.get("behind") or 0)
            self.received += len(st.get("events") or []) if self.behind or self.received else 0
            self.synced = self.synced or not self.behind
            if self.cursor != self.saved:
                self._save_cursor()
        with self._saved_progress_lock:
            saved_progress = self.saved_progress
            if saved_progress:
                candidates, best_comparable = saved_progress
                _share_saved_progress(
                    self.net, self.slug, self, candidates, fork=self.fork, best_comparable=best_comparable,
                    log=lambda line: logger.info("%s: %s", self.slug, line), sync_room=False,
                    forget=self._forget_saved_progress)
                # every candidate was sent, refused or skipped; a transport failure raised above and kept the rest
                self.saved_progress = None
                self._save_saved_progress()

    def keep_for_later(self, name: str, source: str) -> None:
        """A match the host couldn't take just now (away, restarting for an update): queued with the saved work, sent
        again at the next sync that reaches it. It was this copy's alone: the room's function stayed open and another
        member's agent did it again."""
        row = self.net.store.one("SELECT vram, size FROM functions WHERE project_id=? AND name=?", self._pid(), name)
        candidate = {"name": name, "vram": row["vram"] if row else None, "size": row["size"] if row else None,
                     "status": "matched", "matched_source": source, "best_score": None, "best_source": None}
        with self._saved_progress_lock:
            candidates, best_comparable = self.saved_progress or ([], False)
            self.saved_progress = ([c for c in candidates if c["name"] != name] + [candidate], best_comparable)
            self._save_saved_progress()

    def _save_saved_progress(self) -> None:
        """Keep queued work in its own small table, not in projects.config (parsed on every project access): a guest
        restarted while waiting can still send it."""
        with self._lock:
            proj = self.net.project_row(self.slug)
            cfg = json.loads(proj["config"])
            if "link" not in cfg:
                return
            with self.net.store.tx() as db:
                db.execute("DELETE FROM saved_progress WHERE project_id=?", (proj["id"],))
                if self.saved_progress:
                    candidates, best_comparable = self.saved_progress
                    db.executemany("INSERT OR REPLACE INTO saved_progress(project_id,room,url,name,kind,source,score,"
                                   "vram,size,best_comparable) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                   [(proj["id"], self.room, self.url, *row)
                                    for row in _saved_progress_rows(candidates, best_comparable)])
                if cfg["link"].pop("saved_progress", None) is not None:
                    db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))

    def _forget_saved_progress(self, name: str) -> None:
        """One queued candidate is done (sent, refused, or no longer applicable): drop just its row, so the rest
        still waits. A transport failure leaves it for the next sync."""
        with self._saved_progress_lock:
            pid = self.project_id if self.project_id is not None else self.net.project_row(self.slug)["id"]
            with self.net.store.tx() as db:
                db.execute("DELETE FROM saved_progress WHERE project_id=? AND name=?", (pid, name))
            if self.saved_progress:
                candidates, best_comparable = self.saved_progress
                left = [candidate for candidate in candidates if candidate["name"] != name]
                self.saved_progress = (left, best_comparable) if left else None

    def _save_cursor(self) -> None:
        proj = self.net.project_row(self.slug)
        cfg = json.loads(proj["config"])
        if "link" in cfg:  # (left the room meanwhile: nothing to keep)
            cfg["link"]["cursor"] = self.saved = dict(self.cursor)
            with self.net.store.tx() as db:
                db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))

    def _pid(self) -> int:
        return self.project_id if self.project_id is not None else self.net.project_row(self.slug)["id"]

    def status(self) -> dict:
        """What the guest's screen says: waiting to be let in, out of the room, getting the host's work (how far),
        in the room, the host is away, or the host answers but its work doesn't come (`stuck`: following it fails
        here, `error` says why; the header said "In a room" while helpers waited on it)."""
        last_contact = max(self.last_ok, self.last_contact)
        if self.refused:  # (out: declined, taken out, or the room closed; `error` says which)
            state = "waiting" if self.error == WAITING else "out"
        elif (self.error and not last_contact) or (last_contact and time.time() - last_contact >= ROOM_QUIET):
            state = "offline"  # (never answered yet and no error: just started, getting the host's work)
        elif self.error:
            state = "stuck"
        else:
            state = "connected" if self.synced else "syncing"
        return {"state": state, "received": self.received, "behind": self.behind}

    def apply(self, st: dict) -> None:
        if self.fork:
            return self._apply_fork(st)
        net, slug = self.net, self.slug
        pid = self._pid()
        mine = f"{self.member}."
        if st.get("layout"):  # (first: what follows names the host's functions)
            net.apply_remote_layout(slug, st["layout"]["functions"], st["layout"]["symbols"])
            self.cursor["l"] = st["layout"]["digest"]
        if st.get("context"):
            net.apply_remote_context(slug, st["context"]["header"], st["context"]["version"])
            self.cursor["v"] = st["context"]["version"]
        if st.get("matched_set"):
            self._follow_matches(st["matched_set"]["items"])
        _in_batches(net, st.get("best") or [], lambda b: net.apply_remote_best_named(
            slug, b["name"], b["score"], b["source"]))
        self._apply_notes(st)
        self._feed(pid, st, ("match", "claim", "release", "context", "rename", "split", "collab", "polish",
                             "readable", "reopen", "boundary"))
        if st.get("compiler"):
            net.apply_remote_compiler(slug, st["compiler"])
            self.cursor["k"] = st["compiler"]["digest"]
        if st.get("set_aside"):
            net.apply_remote_set_aside(slug, st["set_aside"]["functions"], key="name")
            self.cursor["s"] = st["set_aside"]["digest"]
        if st.get("readable"):
            net.apply_remote_readable_named(slug, st["readable"]["names"])
            self.cursor["r"] = st["readable"]["digest"]
        self.claims = [c for c in st.get("claims") or [] if not (c["agent"] or "").startswith(mine)]
        self.members = st.get("members") or []
        self.cursor["e"], self.cursor["a"] = st.get("e", self.cursor["e"]), st.get("a", self.cursor["a"])

    def _follow_matches(self, items: list) -> None:
        """This copy's matches become the host's: what the host doesn't have matched opens again here (it reopened
        it, or never confirmed this copy's), and what it has, or has with other C, comes from it."""
        net, slug, pid = self.net, self.slug, self._pid()
        host = {name: mark for name, mark in items}
        local = dict(matched_items(net.store, pid))
        net.reopen_remote(slug, [name for name in local if name not in host])
        want = [name for name, mark in host.items() if local.get(name) != mark]
        for at in range(0, len(want), MATCHED_PAGE):
            rows = self._req("POST", "/collab/matched", {"names": want[at:at + MATCHED_PAGE]}).get("functions") or []
            _in_batches(net, rows, lambda r: net.apply_remote_match_named_source(
                slug, r["name"], r["matched_source"] or "", r["agent"] or "host"))

    def _apply_notes(self, st: dict) -> None:
        net, slug = self.net, self.slug
        _in_batches(net, st.get("notes") or [], lambda n: net.apply_remote_note_named(
            slug, n["function"], n["text"], n["agent"] or "host", n["created_at"]))
        self.cursor["n"] = st.get("n", self.cursor["n"])

    def _feed(self, pid: int, st: dict, kinds: tuple) -> None:
        mine = f"{self.member}."
        for ev in st.get("events") or []:
            if ev["kind"] in kinds and not (ev["agent"] or "").startswith(mine):
                self.net.remote_event(pid, ev["kind"], ev["detail"], ev["agent"] or "host", ev["created_at"])

    def _apply_fork(self, st: dict) -> None:
        """A git project's room: follow the host's commits, then mirror matches, notes, events, claims."""
        net, slug = self.net, self.slug
        pid = net.project_row(slug)["id"]
        mine = f"{self.member}."
        if st.get("head") and st["head"] != self.head:
            self.pull(st.get("branch") or "")
        for m in st.get("matched") or []:
            net.apply_remote_match_named(slug, m["name"], m["agent"] or "host")
        self._apply_notes(st)
        _in_batches(net, st.get("best") or [], lambda b: net.apply_remote_best_named(
            slug, b["name"], b["score"], b["source"]))
        self._feed(pid, st, ("match", "claim", "release", "context", "source", "split", "collab", "link", "polish",
                             "readable", "reopen"))
        if st.get("readable"):
            net.apply_remote_readable_named(slug, st["readable"]["names"])
            self.cursor["r"] = st["readable"]["digest"]
        if st.get("set_aside"):
            net.apply_remote_set_aside(slug, st["set_aside"]["functions"], key="name")
            self.cursor["s"] = st["set_aside"]["digest"]
        self.claims = [c for c in st.get("claims") or [] if not (c["agent"] or "").startswith(mine)]
        self.members = st.get("members") or []
        self.cursor["e"], self.cursor["a"] = st.get("e", self.cursor["e"]), st.get("a", self.cursor["a"])

    def pull(self, ref: str) -> bool:
        """Bring the host's new commits into this tree (while no agent here is building in it), rebuild what
        changed and measure again. Returns whether anything came."""
        forks = self.net.forks
        proj, fp, _ = forks.get(self.slug)
        data = self._raw("/collab/bundle", {"have": self.head})
        tip = "" if data else self._req("GET", "/collab/state", {"e": self.cursor["e"]}).get("head") or self.head
        # no bundle: nothing new, or the host's head is a commit this tree has (the public decomp both started from,
        # with nothing on top yet at the host). Only `head` moved there, and the tree stayed on this member's commits.
        moved = bool(data) or (tip != forkroom.head(fp.root) and forkroom.has_commit(fp.root, tip))
        if moved:
            with forks._tree(proj).exclusive():
                tip = forkroom.pull(fp.root, data, ref or forkroom.branch(fp.root), tip=tip)
                forks._build_all(proj, fp)
        self.head = tip
        forkroom.save_head(self.net, self.slug, tip)
        if moved:
            forks.sync(self.slug, log=lambda *_: None)
        return moved

    def run(self, every: float = 2.0) -> None:
        def heartbeat():
            problem = ""
            while not self._stop.is_set():
                try:
                    # whoami authenticates (refreshing the host's last_seen) without sending or applying work.
                    # Keep its result separate: a live connection must not erase a failed sync or a refusal.
                    r = self.client.get(f"{self.url}/collab/whoami", params={"room": self.room},
                                        headers=_auth(self.token, self.room),
                                        timeout=httpx.Timeout(HEARTBEAT_TIMEOUT, connect=5))
                    if r.status_code != 200:
                        raise NetworkError(f"host answered {r.status_code}")
                    self.last_contact = time.time()
                    said = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                    self.host_version = str(said.get("app_version") or "") if isinstance(said, dict) else ""
                except Exception as e:
                    current = type(e).__name__ if isinstance(e, httpx.HTTPError) else str(e)
                    if current != problem:
                        logger.warning("room %s heartbeat failed: %s; retrying", self.slug, current)
                    problem = current
                else:
                    if problem:
                        logger.info("room %s heartbeat recovered", self.slug)
                    problem = ""
                self._stop.wait(HEARTBEAT_EVERY)

        def loop():
            problem = ""
            while not self._stop.is_set():
                try:
                    self.sync()
                except NetworkError as e:
                    current = str(e)
                    if not self.refused:  # (a pull that failed said nothing: the screen said "In a room")
                        self.error = self.error or current
                    self.behind = 0  # (catching up: the next page at once, but not the same failure, at once, forever)
                    if current != problem:
                        logger.warning("room %s sync failed: %s; retrying", self.slug, current)
                    problem = current
                except Exception as e:  # keep syncing; show the problem in the GUI
                    self.error = f"{type(e).__name__}: {e}"
                    self.behind = 0
                    if self.error != problem:
                        logger.exception("room %s couldn't apply the host's work; retrying", self.slug)
                    problem = self.error
                else:
                    if problem:
                        logger.info("room %s sync recovered", self.slug)
                    problem = ""
                self._stop.wait(0 if self.behind else every)  # catching up: the next page at once
        threading.Thread(target=heartbeat, daemon=True, name=f"room-heartbeat-{self.slug}").start()
        threading.Thread(target=loop, daemon=True, name=f"link-{self.slug}").start()

    def stop(self) -> None:
        self._stop.set()


def _hello(http: httpx.Client, link: str) -> tuple[str, str, dict]:
    url, code = parse_invite(link)
    code = code.split("#", 1)[0]
    room_hint = link.split("#room=", 1)[1] if "#room=" in link else ""
    try:
        r = http.get(f"{url}/collab/hello", params={"invite": code, "room": room_hint})
    except httpx.HTTPError:
        raise NetworkError("can't reach that room: is the host's decompdecomp open and sharing?") from None
    hello = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code != 200:
        raise NetworkError(hello.get("error", "the invite didn't work"))
    check_same((hello.get("app_version"), hello.get("app_commit"), hello.get("room_protocol")), own())
    return url, code, hello


def _linked_project(net, sha1: str | None, room: str):
    for p in net.store.all("SELECT slug, config FROM projects"):
        cfg = json.loads(p["config"])
        if forkroom.project_identity(cfg) == sha1 and (cfg.get("link") or {}).get("room") == room:
            return p["slug"], cfg["link"]
    return None, None


def _saved_progress(net, *, slug: str | None = None, identity: str | None = None,
                    room: str | None = None, url: str | None = None) -> list[dict]:
    candidates = []
    for project in net.store.all("SELECT slug, config FROM projects"):
        if slug is not None and project["slug"] != slug:
            continue
        cfg = json.loads(project["config"])
        if identity is not None and forkroom.project_identity(cfg) != identity:
            continue
        linked = cfg.get("link") or {}
        if room is not None and linked.get("room") is not None:
            linked_url = str(linked.get("url") or "").rstrip("/")
            if linked["room"] != room or (url is not None and linked_url != url.rstrip("/")):
                continue
        proj = net.project_row(project["slug"])
        candidates.extend(dict(row) for row in net.store.all(
            "SELECT f.name, f.vram, f.size, f.status, f.matched_source, f.best_score, f.best_source "
            "FROM functions f WHERE f.project_id=? AND "
            "((f.status='matched' AND f.matched_source IS NOT NULL) OR "
            "(f.status='open' AND f.best_score IS NOT NULL AND f.best_source IS NOT NULL))", proj["id"]))
    return candidates


def _share_saved_progress(net, slug: str, link: Link, candidates: list[dict], *, fork: bool,
                          best_comparable: bool = False, log, sync_room: bool = True,
                          forget=None) -> None:
    """Send stronger saved work to the host; matches are always rechecked there. A candidate the host refuses is
    dropped (and logged) on its own, so it can't wedge the ones after it; only a host we can't reach leaves the rest
    for the next sync."""
    if not candidates:
        return
    # (the whole layout, matches and best attempts, whatever this copy had of them: "l", "m" and "a" say nothing)
    state = link._req("GET", "/collab/state", link.cursor | {"fresh": 1, "l": "", "m": "", "a": 0})
    matched_names = ({name for name, _ in state["matched_set"]["items"]} if state.get("matched_set")
                     else {row["name"] for row in state.get("matched", [])})
    layout = (state.get("layout") or {}).get("functions") or state.get("functions") or []
    host_functions = {row["name"]: row for row in layout}  # (by name: overlays share addresses)
    host_best = {row["name"]: row["score"] for row in state.get("best", [])}
    local_names = set()
    if fork:
        proj = net.project_row(slug)
        local_names = {row["name"] for row in net.store.all("SELECT name FROM functions WHERE project_id=?", proj["id"])}

    def done(candidate: dict) -> None:
        if forget is not None:
            forget(candidate["name"])

    transfers = []
    skipped = 0
    for candidate in candidates:
        if fork:
            function = candidate["name"]
            if candidate["status"] != "matched" or function in matched_names:
                done(candidate)
                continue
            if function not in local_names:
                skipped += 1
                done(candidate)
                continue
        else:
            host_fn = host_functions.get(candidate["name"])
            if host_fn is None or host_fn["size"] != candidate["size"] or host_fn["vram"] != candidate["vram"]:
                skipped += 1
                done(candidate)
                continue
            function = host_fn["name"]
            if function in matched_names:
                done(candidate)
                continue
        if candidate["status"] == "matched":
            transfers.append(("match", function, candidate["matched_source"], None, candidate))
        elif not fork and best_comparable and (host_best.get(function) is None
                                               or candidate["best_score"] < host_best[function]):
            transfers.append(("best", function, candidate["best_source"], candidate["best_score"], candidate))
        else:
            done(candidate)

    matches = best_attempts = 0
    if transfers:
        agent, _ = net.local_agent("saved-progress")
    for kind, function, source, score, candidate in transfers:
        try:
            if kind == "match":
                result = link.attempt(agent, function, source)
                if result.get("matched"):
                    matches += 1
                else:
                    log(f"Saved match for {function} wasn't confirmed by the host (score {result.get('score')}).")
            else:
                link.call("/collab/best", agent, function=function, source=source, score=score)
                best_attempts += 1
        except Refused as e:
            if e.room_wide:  # (no to everything now, not to this candidate: the rest waits for the next sync)
                raise
            log(f"The host refused saved progress for {function}: {e}")
            done(candidate)
        except NetworkError as e:
            log(f"Couldn't send saved progress for {function}: {e}")
            raise
        else:
            done(candidate)

    if sync_room:
        try:
            link.sync()
        except NetworkError as e:
            log(f"Couldn't sync the room after sending saved progress: {e}")
    if matches or best_attempts:
        log(f"The host confirmed {matches} saved match{'es' if matches != 1 else ''}; "
            f"submitted {best_attempts} better attempt{'s' if best_attempts != 1 else ''}.")
    if skipped:
        log(f"Skipped {skipped} saved result{'s' if skipped != 1 else ''} whose function layout or name differs.")


def reconnect(net, slug: str, link: str, log=print, client: httpx.Client | None = None, start: bool = True) -> str:
    """Guest: the host restarted and shared a new link. Reconnect this project as the same member if the host still
    knows us, or join again with the invite."""
    http = client or httpx.Client(timeout=httpx.Timeout(60, connect=15))
    url, code, hello = _hello(http, link)
    proj = net.project_row(slug)
    cfg = json.loads(proj["config"])
    if forkroom.project_identity(cfg) != hello.get("sha1"):
        raise NetworkError(f"that link is for {hello['title']}, a different game than this project")
    info = dict(cfg.get("link") or {})
    if info.get("token"):
        r = http.get(f"{url}/collab/whoami", params={"room": hello["room"]},
                     headers=_auth(info['token'], hello["room"]))
        said = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        # the host knows this token: a member (its name), or one it hasn't let in yet (it waits on, as it was: a
        # new join made "alex2" and left "alex" waiting in the host's list for good)
        if r.status_code == 200 or said.get("error") == WAITING:
            old = net.links.pop(slug, None)
            if old is not None:
                old.stop()
            member = said.get("name") or info.get("member") or "friend"
            # (the same room at a new address: the saved work waiting for it goes there)
            net.link_project(slug, info | {"url": url, "room": hello["room"], "member": member}, client=client,
                             start=start, moved=True)
            log(f"reconnected to {hello['title']} as {member}")
            return slug
    name = info.get("member") or "friend"
    r = http.post(f"{url}/collab/join?room={hello['room']}", json={"invite": code, "name": name, "sha1": hello["sha1"], "version": __version__, "commit": own_commit(), "protocol": ROOM_PROTOCOL})
    joined = _joined(r)
    if r.status_code != 200:
        raise NetworkError(joined.get("error", "couldn't join"))
    if joined["name"].lower() != name.lower():
        log(f"the name {name} was taken in this room: you're {joined['name']}")
    old = net.links.pop(slug, None)
    if old is not None:
        old.stop()
    net.link_project(slug, {"url": url, "room": hello["room"], "token": joined["token"], "member": joined["name"],
                            "host_title": hello["title"], "head": info.get("head", "")}, client=client, start=start)
    log(f"joined {hello['title']} again as {joined['name']}")
    return slug


def _joined(r) -> dict:
    """The host's answer to a join. A tunnel's error page or a proxy in the way answers HTML: it said "Expecting
    value" and left the user nothing to act on."""
    try:
        out = r.json()
    except ValueError:
        out = None
    if not isinstance(out, dict):
        raise NetworkError(f"the room's address answered, but not as a room ({r.status_code}): check the address, or "
                           "try again once the host's app is running")
    return out


def _count(value) -> int:
    """A cursor or count from a request: a number, or "invalid request" (int() of anything else was a 500)."""
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        raise NetworkError("invalid request: a count isn't a number") from None


def matched_items(store, pid: int) -> list[list[str]]:
    """A project's matched functions as [name, a digest of its C]: what a room's guest and host compare (the
    digest of this list), so a match renamed, reopened or tidied on the host reaches the guest too."""
    return [[r["name"], hashlib.sha256((r["matched_source"] or "").encode()).hexdigest()[:16]] for r in store.all(
        "SELECT name, matched_source FROM functions WHERE project_id=? AND status='matched' ORDER BY name", pid)]


def _digest(value) -> str:
    """A short digest of what a room's host sends only when it changed (its compiler settings, its set-aside list)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def _in_batches(net, items: list, apply_one, size: int = 500) -> None:
    """What the host sent, a few hundred at a time: each batch is one commit, and the database isn't held for a whole
    room's worth at once. If a batch fails it is all undone (the next sync does it again)."""
    for at in range(0, len(items), size):
        try:
            with net.store.tx():
                for item in items[at:at + size]:
                    apply_one(item)
        except BaseException:
            net._remote_ids.clear()  # (a member made in the batch that was undone)
            raise


def join_room(net, link: str, name: str, rom: bytes | Path, log=print, client: httpx.Client | None = None,
              start: bool = True) -> str:
    """Guest: check the invite, check the ROM is the same game, import it locally, join, link. Returns the slug.
    If this game is already linked to that room here, reconnect instead (no ROM needed). `rom`: the game's bytes or
    the file (a GameCube or Wii disc is gigabytes: never read whole)."""
    from .. import consoles

    http = client or httpx.Client(timeout=httpx.Timeout(60, connect=15))
    url, code, hello = _hello(http, link)
    slug, _info = _linked_project(net, hello["sha1"], hello["room"])
    if slug:
        return reconnect(net, slug, link, log=log, client=client, start=start)
    if not rom:
        raise NetworkError("pick your own copy of the game to join")
    _check_name(name)  # the host would refuse it after the import: catch it before the slow split
    if hello.get("kind") == "fork":
        return _join_fork(net, http, url, code, hello, name, rom, log, client, start)
    if isinstance(rom, Path):
        rom = rom.read_bytes()
    picked = consoles.identify(rom).read_game(rom)
    if picked.info["sha1"] != hello["sha1"]:
        raise NetworkError(f"this ROM isn't the same as the host's: the room is for {hello['title']} "
                           f"({hello['game_code']}, {hello['region']}), and every member needs their own copy of exactly that version")
    log(f"joining {hello['title']} ({hello['functions']} functions, {hello['matched']} matched)")
    # #80: import before joining, so a join the host refuses (a bad name) or a guest that quits while the game is
    # split never leaves a member behind on the host. An import that was already there stays if the join fails.
    before = {p["slug"] for p in net.store.all("SELECT slug FROM projects")}
    slug = net.import_rom(rom, toolchain=hello["compiler"]["toolchain"], flags=hello["compiler"]["flags"],
                          confirmed=True, log=log)
    try:
        # What travels is worked out before the join: a corrupt progress folder, an unknown compiler or a disk
        # error must not leave a member on the host and an imported project here (#80).
        candidates = _saved_progress(net, slug=slug)
        best_comparable = json.loads(net.project_row(slug)["config"]).get("compiler") == hello["compiler"]
        r = http.post(f"{url}/collab/join?room={hello['room']}", json={"invite": code, "name": name, "sha1": hello["sha1"], "version": __version__, "commit": own_commit(), "protocol": ROOM_PROTOCOL})
        joined = _joined(r)
        if r.status_code != 200:
            raise NetworkError(joined.get("error", "couldn't join"))
    except Exception:
        if slug not in before:  # the project was imported for this join and won't be linked now
            root = net.project_row(slug)["root"]
            net.remove_project(slug)
            shutil.rmtree(root, ignore_errors=True)
        raise
    if joined["name"].lower() != name.lower():
        log(f"the name {name} was taken in this room: you're {joined['name']}")
    # the imported project's saved work goes with us: the host rechecks every match before it counts
    room_link = net.link_project(slug, {"url": url, "room": hello["room"], "token": joined["token"],
                                        "member": joined["name"], "host_title": hello["title"]},
                                 client=client, start=False)
    if candidates:
        room_link.saved_progress = (candidates, best_comparable)
        room_link._save_saved_progress()
        if not joined.get("waiting"):
            try:
                _share_saved_progress(net, slug, room_link, candidates, fork=False,
                                      best_comparable=best_comparable, log=log, sync_room=False,
                                      forget=room_link._forget_saved_progress)
            except NetworkError as e:
                log(f"Couldn't send saved progress yet: {e}")
            else:
                room_link.saved_progress = None
                room_link._save_saved_progress()
                try:
                    room_link.sync()
                except NetworkError as e:
                    log(f"Couldn't sync the room after sending saved progress: {e}")
    if start:
        room_link.run()
    log(f"linked as {joined['name']}: your agents now work with the room")
    return slug


def _join_fork(net, http: httpx.Client, url: str, code: str, hello: dict, name: str, game: bytes | Path, log,
               client: httpx.Client | None, start: bool) -> str:
    """Join a git project's room: the host's tree (forkroom.clone), the member's own copy of the game placed where
    the project wants it and built with the member's own tools, then linked."""
    import tempfile

    from .. import consoles

    _check_name(name)  # the host would refuse it after the download: catch it before any of the work
    if not shutil.which("git"):  # the tree comes as git history (forkroom.clone): Windows has no git of its own
        raise NetworkError("joining this room needs git: install it from https://git-scm.com, then join again")
    tmp = None
    if not isinstance(game, Path):
        tmp = tempfile.NamedTemporaryFile(prefix="decomp-join-", suffix=".game", delete=False)
        tmp.write(game)
        tmp.close()
        game = Path(tmp.name)
    try:
        if hello.get("sha1") and forkroom.game_identity(game) != hello["sha1"]:
            raise NetworkError(f"this isn't the same game as the host's: the room is for {hello['title']} "
                               f"({consoles.name(hello.get('platform'))}, "
                               f"{hello.get('version') or 'the same version'}), and every member needs their own copy of "
                               "exactly that version")
        candidates = _saved_progress(net, identity=hello.get("sha1"), room=hello["room"], url=url) \
            if hello.get("sha1") else []
        log(f"joining {hello['title']} ({hello['functions']} functions, {hello['matched']} matched)")
        r = http.post(f"{url}/collab/join?room={hello['room']}", json={"invite": code, "name": name, "sha1": hello.get("sha1") or "", "version": __version__, "commit": own_commit(), "protocol": ROOM_PROTOCOL})
        joined = _joined(r)
        if r.status_code != 200:
            raise NetworkError(joined.get("error", "couldn't join"))
        if joined["name"].lower() != name.lower():
            log(f"the name {name} was taken in this room: you're {joined['name']}")
        headers = _auth(joined['token'], hello["room"])
        if joined.get("waiting"):  # the host's files come only to members it let in
            log("waiting for the host to let you in")
            _wait_to_be_let_in(http, url, hello["room"], headers)

        def get_bundle(have: str) -> bytes:
            res = http.get(f"{url}/collab/bundle", params={"have": have, "room": hello["room"]}, headers=headers,
                           timeout=httpx.Timeout(600, connect=15))
            if res.status_code == 204:
                return b""
            if res.status_code != 200:
                raise NetworkError((res.json() if res.headers.get("content-type", "").startswith("application/json")
                                    else {}).get("error") or "the host couldn't send the project")
            return res.content

        slug = net.forks._free_slug(re.sub(r"[^a-z0-9]+", "-", hello["title"].lower()).strip("-")[:40] or "room")
        dest = net.workspace / slug
        try:
            forkroom.clone(dest, hello, get_bundle, log=log)
            forkroom.register_member(net, slug, dest, hello, hello["title"])
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        info = {"url": url, "room": hello["room"], "token": joined["token"], "member": joined["name"],
                "host_title": hello["title"], "head": forkroom.head(dest)}
        room_link = net.link_project(slug, info, client=client, start=False)  # its agents wait for the room from the start
        log("building the project with your copy of the game and your tools")
        net.forks.setup(slug, game, game.name if tmp is None else "", log=log, move=tmp is not None)
        if candidates:
            room_link.saved_progress = (candidates, False)
            room_link._save_saved_progress()
            try:
                _share_saved_progress(net, slug, room_link, candidates, fork=True, log=log, sync_room=False,
                                      forget=room_link._forget_saved_progress)
            except NetworkError as e:
                log(f"Couldn't send saved progress yet: {e}")
            else:
                room_link.saved_progress = None
                room_link._save_saved_progress()
                try:
                    room_link.sync()
                except NetworkError as e:
                    log(f"Couldn't sync the room after sending saved progress: {e}")
        if start:
            room_link.run()
        log(f"linked as {joined['name']}: your agents now work with the room")
        return slug
    finally:
        if tmp is not None:
            Path(tmp.name).unlink(missing_ok=True)


def _wait_to_be_let_in(http: httpx.Client, url: str, room: str, headers: dict) -> None:
    end = time.monotonic() + LET_IN_WAIT
    while time.monotonic() < end:
        try:
            r = http.get(f"{url}/collab/whoami", params={"room": room}, headers=headers)
        except httpx.HTTPError:  # the host's connection blinked: look again
            r = None
        if r is not None and r.status_code == 200:
            return
        error = (r.json() if r is not None and r.headers.get("content-type", "").startswith("application/json")
                 else {}).get("error", WAITING)
        if error != WAITING:
            raise NetworkError(f"the host didn't let you in ({error})")
        time.sleep(LET_IN_EVERY)
    raise NetworkError("the host hasn't let you in yet: join again once they have")


def cloudflared_available() -> bool:
    return toolchains.get("cloudflared").supported or bool(shutil.which("cloudflared"))


_addresses: tuple[float, list[dict]] = (0.0, [])


def local_addresses() -> list[dict]:
    """Addresses teammates might reach this computer at: the LAN address, and Tailscale's when it's installed."""
    global _addresses
    if time.time() - _addresses[0] < 600:
        return _addresses[1]
    _addresses = (time.time(), _local_addresses())
    return _addresses[1]


def _local_addresses() -> list[dict]:
    import socket

    out = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # no packet is sent: this only picks the outgoing interface
            ip = sock.getsockname()[0]
        if not ip.startswith("127."):
            out.append({"label": "this network (LAN)", "address": f"http://{ip}:6481"})
    except OSError:
        pass
    ts = shutil.which("tailscale")
    if ts:
        try:
            res = subprocess.run([ts, "status", "--json"], capture_output=True, text=True, timeout=5,
                                 encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
            me = json.loads(res.stdout).get("Self") or {}
            name = (me.get("DNSName") or "").rstrip(".")
            ips = [a for a in me.get("TailscaleIPs") or [] if "." in a]
            if name or ips:
                out.append({"label": "Tailscale (your tailnet)", "address": f"http://{name or ips[0]}:6481"})
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    return out
