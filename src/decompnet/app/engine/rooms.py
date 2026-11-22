"""Rooms (collab.py), the engine's side: a project linked to a friend's room forwards claims and attempts to
the host, and the host's events (matches, notes, the header, the layout) arrive here.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time

from ...network import NetworkError
from ...rom.symbols import AUTO_NAME, Symbol

# what says why a function is set aside (network.set_aside): what a room's host sends with each
SET_ASIDE_WHY = ("asm_code", "asm_twin", "not_c", "library", "set_aside", "good_enough")


class RoomMixin:
    def link_project(self, slug: str, info: dict, client=None, start: bool = True, moved: bool = False):
        """`moved`: the same room at a new address (the host knows this member's token there), so the saved work
        waiting for it goes there too: with a quick tunnel the address is new every time the host starts, and the
        queue was dropped as another room's."""
        from ..collab import Link

        proj = self._project(slug)
        cfg = json.loads(proj["config"])  # a copy of its own: changed below
        old_link = cfg.get("link") or {}
        same_room = old_link.get("room") == info.get("room") and (moved or (
            str(old_link.get("url") or "").rstrip("/") == str(info.get("url") or "").rstrip("/")))
        if moved:
            with self.store.tx() as db:
                db.execute("UPDATE saved_progress SET url=? WHERE project_id=? AND room=?",
                           (str(info.get("url") or "").rstrip("/"), proj["id"], info.get("room")))
        queued = old_link.get("saved_progress") if same_room else None
        info = dict(info)
        info.pop("saved_progress", None)
        if queued:
            info["saved_progress"] = queued
        cfg["link"] = info
        with self.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        link = Link(self, slug, info["url"], info["room"], info["token"], info["member"], client=client)
        if (old := self.links.get(slug)) is not None:  # (a new link for it: the old one stops asking the host)
            old.stop()
        self.links[slug] = link
        if start:
            link.run()
        return link

    def restore_links(self) -> None:
        for p in self.store.all("SELECT slug, config FROM projects"):
            info = json.loads(p["config"]).get("link")
            if info and p["slug"] not in self.links:
                if not all(info.get(k) for k in ("url", "room", "token", "member")):
                    # (what a room left mid-sync could leave: never a reason the app doesn't start)
                    logging.getLogger("decompdecomp").warning("%s: its room link is incomplete; not reconnecting",
                                                              p["slug"])
                    continue
                self.link_project(p["slug"], info)

    def remove_project(self, slug: str) -> int:
        """A project deleted while in a room leaves it: its link kept asking the host (who showed the member online,
        its agents' claims held) and, joined again under the same name, wrote the old room's work into the new copy.
        One it shares closes (its guests are told "this room is closed")."""
        if slug in self.links:
            self.unlink(slug)
        if (room := self.rooms.pop(slug, None)) is not None:
            room.close()
        return super().remove_project(slug)

    def unlink(self, slug: str) -> None:
        link = self.links.pop(slug, None)
        if link is not None:
            link.stop()
            try:
                link._req("POST", "/collab/leave", {})
            except NetworkError:
                pass
        proj = self._project(slug)
        cfg = json.loads(proj["config"])  # a copy of its own: changed below
        cfg.pop("link", None)
        with self.store.tx() as db:
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))

    def _link(self, project: str | None):
        if not self.links:
            return None
        try:
            return self.links.get(self._project(project)["slug"])
        except NetworkError:
            return None

    def _remote_agent(self, name: str) -> int:
        label = "@" + name
        if label in self._remote_ids:
            return self._remote_ids[label]
        row = self.store.one("SELECT id FROM agents WHERE name=?", label)
        if row is None:
            with self.store.tx() as db:
                aid = db.execute("INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin) VALUES(?,?,?,?,1,?)",
                                 (label, "room", "remote:" + secrets.token_hex(16), time.time(), "remote")).lastrowid
        else:
            aid = row["id"]
        self._remote_ids[label] = aid
        return aid

    def remote_event(self, project_id: int, kind: str, detail: str, agent_name: str, created_at: float) -> None:
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                       (project_id, aid, kind, detail, created_at))

    def apply_remote_match(self, slug: str, vram: int, source: str, agent_name: str) -> None:
        proj = self._project(slug)
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            row = db.execute("SELECT id, status FROM functions WHERE project_id=? AND vram=?", (proj["id"], vram)).fetchone()
            if row is None or row["status"] == "matched":
                return
            db.execute("UPDATE functions SET status='matched', matched_source=?, matched_agent_id=?, matched_at=?, "
                       "best_score=0, best_source=? WHERE id=?", (source, aid, time.time(), source, row["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (row["id"],))

    def apply_remote_match_named_source(self, slug: str, name: str, source: str, agent_name: str) -> None:
        """A ROM room's match by name (overlays share addresses: by vram, a twin got the other's C), with the host's
        C: a function matched here already takes it too (the host polished or tidied it since)."""
        proj = self._project(slug)
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            row = db.execute("SELECT id, status, matched_source FROM functions WHERE project_id=? AND name=?",
                             (proj["id"], name)).fetchone()
            if row is None:
                return
            if row["status"] == "matched":
                if row["matched_source"] != source:
                    db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?",
                               (source, source, row["id"]))
                return
            db.execute("UPDATE functions SET status='matched', matched_source=?, matched_agent_id=?, matched_at=?, "
                       "best_score=0, best_source=? WHERE id=?", (source, aid, time.time(), source, row["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (row["id"],))

    def reopen_remote(self, slug: str, names: list[str]) -> None:
        """Functions matched here that the room's host has open: it opened them again (Check again, a compiler
        change), or never confirmed this copy's match. Their C stays as the best attempt. A guest kept them matched:
        its progress read higher than the room's, and the host handing one out failed the claim here."""
        if not names:
            return
        proj = self._project(slug)
        with self.store.tx() as db:
            for name in names:
                db.execute("UPDATE functions SET status='open', best_source=matched_source, best_score=NULL, "
                           "best_agent_id=matched_agent_id, matched_source=NULL, matched_agent_id=NULL, "
                           "matched_at=NULL, readable=0 WHERE project_id=? AND name=? AND status='matched'",
                           (proj["id"], name))

    def apply_remote_best_named(self, slug: str, name: str, score: int, source: str) -> None:
        """A room's best attempt, by name (overlays share addresses)."""
        proj = self._project(slug)
        with self.store.tx() as db:
            db.execute("UPDATE functions SET best_score=?, best_source=?, "
                       "last_improved=CASE WHEN ? < COALESCE(n_insns,0)*100 THEN ? ELSE last_improved END "
                       "WHERE project_id=? AND name=? AND status='open' AND (best_score IS NULL OR best_score > ?)",
                       (score, source, score, time.time(), proj["id"], name, score))

    def apply_remote_match_named(self, slug: str, name: str, agent_name: str) -> None:
        """A git project's room: who matched a function (the code itself arrives with the host's commits)."""
        proj = self._project(slug)
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            row = db.execute("SELECT id, status, matched_agent_id FROM functions WHERE project_id=? AND name=?",
                             (proj["id"], name)).fetchone()
            if row is None:
                return
            if row["status"] != "matched":
                db.execute("UPDATE functions SET status='matched', matched_agent_id=?, matched_at=? WHERE id=?",
                           (aid, time.time(), row["id"]))
            elif row["matched_agent_id"] is None:
                db.execute("UPDATE functions SET matched_agent_id=? WHERE id=?", (aid, row["id"]))
            db.execute("DELETE FROM claims WHERE function_id=?", (row["id"],))

    def apply_remote_note_named(self, slug: str, function: str | None, text: str, agent_name: str, created_at: float) -> None:
        proj = self._project(slug)
        row = self.store.one("SELECT id FROM functions WHERE project_id=? AND name=?", proj["id"], function) if function else None
        fid = row["id"] if row else None
        if self.store.one("SELECT 1 FROM notes WHERE project_id=? AND text=? AND function_id IS ?", proj["id"], text, fid):
            return
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fid, aid, text, created_at))

    def apply_remote_compiler(self, slug: str, settings: dict) -> None:
        """The room's compiler settings, the host's: its compiler and flags, and its compiler ranges. A join copied the
        compiler alone, and nothing after it: a 2009 game's 3.4.4 ranges, applied by the host, never reached its
        guests, who built the game's engine with its 4.3.2 and saw none of their matches confirmed."""
        def change(cfg):
            cfg["compiler"] = settings["compiler"]
            if settings.get("compiler_ranges"):
                cfg["compiler_ranges"] = settings["compiler_ranges"]
            else:
                cfg.pop("compiler_ranges", None)

        self._update_cfg(slug, change)
        with self.store.tx() as db:
            self._event(db, self._project(slug)["id"], None, "compiler", "the room's compiler settings, from its host")

    def apply_remote_set_aside(self, slug: str, items: list, key: str = "vram") -> None:
        """The host's set-aside functions ([vram, the meta that says why]; [name, why] in a project room, `key`
        "name", whose functions are known by name): set aside here too, and those the host has opened again open
        here. Only matches and the layout came before: a guest's list and progress still showed open what the host
        had set aside as a library's or assembly."""
        proj = self._project(slug)
        aside = {(int(k) if key == "vram" else str(k)): why for k, why in items}
        with self.store.tx() as db:
            for r in db.execute("SELECT id, name, vram, status, meta FROM functions WHERE project_id=? AND status IN "
                                "('open', 'asm')", (proj["id"],)).fetchall():
                meta = json.loads(r["meta"] or "{}")
                if r[key] in aside and r["status"] == "open":
                    meta.update(aside[r[key]] or {})
                    db.execute("UPDATE functions SET status='asm', meta=? WHERE id=?", (json.dumps(meta), r["id"]))
                    db.execute("DELETE FROM claims WHERE function_id=?", (r["id"],))
                elif r[key] not in aside and r["status"] == "asm":
                    meta = {k: v for k, v in meta.items() if k not in SET_ASIDE_WHY}
                    db.execute("UPDATE functions SET status='open', meta=? WHERE id=?", (json.dumps(meta), r["id"]))

    def apply_remote_readable(self, slug: str, sources: list, readable: list | None) -> None:
        """The host's polishing: each newly readable function's C ([vram, C]), and which matched functions are
        readable (`readable`, all of them; None when unchanged)."""
        proj = self._project(slug)
        with self.store.tx() as db:
            for vram, source in sources:
                if source:
                    db.execute("UPDATE functions SET matched_source=?, best_source=?, readable=1 WHERE project_id=? "
                               "AND vram=? AND status='matched'", (source, source, proj["id"], int(vram)))
            if readable is not None:
                keep = {int(v) for v in readable}
                for r in db.execute("SELECT id, vram, readable FROM functions WHERE project_id=? AND status='matched'",
                                    (proj["id"],)).fetchall():
                    if bool(r["readable"]) != (r["vram"] in keep):
                        db.execute("UPDATE functions SET readable=? WHERE id=?", (int(r["vram"] in keep), r["id"]))

    def apply_remote_readable_named(self, slug: str, names: list) -> None:
        """A git project's room: which matched functions are readable (their C comes with the host's commits)."""
        proj = self._project(slug)
        keep = set(names)
        with self.store.tx() as db:
            for r in db.execute("SELECT id, name, readable FROM functions WHERE project_id=? AND status='matched'",
                                (proj["id"],)).fetchall():
                if bool(r["readable"]) != (r["name"] in keep):
                    db.execute("UPDATE functions SET readable=? WHERE id=?", (int(r["name"] in keep), r["id"]))

    def apply_remote_best(self, slug: str, vram: int, score: int, source: str) -> None:
        proj = self._project(slug)
        with self.store.tx() as db:
            db.execute("UPDATE functions SET best_score=?, best_source=?, "
                       "last_improved=CASE WHEN ? < COALESCE(n_insns,0)*100 THEN ? ELSE last_improved END "
                       "WHERE project_id=? AND vram=? AND status='open' AND (best_score IS NULL OR best_score > ?)",
                       (score, source, score, time.time(), proj["id"], vram, score))

    def apply_remote_note(self, slug: str, host_id: int, vram: int | None, text: str, agent_name: str, created_at: float) -> None:
        proj = self._project(slug)
        fid = None
        if vram is not None:
            row = self.store.one("SELECT id FROM functions WHERE project_id=? AND vram=?", proj["id"], vram)
            fid = row["id"] if row else None
        if self.store.one("SELECT 1 FROM notes WHERE project_id=? AND text=? AND function_id IS ?", proj["id"], text, fid):
            return
        aid = self._remote_agent(agent_name)
        with self.store.tx() as db:
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fid, aid, text, created_at))

    def apply_remote_context(self, slug: str, header: str, host_version: int) -> None:
        proj = self._project(slug)
        if self._context(proj["id"])["header"] == header:
            return
        with self.store.tx() as db:
            version = self._next_version(db, proj["id"])
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, header, None, f"from the room (host v{host_version})",
                                                  time.time(), ""))

    def apply_remote_layout(self, slug: str, functions: list[dict], symbols: list[dict]) -> None:
        """Mirror the room's splits and names. The host already regression-tested them on the same ROM."""
        proj = self._project(slug)
        pid = proj["id"]
        console = self.console(proj)
        local = {r["id"]: r for r in self.store.all("SELECT * FROM functions WHERE project_id=?", pid)}
        by_vram: dict[int, list] = {}
        for row in local.values():
            by_vram.setdefault(row["vram"], []).append(row)
        # Every name a function gave up, as {name it had before this call: name it has now}. The C that says the
        # old names (its own, its callers', the headers) is rewritten once at the end, from the database, so a
        # function renamed twice in one call (stepped aside, then given the host's name) ends up right (#107 review).
        moves: dict[str, str] = {}

        def rename(row, new: str) -> None:
            old = row["name"]
            with self.store.tx() as db:
                db.execute("UPDATE functions SET name=? WHERE id=?", (new, row["id"]))
            followed = [k for k, v in moves.items() if v == old]
            for k in followed:
                moves[k] = new
            if not followed:
                moves[old] = new
            local[row["id"]] = renamed = {**row, "name": new}
            by_vram[row["vram"]] = [renamed if i["id"] == row["id"] else i for i in by_vram[row["vram"]]]
            self._syms.pop(pid, None)

        def free_name(name: str, keep_id: int | None) -> None:
            """#107: the host's layout is authoritative, so another local function holding `name` steps aside to its
            address's default name (func_XXXXXXXX, _2, _3... when an overlay twin has that) instead of failing the
            unique name. Its symbol follows here, its C at the end."""
            for row in [r for r in local.values() if r["name"] == name and r["id"] != keep_id]:
                base = f"func_{row['vram']:08X}"
                spare, n = base, 2
                while any(r["name"] == spare for r in local.values()) or self.store.one(
                        "SELECT 1 FROM symbols WHERE project_id=? AND name=?", pid, spare):
                    spare, n = f"{base}_{n}", n + 1
                with self.store.tx() as db:
                    db.execute("UPDATE symbols SET name=? WHERE project_id=? AND name=?", (spare, pid, name))
                rename(row, spare)

        try:
            self._mirror_layout(proj, console, functions, symbols, local, by_vram, rename, free_name)
        finally:
            self._rename_in_code(pid, moves)

    def _mirror_layout(self, proj, console, functions, symbols, local, by_vram, rename, free_name) -> None:
        pid = proj["id"]
        for f in sorted(functions, key=lambda f: f["vram"]):
            at = by_vram.get(f["vram"], [])
            if any(row["name"] == f["name"] for row in at):
                continue
            if at:
                # The address belongs to another overlay's function (or a renamed one): never guess which to split.
                continue
            owners = [r for r in local.values() if r["vram"] < f["vram"] < r["vram"] + r["size"]]
            if not owners:  # a function the host added past another's end (split_function outside it)
                self._mirror_added(proj, console, f, local, by_vram, free_name)
                continue
            if len(owners) != 1 or owners[0]["status"] == "matched":
                continue
            owner = owners[0]
            try:
                head, tail = console.split_function(owner, f["vram"], f["name"])
            except ValueError:
                continue
            free_name(f["name"], None)
            syms = self.symbols(pid)
            syms.add(Symbol(f["name"], f["vram"], tail.size, "func"))
            th, tt = self._make_target(proj, head, syms), self._make_target(proj, tail, syms)
            with self.store.tx() as db:
                db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL WHERE id=?",
                           (head.size, console.function_insns(head), th.code, json.dumps(th.to_json()),
                            console.function_asm(head), owner["id"]))
                meta = console.function_meta(tail)
                tail_id = db.execute(
                    "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset,"
                    "status,meta) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, f["name"], tail.size, console.function_insns(tail), tt.code,
                     json.dumps(tt.to_json()), console.function_asm(tail), None, owner["unit"], f["vram"], tail.rom,
                     console.function_status(tail), json.dumps(meta) if meta else None)).lastrowid
                db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                           (pid, f["name"], f["vram"], tail.size, "func"))
            local[owner["id"]] = {**owner, "size": head.size}
            local[tail_id] = {**owner, "id": tail_id, "name": f["name"], "vram": f["vram"], "size": tail.size}
            by_vram.setdefault(f["vram"], []).append(local[tail_id])
        self._xrefs.pop(pid, None)
        for sym in symbols:
            at = by_vram.get(sym["address"], [])
            twins = len(at) > 1
            if twins:
                # Overlays share the address: the host says which of them it named by its unit (layout_symbols). An
                # older host doesn't, and renaming the address would rename all of them.
                at = [row for row in at if sym.get("unit") is not None and row["unit"] == sym["unit"]]
            if len(at) != 1 or at[0]["name"] == sym["name"]:
                continue
            row = at[0]
            free_name(sym["name"], row["id"])
            old = row["name"]
            stale = {old, sym["name"]}
            if not twins:  # the one function's address: whatever symbol names it goes
                current, off = self.symbols(pid).name_at(sym["address"])
                if off == 0:
                    stale.add(current)
            with self.store.tx() as db:
                db.executemany("DELETE FROM symbols WHERE project_id=? AND name=?", [(pid, n) for n in stale])
                db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                           (pid, sym["name"], sym["address"], sym["size"], sym["kind"]))
            rename(row, sym["name"])

    def _mirror_added(self, proj, console, f: dict, local: dict, by_vram: dict, free_name) -> None:
        """The host's function that no function here holds, read from this copy's own ROM as the host's split did
        (EditingMixin._add_function). Skipped, the host handed it out and the claim failed here: "no function"."""
        before = [r for r in local.values() if r["vram"] < f["vram"]]
        if not before:
            return
        prev = max(before, key=lambda r: r["vram"] + r["size"])
        rom, _ = self._rom(proj)
        new = console.function_at(rom, f["vram"], f["vram"] + f["size"], f["name"])
        if new is None:
            return
        free_name(f["name"], None)
        self._add_function(proj, prev, new, self.symbols(proj["id"]), None, f["name"], event=False)
        row = self.store.one("SELECT * FROM functions WHERE project_id=? AND name=?", proj["id"], f["name"])
        if row is not None:
            local[row["id"]] = dict(row)
            by_vram.setdefault(row["vram"], []).append(local[row["id"]])

    def _rename_in_code(self, pid: int, moves: dict[str, str]) -> None:
        """Rewrite every matched and best source, and every header, from the names functions had to the names they
        have now: a function that stepped aside and its callers must say its new name, as rename_symbols does, or a
        match is stale and a save writes the wrong C (#107 review)."""
        moves = {old: new for old, new in moves.items() if old != new}
        if not moves:
            return
        word = re.compile(r"\b[A-Za-z_]\w*\b")
        swap = lambda text: word.sub(lambda m: moves.get(m.group(0), m.group(0)), text) if text else text
        with self.store.tx() as db:
            for r in db.execute("SELECT id, matched_source, best_source FROM functions WHERE project_id=? AND "
                                "(matched_source IS NOT NULL OR best_source IS NOT NULL)", (pid,)).fetchall():
                matched, best = swap(r["matched_source"]), swap(r["best_source"])
                if (matched, best) != (r["matched_source"], r["best_source"]):
                    db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?", (matched, best, r["id"]))
            for unit in {""} | self._unit_contexts(pid):
                last = db.execute("SELECT header FROM context_versions WHERE project_id=? AND unit=? "
                                  "ORDER BY version DESC LIMIT 1", (pid, unit)).fetchone()
                if last is None or swap(last["header"]) == last["header"]:
                    continue
                db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                           "VALUES(?,?,?,?,?,?,?)", (pid, self._next_version(db, pid), swap(last["header"]), None,
                                                     "names follow the shared layout", time.time(), unit))

    def layout_symbols(self, pid: int) -> list[dict]:
        """The names given in a project, for a room's state and a save. A name one of several functions at an
        address holds (overlays share addresses) also says that function's unit, so the other side names the same
        one (#107 review); elsewhere the list is as it always was."""
        twins = {r["name"]: r["unit"] for r in self.store.all(
            "SELECT name, unit FROM functions WHERE project_id=? AND vram IN "
            "(SELECT vram FROM functions WHERE project_id=? GROUP BY vram HAVING COUNT(*) > 1)", pid, pid)}
        out = []
        for r in self.store.all("SELECT name, address, size, kind FROM symbols WHERE project_id=?", pid):
            if AUTO_NAME.match(r["name"]):
                continue
            out.append(dict(r) | ({"unit": twins[r["name"]]} if r["name"] in twins else {}))
        return out
