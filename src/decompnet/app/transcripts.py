"""What each helper session said and did, in full and kept: the prompt it got, its words and thinking, every tool it
called with its arguments, and what each tool answered. The card's log keeps the last lines of the running helpers in
memory, cut short; a helper working on its own on a server can only be understood afterwards from all of it.

Kept within bounds: each text cut at MAX_TEXT, nothing older than KEEP_DAYS, at most KEEP_ROWS in all (the oldest go
first). Keys never go in: an API helper's key and a helper's MCP token are taken out, and so are credential fields a
tool's text might echo."""

from __future__ import annotations

import json
import re
import threading
import time

MAX_TEXT = 20000  # characters of one entry (a long brief, a diff)
KEEP_DAYS = 14
KEEP_ROWS = 300_000
PRUNE_EVERY = 2000  # entries between two prunings
PAGE = 200  # entries a read returns
SECRET_FIELD = re.compile(r'(?i)("(?:api_key|access_token|refresh_token|authorization|password|token)"\s*:\s*)"(?:\\.|[^"\\])*"')
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


class Transcripts:
    def __init__(self, store):
        self.store = store
        self._appended = 0
        self._lock = threading.Lock()
        with store.tx() as db:
            db.execute("CREATE TABLE IF NOT EXISTS helper_messages(id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, "
                       "created_at REAL NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_helper_messages_session ON helper_messages(session_id, id)")
        self.prune()

    def append(self, session_id: int, kind: str, value, secrets=()) -> None:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=1)
        for secret in secrets:
            if secret:
                text = text.replace(secret, "[key]")
        text = BEARER.sub("Bearer [key]", SECRET_FIELD.sub(r'\1"[key]"', text))
        if len(text) > MAX_TEXT:
            text = text[:MAX_TEXT] + f"\n[... {len(text) - MAX_TEXT} more characters not kept]"
        with self.store.tx() as db:
            db.execute("INSERT INTO helper_messages(session_id, created_at, kind, text) VALUES(?,?,?,?)",
                       (session_id, time.time(), kind, text))
        with self._lock:
            self._appended += 1
            due = self._appended % PRUNE_EVERY == 0
        if due:
            self.prune()

    def prune(self) -> None:
        with self.store.tx() as db:
            db.execute("DELETE FROM helper_messages WHERE created_at < ?", (time.time() - KEEP_DAYS * 86400,))
            n = db.execute("SELECT COUNT(*) FROM helper_messages").fetchone()[0]
            if n > KEEP_ROWS:
                db.execute("DELETE FROM helper_messages WHERE id IN (SELECT id FROM helper_messages ORDER BY id LIMIT ?)",
                           (n - KEEP_ROWS,))

    def read(self, slug: str, helper_id: int, session: int = 0, after: int = 0) -> dict:
        """A helper's sessions (newest first, the last 50) and one session's entries from `after` on, a page at a time
        (the newest session when none is named)."""
        sessions = [dict(r) for r in self.store.all(
            "SELECT s.id, s.started_at, s.ended_at, s.outcome, s.model, s.compiles, s.matches, s.usd, s.tokens, "
            "(SELECT COUNT(*) FROM helper_messages m WHERE m.session_id=s.id) AS entries FROM helper_sessions s "
            "WHERE s.project=? AND s.helper_id=? ORDER BY s.id DESC LIMIT 50", slug, helper_id)]
        if not session:
            session = next((s["id"] for s in sessions if s["entries"]), sessions[0]["id"] if sessions else 0)
        if session and not any(s["id"] == session for s in sessions):
            raise ValueError("that session isn't one of this helper's on this project")
        rows = self.store.all("SELECT id, created_at, kind, text FROM helper_messages WHERE session_id=? AND id>? "
                              "ORDER BY id LIMIT ?", session, max(0, int(after or 0)), PAGE + 1) if session else []
        return {"sessions": sessions, "session": session, "entries": [dict(r) for r in rows[:PAGE]],
                "more": len(rows) > PAGE}
