"""Browsers paired with this app: decompdecomp on a server, used from another computer's browser over Tailscale.

The app still listens on 127.0.0.1 only. `tailscale serve --bg <port>` gives it an HTTPS address only the user's
tailnet reaches (https://<computer>.<tailnet>.ts.net, with a real certificate) and passes requests on to it. Those
requests arrive from 127.0.0.1 like the window's, so where a request comes from proves nothing: a browser gets in
only with a session it was given by pairing.

Pairing: the window, a paired browser or `decomp pair` on the server asks for a code; the link with it
(/pair?code=...) works once, for PAIR_SECONDS, and leaves a session cookie in the browser that opens it. Sessions
last until they're removed in Settings. Only a hash of each session's token is kept (browsers.json, 0600).

A paired browser can do everything the window can: it's the user, from another computer. What only the window can
do (the system's file chooser, opening a folder) happens on the server's screen, so the page offers paths instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path

COOKIE = "decomp_session"
PAIR_SECONDS = 10 * 60
SEEN_EVERY_SECONDS = 60  # how often a session's "last used" is written down
TAILNET_CHECK_SECONDS = 600  # `tailscale status` can take seconds: the answer is kept this long


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Browsers:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._codes: dict[str, float] = {}  # pairing code's hash -> when it stops working
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.sessions = [s for s in data.get("sessions") or [] if isinstance(s, dict) and s.get("hash")]
        except (OSError, ValueError, AttributeError):
            self.sessions = []

    def _save(self) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps({"sessions": self.sessions}, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def pair_code(self) -> str:
        """A code that pairs one browser, once, within PAIR_SECONDS."""
        code = secrets.token_urlsafe(24)
        with self._lock:
            now = time.time()
            self._codes = {h: t for h, t in self._codes.items() if t > now}
            self._codes[_hash(code)] = now + PAIR_SECONDS
        return code

    def redeem(self, code: str, name: str) -> str | None:
        """The new session's token for a code that's still good (the code is used up), else None."""
        with self._lock:
            until = self._codes.pop(_hash(code or ""), 0)
            if until < time.time():
                return None
            token = secrets.token_urlsafe(32)
            now = int(time.time())
            self.sessions.append({"id": secrets.token_hex(6), "hash": _hash(token), "name": name[:120] or "a browser",
                                  "created": now, "seen": now})
            self._save()
            return token

    def session(self, token: str | None) -> dict | None:
        """The session a cookie's token belongs to, or None."""
        if not token:
            return None
        digest = _hash(token)
        with self._lock:
            for s in self.sessions:
                if secrets.compare_digest(s["hash"], digest):
                    if time.time() - s.get("seen", 0) > SEEN_EVERY_SECONDS:
                        s["seen"] = int(time.time())
                        self._save()
                    return s
        return None

    def remove(self, sid: str) -> bool:
        with self._lock:
            before = len(self.sessions)
            self.sessions = [s for s in self.sessions if s.get("id") != sid]
            if len(self.sessions) == before:
                return False
            self._save()
            return True

    def listing(self) -> list[dict]:
        """The sessions as Settings shows them (never their hashes)."""
        return [{k: s.get(k) for k in ("id", "name", "created", "seen")} for s in self.sessions]


def browser_name(user_agent: str) -> str:
    """A name to tell sessions apart in Settings: the browser and system its user agent names."""
    ua = user_agent or ""
    system = next((s for k, s in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iPhone"),
                                  ("iPad", "iPad"), ("Mac OS", "macOS"), ("Linux", "Linux")) if k in ua), "")
    browser = next((b for k, b in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                   ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), "a browser")
    return f"{browser} on {system}" if system else browser


_tailnet: tuple[float, str] = (0.0, "")


def tailnet_name() -> str:
    """This computer's name on its tailnet (box.tail1234.ts.net), "" without Tailscale."""
    global _tailnet
    if time.time() - _tailnet[0] < TAILNET_CHECK_SECONDS:
        return _tailnet[1]
    name = ""
    ts = shutil.which("tailscale")
    if ts:
        try:
            res = subprocess.run([ts, "status", "--json"], capture_output=True, text=True, timeout=5,
                                 encoding="utf-8", errors="replace")
            name = ((json.loads(res.stdout).get("Self") or {}).get("DNSName") or "").rstrip(".").lower()
        except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError):
            pass
    _tailnet = (time.time(), name)
    return name


def remote_host(host: str | None) -> bool:
    """Whether a Host header names this computer on its tailnet (`tailscale serve` passes the browser's on)."""
    name = tailnet_name()
    return bool(name) and (host or "").lower() in (name, f"{name}:443")
