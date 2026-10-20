"""Browsers on other computers (app/browsers.py): decompdecomp on a server, used through `tailscale serve`. A browser
gets in only by pairing, once per link; everything else still answers only the window, and the agents' endpoint
never answers the tailnet."""

import os
import time

import pytest
from starlette.testclient import TestClient

from decompnet.app import browsers, cli, window
from decompnet.app.engine import RomNetwork
from decompnet.app.server import build

PORT, SECRET, TAILNET = 6498, "s3cret-for-browser-tests", "box.tail1234.ts.net"
WINDOW = {"User-Agent": f"Mozilla/5.0 AppleWebKit/605.1.15 {window.TOKEN_AGENT}{SECRET}"}
EDGE = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"}


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(browsers, "tailnet_name", lambda: TAILNET)
    home = tmp_path / "home"
    (home / ".decomp").mkdir(parents=True)
    net = RomNetwork(home / ".decomp" / "decomp.db", home)
    mcp, _, security, _ = build(net, home / ".decomp", PORT, SECRET)
    app = mcp.streamable_http_app(transport_security=security, host="127.0.0.1")
    win = TestClient(app, base_url=f"http://127.0.0.1:{PORT}", headers=WINDOW)
    return app, win, home / ".decomp"


def remote(app):
    """A browser on another computer, at the tailnet address `tailscale serve` gives the app."""
    return TestClient(app, base_url=f"https://{TAILNET}", headers=EDGE)


def pair(win, browser) -> str:
    link = win.post("/api/browsers", json={"pair": True}, headers={"X-Decomp": "1"}).json()["link"]
    assert link.startswith(f"https://{TAILNET}/pair?code=")
    res = browser.get(link.removeprefix(f"https://{TAILNET}"))
    assert res.status_code == 200 and "paired" in res.text
    return link


def test_a_browser_gets_in_by_pairing_once(server):
    app, win, home = server
    edge = remote(app)
    page = edge.get("/")
    assert page.status_code == 401 and "decomp pair" in page.text  # it says how, at the tailnet address
    assert edge.get("/api/state").status_code == 401
    link = pair(win, edge)
    assert edge.get("/").status_code == 200
    assert edge.get("/api/state").json()["viewer"] == "browser"
    assert win.get("/api/state").json()["viewer"] == "window"
    # the link worked once: another browser can't use it again
    other = remote(app)
    assert other.get(link.removeprefix(f"https://{TAILNET}")).status_code == 400
    assert other.get("/api/state").status_code == 401
    # writes still need the page's own header (a cross-site form can't send it)
    assert edge.post("/api/settings", json={"per_session": 3}).status_code == 403
    assert edge.post("/api/settings", json={"per_session": 3}, headers={"X-Decomp": "1"}).status_code == 200
    # only a hash of the session's token is kept, in a file only its owner reads
    saved = home / "browsers.json"
    assert edge.cookies[browsers.COOKIE] not in saved.read_text() and os.stat(saved).st_mode & 0o077 == 0


def test_a_removed_browser_is_out(server):
    app, win, _ = server
    edge = remote(app)
    pair(win, edge)
    listed = win.get("/api/browsers").json()
    assert listed["address"] == TAILNET and [b["name"] for b in listed["browsers"]] == ["Edge on Windows"]
    gone = win.post("/api/browsers", json={"remove": listed["browsers"][0]["id"]}, headers={"X-Decomp": "1"})
    assert gone.status_code == 200 and gone.json()["browsers"] == []
    assert edge.get("/api/state").status_code == 401


def test_only_this_computers_names_and_never_the_agents_endpoint(server):
    app, win, _ = server
    edge = remote(app)
    pair(win, edge)
    session = {browsers.COOKIE: edge.cookies[browsers.COOKIE]}
    evil = TestClient(app, base_url="https://evil.example", headers=EDGE, cookies=session)
    assert evil.get("/api/state").status_code == 403  # DNS rebinding: a session doesn't change that
    # the agents' endpoint answers 127.0.0.1 only: a paired browser at the tailnet address doesn't reach it
    ask = {"json": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
           "headers": {"Accept": "application/json, text/event-stream"}}
    with TestClient(app, headers=EDGE, cookies=session) as c:  # (the endpoint runs only inside the app's lifespan)
        assert c.post(f"https://{TAILNET}/mcp", **ask).status_code == 421
        assert c.post(f"http://127.0.0.1:{PORT}/mcp", **ask).status_code != 421  # (the host is what it refused)


def test_what_opens_on_the_servers_screen_isnt_offered_to_a_browser(server):
    app, win, _ = server
    edge = remote(app)
    pair(win, edge)
    res = edge.post("/api/pick", json={"kind": "file"}, headers={"X-Decomp": "1"})
    assert res.status_code == 400 and "type the path" in res.json()["error"]
    manifest = edge.get("/manifest.webmanifest").json()  # Edge and Chrome install the page as an app
    assert manifest["start_url"] == "/" and manifest["display"] == "standalone"


def test_a_pairing_code_expires(tmp_path, monkeypatch):
    b = browsers.Browsers(tmp_path / "browsers.json")
    code = b.pair_code()
    later = time.time() + browsers.PAIR_SECONDS + 1
    monkeypatch.setattr(browsers.time, "time", lambda: later)
    assert b.redeem(code, "Edge") is None and b.sessions == []
    assert b.redeem("made-up", "Edge") is None


def test_decomp_pair_prints_the_link(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "_state", lambda path: {"port": 6464, "secret": "x"})
    monkeypatch.setattr(cli, "_call", lambda info, path, body=None, timeout=10:
                        {"link": f"https://{TAILNET}/pair?code=abc", "minutes": 10})
    assert cli.main(["pair"]) == 0
    assert f"https://{TAILNET}/pair?code=abc" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_call", lambda info, path, body=None, timeout=10:
                        {"link": "http://127.0.0.1:6464/pair?code=abc", "minutes": 10})
    cli.main(["pair"])
    assert "tailscale serve --bg 6464" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_state", lambda path: None)
    assert cli.main(["pair"]) == 1


def test_browser_names():
    assert browsers.browser_name(EDGE["User-Agent"]) == "Edge on Windows"
    assert browsers.browser_name("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0") == "Firefox on Linux"
    assert browsers.browser_name("") == "a browser"
