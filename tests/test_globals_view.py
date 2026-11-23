"""The Globals tab: a ROM project's data symbols, listed beside the D_ address name each started as."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from decompnet.app import window
from decompnet.app.engine import RomNetwork
from decompnet.app.globals_view import globals_list
from decompnet.app.server import build

from .test_loading import tiny_game

STATIC = Path(__file__).parents[1] / "src/decompnet/app/static"
PORT, SECRET = 6498, "s3cret-for-globals"
WINDOW = {"User-Agent": f"Mozilla/5.0 AppleWebKit/605.1.15 {window.TOKEN_AGENT}{SECRET}"}


def _game(tmp_path):
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    proj = tiny_game(net, "g")
    with net.store.tx() as db:
        for name, addr, size, kind, preview in [("sDirectKey", 0x800A4DFC, 4, "data", "0x00000001"),
                                                ("D_800A4E00", 0x800A4E00, 8, "bss", None),
                                                ("jtbl_800A4E08", 0x800A4E08, 8, "jtbl", None),
                                                ("func_0", 0x100000, 16, "func", None),
                                                ("func_1", 0x100010, 16, "data", None)]:  # a function, whatever its kind
            db.execute("INSERT INTO symbols(project_id,name,address,size,kind,preview) VALUES(?,?,?,?,?,?)",
                       (proj["id"], name, addr, size, kind, preview))
    return net


def test_lists_data_symbols_with_their_address_names(tmp_path):
    net = _game(tmp_path)
    data = globals_list(net, "g")
    rows = [dict(zip(data["keys"], r)) for r in data["rows"]]
    assert [r["name"] for r in rows] == ["sDirectKey", "D_800A4E00", "jtbl_800A4E08"]  # functions: the Functions tab
    assert rows[0]["original"] == "D_800A4DFC" and rows[0]["preview"] == "0x00000001"
    assert rows[1]["original"] == rows[1]["name"] and rows[1]["preview"] == ""
    assert rows[2]["original"] == rows[2]["name"]  # a jump table splat named isn't one someone named
    assert data["supported"] is True and data["named"] == 1


def test_a_project_mode_game_says_why_it_has_no_list(tmp_path):
    net = _game(tmp_path)
    with net.store.tx() as db:
        db.execute("UPDATE projects SET config=? WHERE slug='g'", (json.dumps({"kind": "fork"}),))
    data = globals_list(net, "g")
    assert data["supported"] is False and data["rows"] == [] and "ROM projects" in data["reason"]


def test_the_window_asks_for_them_by_route(tmp_path):
    net = _game(tmp_path)
    mcp, _manager, security, _ = build(net, tmp_path / ".decomp", PORT, SECRET)
    client = TestClient(mcp.streamable_http_app(transport_security=security, host="127.0.0.1"),
                        base_url=f"http://127.0.0.1:{PORT}", headers=WINDOW)
    answer = client.get("/api/globals", params={"slug": "g"})
    assert answer.status_code == 200, answer.text
    assert [r[0] for r in answer.json()["rows"]] == ["sDirectKey", "D_800A4E00", "jtbl_800A4E08"]
    missing = client.get("/api/globals", params={"slug": "nothing-here"})
    assert missing.status_code == 400 and "no project" in missing.json()["error"]


def test_the_tab_is_wired_into_the_page():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'data-ptab="globals"' in html and 'data-pane="globals"' in html and "/assets/js/globals.js" in html
    assert html.index("/assets/js/base.js") < html.index("/assets/js/globals.js")
    assert '"globals"' in (STATIC / "js/base.js").read_text(encoding="utf-8")
    assert 'tab === "globals"' in (STATIC / "js/project.js").read_text(encoding="utf-8")


def test_the_tab_searches_filters_and_sorts():
    node = shutil.which("node")
    if node is None:
        pytest.skip("needs node to run the GUI's scripts")
    subprocess.run([node, str(Path(__file__).with_name("gui_globals.js"))], check=True,
                   capture_output=True, text=True, timeout=60)
