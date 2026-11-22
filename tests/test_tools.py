"""The tools helpers get are the ones their project's console (or, for a ROM join, its engine) can do (#232): a DS
helper isn't offered joins it can't make, a GameCube one no function ends or C++ classes, and the API helper's
schemas say the same as the MCP tool list."""

import json

import pytest

from decompnet import consoles
from decompnet.agents.api import api_tool_schemas
from decompnet.app import agents, tools
from decompnet.app.engine import RomNetwork

# platform, project mode (a fork), tools that must be there, tools that must not
CASES = [
    ("gc", True, {"claim_function", "file_status", "split_file", "compiler_map"},
     {"join_functions", "report_boundary", "get_class", "guess_struct", "redraft", "search_flags"}),
    ("wii", True, {"claim_function", "file_status", "split_file", "compiler_map"},
     {"join_functions", "report_boundary", "get_class", "guess_struct", "redraft", "search_flags"}),
    ("nds", True, {"claim_function", "file_status", "split_file", "join_functions", "compiler_map"},
     {"report_boundary", "get_class", "guess_struct", "redraft", "search_flags"}),
    ("pc", True, {"join_functions", "report_boundary", "get_class", "guess_struct", "compiler_map", "redraft",
                  "search_flags"}, set()),
    ("n64", False, {"report_boundary", "get_class", "guess_struct", "compiler_map", "redraft", "search_flags"},
     {"join_functions", "read_file", "split_file"}),
    ("ps2", False, {"report_boundary", "get_class", "guess_struct", "compiler_map", "redraft", "search_flags"},
     {"join_functions", "read_file", "split_file"}),
]


@pytest.mark.parametrize("platform,fork,present,absent", CASES, ids=[c[0] for c in CASES])
def test_the_mcp_tools_and_api_schemas_are_what_the_console_can_do(platform, fork, present, absent):
    console = consoles.get(platform)
    names = tools.tool_names(fork, console)
    assert present <= set(names)
    assert absent.isdisjoint(names)
    # the API helper gets the same list, not a schema for a tool the MCP list leaves out
    assert {t["function"]["name"] for t in api_tool_schemas(fork=fork, names=names)} == set(names)


def test_an_old_prompt_calling_an_unoffered_tool_gets_a_sentence(tmp_path):
    """An older prompt (or a cached tool list) calling join_functions on a GameCube project is told why, not a
    traceback from the console's default."""
    net = RomNetwork(tmp_path / "app.db", tmp_path / "ws")
    root = tmp_path / "ws" / "gc"
    root.mkdir(parents=True)
    (root / "objdiff.json").write_text(json.dumps({"units": []}))
    net.forks._register("gc", "GC", "fork", root,
                        {"kind": "fork", "platform": "gc", "origin": "scratch", "ready": True}, "x")
    agent, _ = net.local_agent("old-prompt")
    text = tools.call(net, agent, "gc", "join_functions",
                      {"function": "a", "with_function": "b", "reason": "a has no epilogue"})
    assert text.startswith("error: join_functions isn't offered in GameCube projects")
    assert "can't join functions" in text and "Traceback" not in text


def test_a_rom_engine_that_can_join_offers_it_to_rom_consoles(monkeypatch):
    """#192 adds ROM joins in the engine, not on Console: once its join_functions handler exists (and FORK_ONLY no
    longer hides the tool), every ROM console gets it. Project mode still asks the console: PC joins, GameCube not."""
    monkeypatch.setattr(tools, "FORK_ONLY", tools.FORK_ONLY - {"join_functions"})
    monkeypatch.setattr(tools.RomNetwork, "join_functions", lambda *args, **kwargs: "", raising=False)
    for platform in ("n64", "ps2", "gba"):
        assert "join_functions" in tools.tool_names(False, consoles.get(platform))
    assert "join_functions" in tools.tool_names(True, consoles.get("pc"))
    assert "join_functions" not in tools.tool_names(True, consoles.get("gc"))


def test_the_rom_prompt_names_joins_only_when_the_engine_has_them(tmp_path, monkeypatch):
    """A ROM prompt follows the same gate as its tool list: no join_functions before #192, and the join guidance
    once the engine has it."""
    net = RomNetwork(tmp_path / "app.db", tmp_path / "ws")
    manager = agents.Manager(net, tmp_path, "http://127.0.0.1:1/mcp")
    session = agents.Session("1", "claude", "claude-1", "rom", "claude-1", {})
    monkeypatch.setattr(net, "overview", lambda slug: {
        "kind": "rom", "title": "Game", "platform": "n64", "compiler": {"toolchain": "gcc-2.7.2-kmc"}})
    assert "join_functions" not in manager._prompt(session)
    monkeypatch.setattr(tools, "FORK_ONLY", tools.FORK_ONLY - {"join_functions"})
    monkeypatch.setattr(tools.RomNetwork, "join_functions", lambda *args, **kwargs: "", raising=False)
    assert "join_functions" in manager._prompt(session)


def test_a_rom_project_without_engine_joins_names_the_engine(tmp_path, monkeypatch):
    """The refusal follows the same gate: ROM joins are the engine's (#192), not a console's, so say so."""
    monkeypatch.setattr(tools, "FORK_ONLY", tools.FORK_ONLY - {"join_functions"})
    net = RomNetwork(tmp_path / "app.db", tmp_path / "ws")
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                   ("rom", "ROM", "", "mips", 0, str(tmp_path), json.dumps({"kind": "rom", "platform": "n64"})))
    agent, _ = net.local_agent("old-prompt")
    text = tools.call(net, agent, "rom", "join_functions",
                      {"function": "a", "with_function": "b", "reason": "a has no epilogue"})
    assert text.startswith("error: join_functions isn't offered in Nintendo 64 projects")
    assert "the ROM engine can't join functions" in text and "Traceback" not in text


def test_every_mcp_tool_reaches_its_handler_with_its_own_arguments(tmp_path, monkeypatch):
    """sdk_inline's `name` collided with the tool runner's own parameter, so every agent's call failed before it ran
    (a GameCube game's main waited on it): each tool, called through MCP with every parameter it has, gets there."""
    import anyio

    net = RomNetwork(tmp_path / "test.db", tmp_path)
    reached = []
    monkeypatch.setattr(tools, "_invoke", lambda net, agent, slug, name, args: reached.append((name, args)) or "ok")
    mcp = tools.build_mcp(net, lambda ctx: (None, "slug"))
    dummy = {"string": "x", "integer": 1, "number": 1.0, "boolean": True, "array": [], "object": {}}

    async def each():
        for tool in await mcp.list_tools():
            props = tool.input_schema.get("properties", {})
            kind = lambda v: v.get("type") or next((a.get("type") for a in v.get("anyOf", [])  # noqa: E731
                                                    if a.get("type") != "null"), None)
            args = {k: dummy.get(kind(v), "x") for k, v in props.items()}
            reached.clear()
            await mcp.call_tool(tool.name, args)
            assert [name for name, _ in reached] == [tool.name]  # (some map aliases: read_file's offset)

    anyio.run(each)
    reached.clear()
    sdk = {"name": "OSInitFastCast", "path": "src/main.c"}
    anyio.run(lambda: mcp.call_tool("sdk_inline", sdk))
    assert reached == [("sdk_inline", sdk)]


def test_compile_and_diff_takes_edits_to_the_agents_last_c(tmp_path):
    """A GameCube game's 1,318-instruction function cost its agents 23,000 characters of C a compile, to change a
    line or two: `edits` change the C of the agent's last compile of the function (its best attempt before that)."""
    import shutil
    import sys
    from pathlib import Path

    from decompnet.network import NetworkError

    from .handmade import import_project
    from .solutions import WRONG_CLAMP

    if sys.platform != "linux" or shutil.which("gcc") is None:
        pytest.skip("projects/demo needs a Linux gcc (x86-64 ELF)")
    net = RomNetwork(tmp_path / "t.db", tmp_path)
    import_project(net.store, Path(__file__).resolve().parent.parent / "projects" / "demo", log=lambda *_: None)
    slug = net.store.one("SELECT slug FROM projects")["slug"]
    agent, _ = net.local_agent("claude-1")
    with pytest.raises(NetworkError, match="no C to edit yet"):
        tools._compile(net, agent, slug, "clamp_s32", "", [{"old": "a", "new": "b"}])
    assert not tools._compile(net, agent, slug, "clamp_s32", WRONG_CLAMP).startswith("✅")
    fixed = [{"old": "if (v > hi) return hi;\n    if ((u32)v < (u32)lo) return lo;",
              "new": "if (v < lo) return lo;\n    if (v > hi) return hi;"}]  # (the demo's own solution)
    out = tools._compile(net, agent, slug, "clamp_s32", "", fixed)
    assert out.startswith("(compiled your last compile of clamp_s32 with 1 edit)") and "MATCH" in out
    assert net._function("clamp_s32", slug)["status"] == "matched"
    with pytest.raises(NetworkError, match="isn't in your last compile of clamp_s32"):
        tools._compile(net, agent, slug, "clamp_s32", "", [{"old": "no such line;", "new": "x"}])
    with pytest.raises(NetworkError, match="not both"):
        tools._compile(net, agent, slug, "clamp_s32", WRONG_CLAMP, fixed)
    with pytest.raises(NetworkError, match="name one function"):
        tools._compile(net, agent, slug, "clamp_s32, abs_s32", "", fixed)
