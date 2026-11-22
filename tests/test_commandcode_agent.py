"""Command Code (agents/commandcode.py): a session's private home keeps the user's own MCP servers, mods and taste
out and allows only decompdecomp's tools, its sign-in goes in by its environment, and what it prints is read. Its
program is never run here."""

import json

from decompnet import agents
from decompnet.app import agents as helpers

CC = agents.get("commandcode")
TOKEN = "secret-token-1234"


def test_a_session_runs_with_a_private_home_and_only_decomps_tools(tmp_path, monkeypatch):
    mine = tmp_path / "user" / ".commandcode"
    mine.mkdir(parents=True)
    (mine / "auth.json").write_text(json.dumps({"apiKey": "user-key", "userName": "someone"}))
    (mine / "mcp.json").write_text(json.dumps({"mcpServers": {"github": {"command": "npx"}}}))
    (mine / "providers.json").write_text(json.dumps({"providers": {"mine": {}}}))
    (mine / "settings.json").write_text(json.dumps({"model": "kimi-k2.5"}))
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.delenv("COMMAND_CODE_API_KEY", raising=False)
    assert CC.config_model() == "kimi-k2.5"
    work = tmp_path / "work"
    work.mkdir()
    cmd, env = CC.session_command("/bin/command-code", work, "http://127.0.0.1:6464/mcp", TOKEN, "deepseek-v4.1-flash")
    assert cmd[:4] == ["/bin/command-code", "-p", "--output-format", "json"]
    assert cmd[cmd.index("--permission-mode") + 1] == "dont-ask" and cmd[-2:] == ["--model", "deepseek-v4.1-flash"]
    assert "--safe-mode" in cmd and "--no-skills" in cmd and not any(TOKEN in a for a in cmd)
    private = work / "home" / ".commandcode"
    assert env["HOME"] == str(work / "home") and env["COMMAND_CODE_API_KEY"] == "user-key"
    settings = json.loads((private / "settings.json").read_text())
    assert settings["permissions"]["defaultMode"] == "dont-ask" and settings["permissions"]["allow"] == ["mcp__decomp"]
    assert "Bash" in settings["permissions"]["deny"] and settings["model"] == "deepseek-v4.1-flash"
    assert settings["tasteLearning"] is False
    servers = json.loads((private / "mcp.json").read_text())["mcpServers"]
    assert list(servers) == ["decomp"] and servers["decomp"]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert (private / "providers.json").is_file() and not (private / "auth.json").exists()
    monkeypatch.setenv("COMMAND_CODE_API_KEY", "env-key")  # (the user's own variable wins, as it does for the CLI)
    assert CC.session_command("/bin/command-code", work, "http://x/mcp", TOKEN, "")[1]["COMMAND_CODE_API_KEY"] == "env-key"


def test_what_it_prints_is_read():
    state = {}
    end = {"type": "event", "event": {"type": "message_end", "content": [
        {"type": "thinking", "thinking": "look at the diff"}, {"type": "text", "text": "Claiming one."},
        {"type": "tool_use", "id": "t1", "name": "mcp__decomp__claim_function", "input": {"function": "f"}}]}}
    items = CC.parse_line(json.dumps(end), state)
    assert ("think", "look at the diff") in items and ("text", "Claiming one.") in items
    assert any(kind == "tool" and text.startswith("claim_function(") for kind, text in items)
    CC.parse_line(json.dumps({"type": "event", "event": {"type": "model_request_end", "usage": {}}}), state)
    CC.parse_line(json.dumps({"type": "event", "event": {"type": "model_request_end", "usage": {}}}), state)
    done = CC.parse_line(json.dumps({"type": "result", "subtype": "success", "usage": {
        "inputTokens": 1200, "outputTokens": 300, "cacheReadTokens": 900, "cacheWriteTokens": 0}}), state)
    assert done[0] == ("info", "session finished") and done[1][0] == "usage"
    assert '"input": 1200' in done[1][1] and '"turns": 2' in done[1][1]
    failed = CC.parse_line(json.dumps({"type": "result", "subtype": "error", "usage": {}, "error": "Not signed in"}), {})
    assert failed[0] == ("error", "Not signed in")
    assert CC.parse_line(json.dumps({"type": "event", "event": {"type": "run_error", "error": {"message": "boom"}}})) == [
        ("error", "boom")]


def test_its_models_come_from_its_list():
    printed = """Available models  ·  3 models

Anthropic

anthropic/claude-sonnet-4.6  Fast and capable (default)
anthropic/claude-opus-4.8    Most capable

Moonshot

moonshotai/kimi-k2.5         FREE Open model

Pass the full id, or just the short name after the last "/":
cmd --model moonshotai/kimi-k2.5
cmd --model kimi-k2.5

Docs:  https://commandcode.ai/docs/models""".splitlines()
    models = CC.read_models([line.strip() for line in printed])
    assert [m["id"] for m in models] == ["anthropic/claude-sonnet-4.6", "anthropic/claude-opus-4.8", "moonshotai/kimi-k2.5"]
    assert models[0]["note"] == "Fast and capable (your default)" and models[2]["note"] == "Open model"


def test_its_sign_in_and_credit_messages_are_recognised():
    assert helpers._SIGNED_OUT.search("Error: Not signed in. Run `cmd login` to sign in")
    assert helpers._SIGNED_OUT.search('Error: Not authenticated. Please run "cmd login" first.')  # (1.93.0's, for real)
    assert helpers.no_credit("credits exhausted: top up at commandcode.ai")
    assert CC.fatal('unknown model "nope". Run "--list-models" to see the available models')
