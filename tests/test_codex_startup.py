"""Codex needs decompdecomp's tools before its first model turn: a session without them only spends the user's
allowance. The app's server is required, never switched off with the user's own, and a startup that fails says why
and is tried again like any failure."""
import os
import sys
import tomllib

import pytest

from decompnet.agents import codex
from decompnet.app import agents
from decompnet.app.engine import RomNetwork

URL = "http://127.0.0.1:1/mcp"


def overrides(command):
    return [command[i + 1] for i, value in enumerate(command[:-1]) if value == "-c"]


def test_codex_requires_the_apps_server_and_switches_off_only_the_users(tmp_path, monkeypatch):
    monkeypatch.setattr(codex, "codex_config", lambda: {"mcp_servers": {"decomp_agent": {"enabled": False}, "other": {}}})
    command, env = codex.CODEX.session_command("codex", tmp_path, URL, "private-token", "gpt-6.1")
    values = overrides(command)
    settings = tomllib.loads("\n".join(values))["mcp_servers"]
    ours = settings["decomp_agent"]
    assert ours["enabled"] is True and ours["required"] is True
    assert ours["startup_timeout_sec"] == codex.STARTUP_TIMEOUT and ours["tool_timeout_sec"] == codex.TOOL_TIMEOUT
    assert settings["other"]["enabled"] is False
    assert "mcp_servers.decomp_agent.enabled=false" not in values
    assert env[codex.TOKEN_ENV] == "private-token" and "private-token" not in " ".join(command)


@pytest.mark.parametrize("message", [
    "Error: required MCP servers failed to initialize: decomp_agent: connection refused",
    "required MCP server decomp_agent did not start: initialize timed out",
    "MCP startup failed: decomp_agent",
])
def test_codex_recognises_a_startup_that_stopped_before_any_model_turn(message):
    assert message in codex.CODEX.startup_failure(message)
    assert codex.CODEX.startup_failure("Provider usage limit reached") is None


def test_a_required_server_that_didnt_start_is_said_redacted_and_retried(tmp_path, monkeypatch):
    manager = agents.Manager(RomNetwork(tmp_path / "app.db", tmp_path), tmp_path, URL)
    token = "secret-token-123"
    said = f"Error: required MCP servers failed to initialize: decomp_agent: connection refused {token}"
    code = f"import sys; sys.stdin.read(); print({said!r}, file=sys.stderr, flush=True); sys.exit(1)"
    monkeypatch.setattr(manager, "_command", lambda s, token, workdir: ([sys.executable, "-c", code], dict(os.environ), ""))
    s = agents.Session("codex-1", "codex", "Codex #1", "game", "codex-1", {})
    assert manager._run_cli(s, token, tmp_path) is False  # (the helper loop's usual wait, then it tries again)
    assert "couldn't start decompdecomp's tools" in s.error and "connection refused" in s.error
    assert token not in s.error and "[redacted]" in s.error
    assert not s.limited and not s.auth_failed and not s.signed_out
    assert any(f["type"] == "error" and "before any model turn" in f["text"] for f in s.feed)
