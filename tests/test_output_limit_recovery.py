"""A model whose reply runs into its output limit is cut off in the middle of a tool call: the call never reaches the
app, and the same session only writes the same too-long reply again. The helper gets one fresh session asking for
smaller replies (OUTPUT_RECOVERY); the same again pauses it, instead of spending paid sessions on it."""
import json
import os
import sys

import httpx

from decompnet.agents import api
from decompnet.app import agents
from decompnet.app.agents import OUTPUT_RECOVERY, Manager
from decompnet.app.engine import RomNetwork

from .test_agents import URL, Quick, _FakeClaude, _game, _no_agent_settings


def test_a_cli_cut_off_at_its_output_limit_says_so(tmp_path, monkeypatch):
    manager = Manager(RomNetwork(tmp_path / "app.db", tmp_path), tmp_path, URL)
    event = json.dumps({"type": "turn.failed", "error": {
        "message": "Incomplete response returned, reason: max_output_tokens"}})
    code = f"import sys; print({event!r}); raise SystemExit(1)"
    monkeypatch.setattr(manager, "_command", lambda s, token, workdir: ([sys.executable, "-c", code], dict(os.environ), ""))
    s = agents.Session("codex-1", "codex", "Codex #1", "game", "codex-1", {})
    assert manager._run_cli(s, "token", tmp_path) is False
    assert s.output_limited and "output limit" in s.error and not s.limited and not s.throttled


def test_one_fresh_session_asks_for_smaller_replies_and_a_second_cut_off_pauses(tmp_path, monkeypatch):
    _no_agent_settings(monkeypatch)
    net = _game(tmp_path)
    manager = Manager(net, tmp_path, URL)
    manager.prompt = lambda s: "task"
    s = manager._record("game", "codex", "codex-1", "codex-1", {})
    s.stop = Quick()
    prompts = []

    def run(session, token, workdir):
        prompts.append(manager.session_prompt(session))
        session.output_limited = True
        return False

    monkeypatch.setattr(manager, "_run_cli", run)
    manager._run(s)
    assert prompts[0] == "task" and OUTPUT_RECOVERY in prompts[1] and len(prompts) == 2
    assert s.state == "paused" and "output limit again" in s.why and not s.followup
    assert [r["outcome"] for r in net.store.all("SELECT outcome FROM helper_sessions")] == ["failed", "failed"]


def _api_session(tmp_path, monkeypatch, options):
    _no_agent_settings(monkeypatch)
    net = _game(tmp_path, functions=1)
    manager = Manager(net, tmp_path, URL)
    manager.prompt = lambda s: "task"
    s = manager._record("game", "api", "api-m-1", "box #1", {"per_session": 1, "context_tokens": 32768} | options)
    s.stop = Quick()
    called = []
    monkeypatch.setattr(agents.tools, "call", lambda net, agent, slug, name, args: called.append(name) or "ok")
    return manager, s, net.local_agent(s.agent_name)[0], called


def test_an_api_reply_cut_off_at_its_output_limit_isnt_run(tmp_path, monkeypatch):
    """Its tool call's arguments may be cut off too (read as none): the call isn't made."""
    manager, s, agent, called = _api_session(tmp_path, monkeypatch, {"base_url": "http://mock/v1", "model": "m"})

    def handler(request):
        msg = {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "compile_and_diff", "arguments": '{"source": "int'}}]}
        return httpx.Response(200, json={"choices": [{"message": msg, "finish_reason": "length"}]})
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    assert api.API.run(manager, s, agent) is False
    assert s.output_limited and not called


def test_an_anthropic_reply_cut_off_at_max_tokens_isnt_run(tmp_path, monkeypatch):
    manager, s, agent, called = _api_session(tmp_path, monkeypatch, {
        "provider": "anthropic", "base_url": "https://api.anthropic.com", "model": "claude-opus-5-5", "api_key": "k"})
    reply = {"content": [{"type": "tool_use", "id": "toolu_1", "name": "compile_and_diff", "input": {}}],
             "stop_reason": "max_tokens", "model": "claude-opus-5-5", "usage": {"input_tokens": 1, "output_tokens": 1}}
    monkeypatch.setattr(api, "anthropic_client", lambda options: _FakeClaude([reply]))
    assert api.API.run(manager, s, agent) is False
    assert s.output_limited and not called
