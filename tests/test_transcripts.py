"""Each helper session's full transcript: kept, bounded, and without keys."""

import json

from decompnet.app import agents, tools, transcripts

from .test_agents import URL, Quick, _FakeClaude, _game, _no_agent_settings


def test_a_transcript_keeps_no_keys_and_stays_within_bounds(tmp_path, monkeypatch):
    net = _game(tmp_path)
    t = agents.Manager(net, tmp_path, URL).transcripts  # (helper_sessions is the manager's)
    with net.store.tx() as db:
        db.execute("INSERT INTO helper_sessions(id, helper_id, project, kind, model, agent, started_at) "
                   "VALUES(7, 1, 'game', 'api', 'm', 'api-m-1', 0)")
    t.append(7, "prompt", "use sk-secret and Bearer abc.def", secrets=("sk-secret",))
    t.append(7, "call", {"tool": "x", "arguments": {"api_key": "sk-other", "n": 1}})
    t.append(7, "result", "x" * (transcripts.MAX_TEXT + 50))
    got = t.read("game", 1)
    texts = [e["text"] for e in got["entries"]]
    assert got["session"] == 7 and got["sessions"][0]["entries"] == 3
    assert "sk-secret" not in texts[0] and "abc.def" not in texts[0] and "sk-other" not in texts[1]
    assert texts[2].endswith("50 more characters not kept]")
    monkeypatch.setattr(transcripts, "PAGE", 2)
    first = t.read("game", 1)
    assert first["more"] and len(first["entries"]) == 2
    assert [e["kind"] for e in t.read("game", 1, 7, first["entries"][-1]["id"])["entries"]] == ["result"]
    monkeypatch.setattr(transcripts, "KEEP_ROWS", 1)
    t.prune()
    assert [e["kind"] for e in t.read("game", 1)["entries"]] == ["result"]


def test_an_api_helpers_session_is_kept_with_its_tool_calls(tmp_path, monkeypatch):
    """A helper working alone on a server can only be understood afterwards: its prompt, words, and each tool call
    with what the tool answered are kept for its card's Full transcript."""
    from decompnet.agents import api

    _no_agent_settings(monkeypatch)
    net = _game(tmp_path)
    m = agents.Manager(net, tmp_path, URL)
    m.prompt = lambda s: "task"
    monkeypatch.setattr(tools, "OBSERVERS", [m.record_tool])
    monkeypatch.setitem(tools.HANDLERS, "claim_function", lambda net, agent, slug, **kw: "## CLAIMED: game/f0")
    s = m._record("game", "api", "api-claude-opus-5-5-1", "Anthropic #1",
                  {"provider": "anthropic", "base_url": "https://api.anthropic.com", "model": "claude-opus-5-5",
                   "api_key": "sk-ant-secret", "per_session": 1})
    s.stop = Quick()
    claim = {"content": [{"type": "tool_use", "id": "toolu_1", "name": "claim_function", "input": {}}],
             "stop_reason": "tool_use", "usage": {}}
    done = {"content": [{"type": "text", "text": "I'm done."}], "stop_reason": "end_turn", "usage": {}}
    monkeypatch.setattr(api, "anthropic_client", lambda options: _FakeClaude([claim, done]))
    sessions = []
    real_end = m._session_end
    monkeypatch.setattr(m, "_session_end", lambda *a: (sessions.append(a[1]), real_end(*a), Quick.set(s.stop)))
    m._run(s)
    got = m.transcript(s.id, sessions[0])
    kinds = [e["kind"] for e in got["entries"]]
    assert kinds[0] == "prompt" and "call" in kinds and "result" in kinds and "text" in kinds
    call = next(e for e in got["entries"] if e["kind"] == "call")
    assert json.loads(call["text"]) == {"tool": "claim_function", "arguments": {}}
    assert "CLAIMED" in next(e for e in got["entries"] if e["kind"] == "result")["text"]
    assert not any("sk-ant-secret" in e["text"] for e in got["entries"])
