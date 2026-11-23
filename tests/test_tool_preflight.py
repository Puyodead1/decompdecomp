"""Before each session of a CLI helper the app asks its own MCP server for the helper's tools (Manager._preflight_tools):
helpers started paid sessions with no tools and spent them saying so. A server that doesn't answer is checked again
after a short wait, without a session or a failure counted; one that refuses the helper pauses it."""
import socket
import threading
import time
from contextlib import asynccontextmanager

import pytest

from decompnet.app import agents
from decompnet.app.agents import Fatal, Manager, ToolConnectionUnavailable

from .test_agents import URL, Quick, _game, _no_agent_settings


@pytest.fixture
def checks(monkeypatch):
    monkeypatch.setattr(Manager, "check_tools", True)


@pytest.fixture
def served(tmp_path, checks):
    """The real app on a free port, as the helpers' CLIs reach it."""
    import uvicorn

    from decompnet.app.server import build

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    _game(tmp_path)  # (the project's records, in the database build opens)
    from decompnet.app.engine import RomNetwork

    net = RomNetwork(tmp_path / "app.db", tmp_path)
    mcp, manager, security, _ = build(net, tmp_path, port, "secret")
    app = mcp.streamable_http_app(transport_security=security, host="127.0.0.1")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    try:
        yield net, manager
    finally:
        server.should_exit = True
        thread.join(10)


def test_a_helper_with_its_project_passes_and_one_without_is_paused(served, monkeypatch):
    _no_agent_settings(monkeypatch)
    net, manager = served
    s = manager._record("game", "claude", "claude-1", "claude-1", {})
    agent, token = net.local_agent(s.agent_name)
    with pytest.raises(Fatal, match="without its project's tools"):  # (no project assigned yet: an empty list)
        manager._preflight_tools(token)
    manager.assignments[agent.id] = "game"
    manager._preflight_tools(token)
    with pytest.raises(Fatal, match="refused"):
        manager._preflight_tools("not-a-token")


def test_a_server_that_doesnt_answer_is_checked_again_and_the_token_never_shown(tmp_path, checks, monkeypatch):
    import mcp.shared._httpx_utils as http

    _no_agent_settings(monkeypatch)
    net = _game(tmp_path)
    manager = Manager(net, tmp_path, URL)
    s = manager._record("game", "claude", "claude-1", "claude-1", {})
    _, token = net.local_agent(s.agent_name)

    @asynccontextmanager
    async def unavailable(**kwargs):
        raise ExceptionGroup("transport failed", [TimeoutError(f"busy {token}")])
        yield  # pragma: no cover

    monkeypatch.setattr(http, "create_mcp_http_client", unavailable)
    with pytest.raises(ToolConnectionUnavailable) as caught:
        manager._preflight_tools(token)
    said = str(caught.value)
    assert "connecting failed" in said and "TimeoutError" in said
    assert token not in said and "[redacted]" in said


def test_an_unanswered_check_waits_without_a_session_or_a_failure(tmp_path, checks, monkeypatch):
    _no_agent_settings(monkeypatch)
    net = _game(tmp_path)
    manager = Manager(net, tmp_path, URL)
    s = manager._record("game", "claude", "claude-1", "claude-1", {})
    s.stop = Quick()
    checked, ran = [], []

    def check(token):
        checked.append(1)
        if len(checked) <= 7:
            raise ToolConnectionUnavailable("connecting failed after 15s: TimeoutError")

    def run(session, token, workdir):
        ran.append(1)
        session.stop.set()
        return True

    monkeypatch.setattr(manager, "_preflight_tools", check)
    monkeypatch.setattr(manager, "_run_cli", run)
    manager._run(s)
    assert len(checked) == 8 and ran == [1] and s.runs == 1
    assert [round(w) for w in s.stop.waits if w] == [5, 10, 20, 40, 60, 60, 60]
    assert s.state != "paused"
    assert [r["outcome"] for r in net.store.all("SELECT outcome FROM helper_sessions")] == ["stopped"]


def test_a_refused_check_pauses_the_helper_before_any_session(tmp_path, checks, monkeypatch):
    _no_agent_settings(monkeypatch)
    net = _game(tmp_path)
    manager = Manager(net, tmp_path, URL)
    s = manager._record("game", "claude", "claude-1", "claude-1", {})
    s.stop = Quick()

    def refused(token):
        raise Fatal("The app's tool server answered this helper without its project's tools")

    monkeypatch.setattr(manager, "_preflight_tools", refused)
    monkeypatch.setattr(manager, "_run_cli", lambda *a: pytest.fail("a session started"))
    manager._run(s)
    assert s.state == "paused" and "without its project's tools" in s.why
    assert not net.store.all("SELECT * FROM helper_sessions")
    assert agents.agents.get(s.kind).command  # (an API helper, which calls the tools in-process, isn't checked)
