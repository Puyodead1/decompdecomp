"""A model's provider with no room for it: the helper waits like after any throttle, says that it's the provider's,
and a CLI that keeps its session open through it (OpenCode retrying an overloaded provider for as long as it lasts)
is ended once it said so again and again with nothing between."""
import os
import sys
import time

from decompnet import agents as kinds
from decompnet.app import agents
from decompnet.app.agents import Manager
from decompnet.app.engine import RomNetwork

from .test_agents import URL, Quick, _game, _no_agent_settings

OVERLOADED = 'level=error message=failed error="The inference service is overloaded. Please try again later."'


def test_opencode_says_an_overloaded_provider_and_nothing_else():
    opencode = kinds.get("opencode")
    assert "overloaded" in opencode.stderr_retry(OVERLOADED)
    assert not opencode.stderr_retry('level=info message="The inference service is overloaded"')
    assert not opencode.stderr_retry('level=error message=failed error="quota exceeded"')
    assert not kinds.get("claude").stderr_retry(OVERLOADED)  # (an agent that doesn't say it: the default)


def test_a_cli_retrying_an_overloaded_provider_is_ended_and_waits(tmp_path, monkeypatch):
    monkeypatch.setattr(agents, "OVERLOAD_QUIET", 0)
    manager = Manager(RomNetwork(tmp_path / "app.db", tmp_path), tmp_path, URL)
    code = (f"import sys, time\nfor _ in range(3): print({OVERLOADED!r}, file=sys.stderr, flush=True)\n"
            "time.sleep(60)")
    monkeypatch.setattr(manager, "_command", lambda s, token, workdir: ([sys.executable, "-c", code], dict(os.environ), ""))
    s = agents.Session("opencode-1", "opencode", "OpenCode #1", "game", "opencode-1", {})
    began = time.monotonic()
    assert manager._run_cli(s, "token", tmp_path) is False
    assert time.monotonic() - began < 30  # (ended, not waited out)
    assert s.throttled and "overloaded" in s.error and "3 times" in s.error


def test_progress_between_refusals_keeps_the_session(monkeypatch):
    monkeypatch.setattr(agents, "OVERLOAD_QUIET", 0)
    retries = agents._StreamRetries()
    assert not retries.observe("busy") and not retries.observe("busy")
    retries.progress()  # (the model answered between: the CLI's own retrying works)
    assert not retries.observe("busy") and not retries.observe("busy") and not retries.observe("")
    assert retries.observe("busy") and retries.given_up == "busy"
    monkeypatch.setattr(agents, "OVERLOAD_QUIET", 3600)
    later = agents._StreamRetries()
    assert not any(later.observe("busy") for _ in range(10))  # (many, but close together)


def test_a_provider_with_no_capacity_is_waited_out_and_said_so(tmp_path, monkeypatch):
    _no_agent_settings(monkeypatch)
    net = _game(tmp_path)
    manager = Manager(net, tmp_path, URL)
    s = manager._record("game", "antigravity", "agy-1", "agy-1", {})
    s.stop = Quick()
    runs, waits = [], []

    def run(session, token, workdir):
        runs.append(1)
        if len(runs) == 1:
            session.throttled = True
            session.error = "UNAVAILABLE (code 503): No capacity available for model gemini-3-pro"
            return False
        session.stop.set()
        return True

    real_wait = manager._wait
    monkeypatch.setattr(manager, "_run_cli", run)
    monkeypatch.setattr(manager, "_wait", lambda s, why, until, todo="": waits.append(why) or real_wait(s, why, until, todo))
    manager._run(s)
    assert len(runs) == 2 and len(waits) == 1 and "no capacity for this model" in waits[0]
    assert agents.THROTTLED.search("UNAVAILABLE (code 503): No capacity available for model")
