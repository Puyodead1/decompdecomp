"""A weekly usage limit names the day it resets ("resets Nov 9 at 5pm (Europe/London)"): the helper waits for it once,
instead of retrying on the short fallback waits all week."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from decompnet.app.agents import limit_reset


@pytest.mark.parametrize("text", [
    "You've hit your weekly limit · resets Nov 9 at 5pm (Europe/London)",
    "Quota exhausted; resets November 9 at 5:00 PM (Europe/London)",
    "Available again Nov 9, 2026 at 17:00 (Europe/London)",
])
def test_explicit_weekly_reset_date(text):
    now = datetime(2026, 11, 6, 10, tzinfo=timezone.utc).timestamp()
    assert limit_reset(text, now) == datetime(2026, 11, 9, 17, tzinfo=ZoneInfo("Europe/London")).timestamp()


def test_yearless_reset_crosses_year_boundary():
    now = datetime(2026, 12, 30, 10, tzinfo=timezone.utc).timestamp()
    assert limit_reset("resets Jan 2 at 12am (UTC)", now) == datetime(2027, 1, 2, tzinfo=timezone.utc).timestamp()


def test_dated_reset_uses_timezone_offset_at_reset_not_current_offset():
    now = datetime(2026, 10, 31, 17, tzinfo=ZoneInfo("America/New_York")).timestamp()
    expected = datetime(2026, 11, 1, 17, tzinfo=ZoneInfo("America/New_York")).timestamp()
    assert expected - now == 25 * 3600
    assert limit_reset("resets Nov 1 at 5pm (America/New_York)", now) == expected


@pytest.mark.parametrize("text", [
    "resets Nov 5 at 5pm (UTC)",  # already past: next year's is too far off to believe
    "resets Nov 20 at 5pm (UTC)",
    "resets Nov 31 at 5pm (UTC)",
    "resets Nov 9 at 13pm (UTC)",
    "resets Nov 9 at 5:99pm (UTC)",
    "resets Nov 9 at 5pm (Unknown/Timezone)",
    "resets Nov 9 at 5pm (Not a zone)",
    "resets Nov 9 at 5pm ()",
    "resets Nov 9",
    "resets Nov 9 at 5",
    "resets Frob 9 at 5pm (UTC)",
])
def test_invalid_past_distant_or_ambiguous_dates_remain_unknown(text):
    now = datetime(2026, 11, 6, 10, tzinfo=timezone.utc).timestamp()
    assert limit_reset(text, now) is None


def test_weekly_reset_flows_into_one_manager_wait_before_retry(tmp_path, monkeypatch):
    from decompnet.app import agents
    from tests.test_agents import URL, Quick, _game, _no_agent_settings

    _no_agent_settings(monkeypatch)
    now = datetime(2026, 11, 6, 10, tzinfo=timezone.utc).timestamp()
    monkeypatch.setattr(agents.time, "time", lambda: now)
    net = _game(tmp_path)
    manager = agents.Manager(net, tmp_path, URL)
    session = manager._record("game", "claude", "claude-1", "claude-1", {})
    session.stop = Quick()
    said = "You've hit your weekly limit · resets Nov 9 at 5pm (Europe/London)"
    runs = []

    def run(current, token, workdir):
        runs.append(1)
        if len(runs) == 1:
            current.push("text", said)
            current.limited = True
            current.limit_until = agents.limit_reset(said)
            return False
        manager.stop(current.id)
        return True

    monkeypatch.setattr(manager, "_run_cli", run)
    manager._run(session)
    expected = datetime(2026, 11, 9, 17, tzinfo=timezone.utc).timestamp() - now + agents.LIMIT_RESET_MARGIN
    assert max(w for w in session.stop.waits if w) == pytest.approx(expected, abs=5)  # (the workers' stagger adds a few)
    assert runs == [1, 1]
    assert [r["outcome"] for r in net.store.all("SELECT outcome FROM helper_sessions")] == ["limit", "stopped"]


@pytest.mark.parametrize("apostrophe", ["'", "’"])
def test_codex_usage_limit_is_a_limit_and_says_when_it_resets(apostrophe):
    """Codex writes "You’ve hit your usage limit ... or try again at Nov 24th, 2026 8:43 PM." (a typographic
    apostrophe, an ordinal day, its local time): read as an ordinary failure, five in a row paused the helper."""
    from decompnet.agents.codex import CODEX
    from decompnet.app.agents import LIMIT

    said = (f"You{apostrophe}ve hit your usage limit. Upgrade to Pro (https://chatgpt.com/explore/pro), visit "
            "https://chatgpt.com/settings/usage to purchase more credits or try again at Nov 24th, 2026 8:43 PM.")
    state = {}
    CODEX.parse({"type": "turn.failed", "error": {"message": said}}, state)
    assert CODEX.quota_error(state, 1, [], said if LIMIT.search(said) else "") == said
    assert CODEX.quota_error({}, 1, [said], "") == said  # (on stderr alone too)
    now = datetime(2026, 11, 23, 20, 19).astimezone().timestamp()
    assert limit_reset(said, now) == datetime(2026, 11, 24, 20, 43).astimezone().timestamp()
    assert limit_reset("You’ve hit your usage limit. Try again at Nov 1st, 2026 9:05 AM.",
                       datetime(2026, 10, 31, 12).astimezone().timestamp()) == datetime(2026, 11, 1, 9, 5).astimezone().timestamp()
