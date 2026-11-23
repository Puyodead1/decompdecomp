"""Quitting ends the app: at once on Ctrl-C or SIGTERM, within a deadline whatever hangs, and `decomp stop` ends an
app of this home that no longer answers (app/cli.py, app/server.py)."""

import json
import signal
import socket
import subprocess
import sys
import threading
import time

from decompnet.app import cli, server


def test_the_server_waits_a_few_seconds_for_open_connections_not_for_ever():
    """A helper's MCP stream stays open as long as the helper runs: quitting waited for every one."""
    assert cli.server_config(object()).timeout_graceful_shutdown == cli.CLOSING_SECONDS == 5


def test_ctrl_c_starts_quitting_at_once_and_a_second_stops_waiting_for_connections():
    started, release = [], threading.Event()

    def quit_app():
        started.append(threading.current_thread().name)
        release.wait(5)

    web = cli.quitting_server(cli.server_config(object()), quit_app)
    web.handle_exit(signal.SIGINT, None)
    assert web.should_exit and not web.force_exit
    for _ in range(100):
        if started:
            break
        time.sleep(0.01)
    assert started == ["quit"]  # (beside the server: the handler itself takes no lock)
    web.handle_exit(signal.SIGTERM, None)
    assert web.force_exit and len(started) == 1
    release.set()


def test_a_quit_that_hangs_ends_the_process_at_its_deadline(monkeypatch):
    """A quit that never finished left an app that answered nothing and needed SIGKILL."""
    ended = threading.Event()
    monkeypatch.setattr(server.os, "_exit", lambda code: ended.set())
    server.exit_after(0.01)
    assert ended.wait(5)


def _silent_port():
    """A port that accepts connections and never answers them: a hung app's."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    return sock


def _home(tmp_path, monkeypatch, port, pid):
    home = tmp_path / "home"
    (home / ".decomp").mkdir(parents=True)
    (home / ".decomp" / "server.json").write_text(json.dumps({"port": port, "secret": "s", "pid": pid}))
    monkeypatch.setenv("DECOMP_HOME", str(home))
    ended = []
    monkeypatch.setattr(cli, "_end", lambda info, grace, log=print: ended.append(info["pid"]) or True)
    return home / ".decomp" / "server.json", ended


def test_stop_ends_an_app_of_this_home_that_no_longer_answers(tmp_path, monkeypatch, capsys):
    sock = _silent_port()
    try:
        _, ended = _home(tmp_path, monkeypatch, sock.getsockname()[1], 424242)
        assert cli.stop(None) == 0
    finally:
        sock.close()
    assert ended == [424242]
    assert "doesn't answer" in capsys.readouterr().out


def test_stop_ends_nothing_once_the_apps_port_is_closed(tmp_path, monkeypatch, capsys):
    """Once the app has ended, the pid in its server.json may be another program's."""
    sock = _silent_port()
    port = sock.getsockname()[1]
    sock.close()
    _, ended = _home(tmp_path, monkeypatch, port, 424242)
    assert cli.stop(None) == 0 and ended == []
    assert "is not running" in capsys.readouterr().out


def test_stop_never_names_the_first_process_or_itself(tmp_path, monkeypatch):
    sock = _silent_port()
    try:
        state, _ = _home(tmp_path, monkeypatch, sock.getsockname()[1], 1)
        assert cli._hung(state) is None
        state.write_text(json.dumps({"port": sock.getsockname()[1], "secret": "s", "pid": cli.os.getpid()}))
        assert cli._hung(state) is None
    finally:
        sock.close()


def test_an_older_app_that_does_not_quit_is_ended_before_this_one_starts(tmp_path, monkeypatch):
    """It would otherwise keep running beside the new one, on another port, with the same projects."""
    sock = _silent_port()
    try:
        state, ended = _home(tmp_path, monkeypatch, sock.getsockname()[1], 424242)
        monkeypatch.setattr(cli, "_state", lambda path: {"port": sock.getsockname()[1], "secret": "s", "pid": 424242})
        monkeypatch.setattr(cli, "_running_version", lambda port: "0.0.1")
        monkeypatch.setattr(cli, "_alive", lambda port: True)
        monkeypatch.setattr(cli, "_call", lambda *args, **kwargs: {})
        monkeypatch.setattr(cli, "QUIT_WAIT_SECONDS", 0.2)
        assert cli.replace_older(state, log=lambda *_: None) is None
    finally:
        sock.close()
    assert ended == [424242]


def test_a_hung_app_is_ended(tmp_path):
    """SIGTERM first (its quit saves what it can), then SIGKILL; on Windows at once."""
    child = subprocess.Popen([sys.executable, "-c", "import socket, time\n"
                              "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(8)\n"
                              "print(s.getsockname()[1], flush=True); time.sleep(60)"],
                             stdout=subprocess.PIPE, text=True)
    try:
        port = int(child.stdout.readline())
        assert cli._end({"pid": child.pid, "port": port}, grace=5, log=lambda *_: None)
        assert child.wait(timeout=10) is not None
    finally:
        if child.poll() is None:
            child.kill()
        child.stdout.close()
