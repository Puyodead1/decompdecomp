"""The app's log is always on and holds what went wrong (app/support.py file_log): the app once quit at start
without a word, and finding out why meant guessing."""

import logging
import threading

from decompnet.app import support
from decompnet.app.support import file_log


def test_the_log_holds_debug_messages_other_libraries_and_crashes_in_threads(tmp_path):
    path = tmp_path / "logs" / "decomp.log"
    log = file_log(path)
    log.debug("our own debug line")
    logging.getLogger("uvicorn.error").error("the web server's error")
    worker = threading.Thread(target=lambda: 1 / 0, name="doomed")
    worker.start()
    worker.join()
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = path.read_text()
    assert "our own debug line" in text and "the web server's error" in text
    assert "uncaught error in thread doomed" in text and "ZeroDivisionError" in text
    assert file_log(path) is log  # once: a second call adds no second handler
    assert sum(getattr(h, "baseFilename", None) == str(path) for h in logging.getLogger().handlers) == 1


def test_the_web_servers_errors_reach_the_log(tmp_path):
    """uvicorn's own logging setup kept its errors in a terminal of their own, never in the app's log."""
    from decompnet.app import cli

    path = tmp_path / "logs" / "decomp.log"
    file_log(path)
    cli.server_config(lambda *a: None)  # what the app runs the server with (it sets logging up as it's made)
    logging.getLogger("uvicorn.error").error("Exception in ASGI application")
    logging.getLogger("uvicorn.access").info("GET /api/live 200")
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = path.read_text()
    assert "Exception in ASGI application" in text and "GET /api/live" not in text


def test_a_log_that_cant_be_rolled_over_keeps_every_line(tmp_path, monkeypatch):
    """On Windows a log another program had open couldn't be renamed: the rollover failed, and every line after it
    was lost (a guest's log ended two days before what it was asked about). The lines go on in the same file, and
    the rollover is tried again later."""
    path = tmp_path / "decomp.log"
    handler = support.LogFile(path, maxBytes=200, backupCount=2, encoding="utf-8")
    log = logging.getLogger("decompdecomp.test-rollover")
    log.propagate, log.level = False, logging.INFO
    log.addHandler(handler)
    clock = [1000.0]
    monkeypatch.setattr(support.time, "monotonic", lambda: clock[0])

    def held(source, dest):
        raise PermissionError(32, "The process cannot access the file because it is being used by another process")
    try:
        handler.rotate = held
        for n in range(20):
            log.info("line %d of a busy room", n)
        handler.flush()
        text = path.read_text()
        assert all(f"line {n} of a busy room" in text for n in range(20))
        assert text.count("couldn't be started afresh") == 1  # tried once, not on every line
        clock[0] += support.LOG_RETRY
        del handler.rotate  # the other program let go
        log.info("after it let go")
        handler.flush()
        assert path.read_text().strip().endswith("after it let go") and (tmp_path / "decomp.log.1").exists()
    finally:
        log.removeHandler(handler)
        handler.close()


def test_the_log_keeps_requests_failures_but_not_every_request(tmp_path):
    """A room's guest logged every request to the host (a sync every two seconds, a heartbeat every five) and every
    connection Windows reset: 85% of a log that filled its 5 MB in two days."""
    path = tmp_path / "logs" / "decomp.log"
    file_log(path)
    logging.getLogger("httpx").info('HTTP Request: GET https://host.example/collab/whoami "HTTP/1.1 200 OK"')
    logging.getLogger("httpx").warning("a request's own warning")
    try:
        raise ConnectionResetError(10054, "An existing connection was forcibly closed by the remote host")
    except ConnectionResetError:
        logging.getLogger("asyncio").error("Exception in callback _ProactorBasePipeTransport._call_connection_lost(None)",
                                           exc_info=True)
    try:
        raise ValueError("a real one")
    except ValueError:
        logging.getLogger("asyncio").error("Exception in callback something else", exc_info=True)
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = path.read_text()
    assert "collab/whoami" not in text and "a request's own warning" in text
    assert "_call_connection_lost" not in text and "a real one" in text


def test_a_file_held_for_a_moment_is_still_replaced(tmp_path, monkeypatch):
    """A Windows guest's compiler survey of a GameCube project died of "Access is denied" replacing configure.py, a
    file something else had open for a moment: the replace waits that out."""
    import os

    from decompnet import hostenv

    tmp, path = tmp_path / "configure.tmp", tmp_path / "configure.py"
    tmp.write_text("new")
    path.write_text("old")
    real, refused = os.replace, []

    def held(src, dst):
        if len(refused) < 3:
            refused.append(dst)
            raise PermissionError(5, "Access is denied")
        real(src, dst)
    monkeypatch.setattr(hostenv.os, "replace", held)
    monkeypatch.setattr(hostenv.sys, "platform", "win32")
    monkeypatch.setattr(hostenv.time, "sleep", lambda s: None)
    hostenv.replace_file(tmp, path)
    assert path.read_text() == "new" and len(refused) == 3
