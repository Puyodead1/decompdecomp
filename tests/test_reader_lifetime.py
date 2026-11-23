"""A thread's database reader (store.py) closes when the thread ends, not when the cycle collector next runs."""

import gc
import sqlite3
import threading

from decompnet.store import Store


def test_a_threads_reader_closes_when_the_thread_ends(tmp_path, monkeypatch):
    """Short-lived threads (drafts, the permuter, the routes) each left a connection open until the cycle collector
    ran, and an app started with 256 open files ran out."""
    store, closed, errors = Store(tmp_path / "test.db"), [], []
    connect = sqlite3.connect

    class Connection(sqlite3.Connection):
        def close(self):
            closed.append(threading.get_ident())
            super().close()

    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: connect(*a, factory=Connection, **kw))

    def read():
        try:
            assert store.one("SELECT 1 AS value")["value"] == 1
            assert store.all("SELECT 2 AS value")[0]["value"] == 2
        except BaseException as error:  # noqa: BLE001 (reported by the test's own thread)
            errors.append(error)

    enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(20):
            worker = threading.Thread(target=read)
            worker.start()
            worker.join()
        assert not errors
        assert len(closed) == 20
        assert store.one("SELECT 3 AS value")["value"] == 3
    finally:
        if enabled:
            gc.enable()
        store.conn.close()
