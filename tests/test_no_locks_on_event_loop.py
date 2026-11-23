"""The app's event loop (every async handler) never waits for a lock: one lock held by a worker thread there freezes
every request, the window's and the helpers' included. Work that may wait goes to a worker thread (`app.call`,
`anyio.to_thread`). A non-blocking try (`acquire(blocking=False)`) can't wait, so it is allowed. The window and tray
programs, whose main thread runs the UI, take no locks at all, and the tray starts without the main thread."""
import ast
import threading
import time
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "decompnet"
# what can wait on a lock without saying "lock": the Jobs methods (app/support.py) that take its lock themselves
# (jobs_locking() finds them: Jobs.start takes none, its thread does), and sleeping
WAITING_CALLS = ("time.sleep", "threading.Event().wait")
# their main thread runs the UI (Cocoa, GTK, WinForms, the tray's loop): a lock another thread holds freezes it
FRONT_ENDS = ("app/macwindow.py", "app/gtkwindow.py", "app/winwindow.py", "app/wintray.py", "app/tray.py")


def _own_nodes(function):
    """The nodes an async function runs itself, not those of the functions it defines (they run where they're sent)."""
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _non_blocking(call: ast.Call) -> bool:
    return any(k.arg == "blocking" and isinstance(k.value, ast.Constant) and k.value.value is False
               for k in call.keywords) or bool(call.args and isinstance(call.args[0], ast.Constant)
                                               and call.args[0].value is False)


def _lock_in(node: ast.With) -> str | None:
    return next((n for n in (ast.unparse(item.context_expr) for item in node.items) if "lock" in n.lower()), None)


def jobs_locking() -> tuple[str, ...]:
    """jobs.<method> for each method of app/support.py's Jobs that takes self._lock on the caller's thread."""
    tree = ast.parse((SRC / "app" / "support.py").read_text(encoding="utf-8"))
    jobs = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Jobs")
    return tuple(f"jobs.{method.name}" for method in jobs.body if isinstance(method, ast.FunctionDef)
                 and any(isinstance(node, ast.With) and _lock_in(node) for node in _own_nodes(method)))


def offences() -> list[str]:
    locking = jobs_locking()
    found = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, ast.AsyncFunctionDef):
                continue
            for node in _own_nodes(function):
                what = None
                if isinstance(node, ast.With):  # (`async with` an asyncio lock is the loop's own, and fine)
                    what = _lock_in(node)
                elif isinstance(node, ast.Call):
                    name = ast.unparse(node.func)
                    if name.endswith(".acquire") and not _non_blocking(node):
                        what = name
                    elif name.endswith(locking) or name in WAITING_CALLS:
                        what = name
                if what:
                    found.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno} {function.name}: {what}")
    return found


def test_async_handlers_never_wait_for_a_lock():
    assert "jobs.cancel" in jobs_locking() and "jobs.start" not in jobs_locking()  # (the check reads Jobs right)
    assert offences() == []


def test_window_and_tray_programs_take_no_locks():
    found = []
    for name in FRONT_ENDS:
        for node in ast.walk(ast.parse((SRC / name).read_text(encoding="utf-8"))):
            what = None
            if isinstance(node, ast.With):
                what = _lock_in(node)
            elif isinstance(node, ast.Call):
                call = ast.unparse(node.func)
                if call.endswith(("Lock", "RLock", "Semaphore", "Condition", ".acquire", "time.sleep")):
                    what = call
            if what:
                found.append(f"{name}:{node.lineno}: {what}")
    assert found == []


def test_the_tray_starts_without_holding_up_the_main_thread(monkeypatch):
    from decompnet.app import tray

    release, results = threading.Event(), []
    monkeypatch.setattr(tray, "start", lambda on_open, on_quit: release.wait(5))
    began = time.monotonic()
    tray.start_in_background(lambda: None, lambda: None, results.append)
    assert time.monotonic() - began < 1 and results == []
    release.set()
    for _ in range(100):
        if results:
            break
        time.sleep(0.01)
    assert results == [True]


def test_a_tray_that_fails_to_start_says_so(monkeypatch):
    from decompnet.app import tray

    def broken(on_open, on_quit):
        raise RuntimeError("no session bus")

    results = []
    monkeypatch.setattr(tray, "start", broken)
    tray.start_in_background(lambda: None, lambda: None, results.append)
    for _ in range(100):
        if results:
            break
        time.sleep(0.01)
    assert results == [False]
