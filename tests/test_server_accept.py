"""A connection reset before the server accepts it doesn't stop the app answering: on Windows the default event loop
(Proactor) closed its listening socket then (CPython #93821), and the window and helpers got no answer again."""

import asyncio
import socket
import struct
import sys
import threading

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from decompnet import hostenv
from decompnet.app import cli


async def live(request):
    return PlainTextResponse("live")


APP = Starlette(routes=[Route("/live", live)])


def reset_server(address, answered: list):
    """A uvicorn server that, once serving, resets a queued connection and then asks for /live."""

    class ResetServer(uvicorn.Server):
        async def main_loop(self):
            # the loop's accept is waiting; one connection takes it while a second, queued behind it, is reset
            await asyncio.sleep(0)
            with socket.create_connection(address, timeout=2):
                with socket.create_connection(address, timeout=2) as reset:
                    linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)
                    reset.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)  # closed with a reset
                async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                    response = await client.get(f"http://127.0.0.1:{address[1]}/live")
                answered.append((response.status_code, response.text))
            if sys.platform == "win32":
                assert isinstance(asyncio.get_running_loop(), asyncio.SelectorEventLoop)

    return ResetServer


def test_the_app_answers_after_a_connection_is_reset_before_its_accepted(monkeypatch):
    answered = []
    with cli._listen(0) as listener:
        monkeypatch.setattr(uvicorn, "Server", reset_server(listener.getsockname(), answered))
        cli.serve_app(APP, listener)
    assert answered == [(200, "live")]


def test_a_rooms_server_in_its_own_thread_does_too():
    """A room's server (routes/rooms.py) runs in a thread of its own, open to teammates' computers."""
    answered = []
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = reset_server(("127.0.0.1", port), answered)(
        uvicorn.Config(APP, host="127.0.0.1", port=port, log_config=None, access_log=False))
    thread = threading.Thread(target=hostenv.run_server, args=(server,), daemon=True)
    thread.start()
    thread.join(30)
    assert answered == [(200, "live")]
