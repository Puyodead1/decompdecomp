"""Browsers on other computers (app/browsers.py): pairing one (/pair, with a code from Settings or `decomp pair`), the
ones paired, and the page's web app manifest, which lets Edge or Chrome install the page as an app of its own.
"""

from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from .. import browsers, edition
from . import App

SESSION_SECONDS = 400 * 24 * 3600  # as long as browsers keep a cookie: a session ends when it's removed in Settings
PAGE = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width, initial-scale=1'>"
        "<title>decompdecomp</title><body style='font:16px/1.5 system-ui;background:#0b0c0e;color:#e8e6e1;"
        "padding:3rem 1rem;max-width:40rem;margin:auto'>")


def register(app: App) -> None:
    mcp, guard, body, fail, host_ok, paired = app.mcp, app.guard, app.body, app.fail, app.host_ok, app.browsers

    def link(request: Request, code: str) -> str:
        """The pairing link: at the tailnet address (`tailscale serve`), or where this request came from."""
        host = request.headers.get("host") or ""
        if browsers.remote_host(host):
            return f"https://{host.removesuffix(':443')}/pair?code={code}"
        name = browsers.tailnet_name()
        return f"https://{name}/pair?code={code}" if name else f"http://{host}/pair?code={code}"

    @mcp.custom_route("/pair", methods=["GET"])
    async def pair(request: Request) -> Response:
        if not host_ok(request):
            return Response(status_code=403)
        token = paired.redeem(request.query_params.get("code", ""),
                              browsers.browser_name(request.headers.get("user-agent", "")))
        if token is None:
            return HTMLResponse(PAGE + "<p><b>This link was used already, or it's too old.</b></p><p>Ask for a new one: "
                                "<code>decomp pair</code> on the computer decompdecomp runs on.</p>", status_code=400)
        # a page that moves on by itself, not a redirect: the cookie then goes with a navigation that starts here
        res = HTMLResponse(PAGE + "<meta http-equiv=refresh content='0;url=/'><p>This browser is paired. Opening "
                           "decompdecomp…</p>", headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        res.set_cookie(browsers.COOKIE, token, max_age=SESSION_SECONDS, path="/", httponly=True, samesite="lax",
                       secure=secure)
        return res

    @mcp.custom_route("/manifest.webmanifest", methods=["GET"])
    async def manifest(request: Request) -> Response:
        if not host_ok(request):
            return Response(status_code=403)
        return Response(json.dumps({
            "name": edition.NAME, "short_name": edition.NAME, "start_url": "/", "scope": "/", "display": "standalone",
            "background_color": "#0b0c0e", "theme_color": "#0b0c0e",
            "icons": [{"src": "/assets/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}],
        }), media_type="application/manifest+json")

    @mcp.custom_route("/api/browsers", methods=["GET", "POST"])
    async def api_browsers(request: Request) -> Response:
        """GET: the paired browsers, and the tailnet address. POST {"pair": true}: a pairing code and its link;
        {"remove": id}: that browser's session ends."""
        if (bad := guard(request, write=request.method == "POST")):
            return bad
        if request.method == "GET":
            return JSONResponse({"browsers": paired.listing(), "address": browsers.tailnet_name(),
                                 "viewer": request.state.viewer})
        data = await body(request)
        if data.get("pair"):
            code = paired.pair_code()
            return JSONResponse({"code": code, "link": link(request, code), "minutes": browsers.PAIR_SECONDS // 60})
        if data.get("remove"):
            if not paired.remove(str(data["remove"])):
                return fail(ValueError("no such browser"), 404)
            return JSONResponse({"browsers": paired.listing()})
        return fail(ValueError("pair, or remove a browser"))
