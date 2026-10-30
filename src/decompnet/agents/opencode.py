"""opencode, an agent CLI for any provider's models (DeepSeek, Qwen, Kimi, OpenCode Zen's free ones...). Each session
runs `opencode run --format json` in a folder whose opencode.json names the app's MCP server and nothing else; it
prints one JSON event a line, and says what failed on stderr (--print-logs)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import SAID_CHARS, Agent, args_brief, error_text, number, read_json, tool_name, usage_item

ZEN = "opencode/"  # OpenCode Zen's models: their names start with it, and opencode's default is one of them
STANDALONE_FROM = 2  # the major version that runs sessions in a shared service unless told --standalone
PLACEHOLDER = "Unexpected server error"  # its JSON error when the log line says what failed
MCP_SERVER = "decompdecomp"  # the app's MCP server, in the config and in the plugin that waits for it
MCP_WAIT_SECONDS = 10  # how long opencode 2's first prompt waits for that server to connect (#24)
MCP_SETTLE_MS = 300  # then for the registry's 100 ms debounce to publish its tools
PLUGIN_DIR = "decompdecomp-wait"  # the plugin's folder in a helper's own folder, next to its opencode.json
# reasoning efforts from least to most: a model offers some of them (its variants), and one it doesn't stops a session
USAGE_SECONDS = 15  # how long its service may take to say when a usage limit resets
EFFORT_SCALE = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
_PLUGIN_SOURCE = Path(__file__).with_name("opencode_wait.js")


def _wait_plugin() -> str:
    """opencode 2's plugin for #24, with the app's server name and timings filled in. It waits before the first prompt
    until the app's MCP tools are registered, because opencode connects MCP in the background and its first request
    otherwise carries no tools (upstream #51812, fix #54942). Remove it once opencode waits itself."""
    source = _PLUGIN_SOURCE.read_text(encoding="utf-8")
    return (source.replace("__DECOMP_MCP_SERVER__", json.dumps(MCP_SERVER))
                  .replace("__DECOMP_MCP_DEADLINE_MS__", str(MCP_WAIT_SECONDS * 1000))
                  .replace("__DECOMP_MCP_SETTLE_MS__", str(MCP_SETTLE_MS)))


class Opencode(Agent):
    id = "opencode"
    name = "opencode"
    command = "opencode"
    vendor = "any provider (DeepSeek, Qwen, Kimi, ...)"
    install = "curl -fsSL https://opencode.ai/v2/install | bash"  # (opencode.ai/install gives 1.x)
    windows_install = "npm install -g opencode-ai"
    signin = "Run `opencode auth login` once to add a provider (DeepSeek, OpenRouter, ...)."
    docs = "https://opencode.ai"
    models_args = ("models",)
    takes_effort = True  # opencode 2 picks a model's reasoning effort as a variant of it: provider/model#high
    # OpenCode Zen's free models: "Free usage limit reached", then opencode retried in silence for as long as it let it
    # (a helper's session hung, then counted as a failure)
    limit_hangs = True

    def limit_resets_at(self) -> float | None:
        """OpenCode Go's "5 hour usage limit reached" says no time: its background service does (2.2's usage route,
        each meter's `limited` and `resetsAt`). A helper otherwise waited 30 minutes for a limit that reset in 10."""
        import httpx

        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
        service = read_json(base / "opencode" / "service.json")
        if not service.get("url") or not service.get("password"):
            return None
        try:
            r = httpx.get(f"{service['url']}/api/experimental/usage/limits", auth=("opencode", service["password"]),
                          timeout=USAGE_SECONDS)
            meters = ((r.json().get("data") or {}).get("go") or {}).values() if r.status_code == 200 else []
        except (httpx.HTTPError, ValueError, AttributeError):
            return None
        resets = [m["resetsAt"] / 1000 for m in meters if isinstance(m, dict) and m.get("limited")
                  and isinstance(m.get("resetsAt"), (int, float))]
        return max(resets) if resets else None

    def read_models(self, lines: list[str]) -> list[dict]:
        """`opencode models`: "<provider>/<model>" per model."""
        rows = [r for r in lines if re.fullmatch(r"[\w.-]+/[\w.:/-]+", r)]
        catalog = self.catalog()
        return [{"id": r, "name": r.split("/", 1)[1], "note": r.split("/", 1)[0],
                 **({} if (e := self.model_efforts(r, catalog)) is None else {"efforts": e})} for r in rows]

    def catalog(self) -> dict:
        """opencode's copy of the models it knows (models.dev's), with the efforts each offers."""
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        return read_json(base / "opencode" / "models.json")

    def model_efforts(self, model: str, catalog: dict) -> list[str] | None:
        """The reasoning efforts a model offers, as opencode's catalog says (DeepSeek V4.1 Flash on OpenCode Go: low,
        high and max, and "#medium" stopped each of its sessions: "Variant unavailable"); None when it doesn't say."""
        provider, _, name = model.split("#", 1)[0].partition("/")
        info = ((catalog.get(provider) or {}).get("models") or {}).get(name)
        if not isinstance(info, dict):
            return None
        if not info.get("reasoning"):
            return []
        for o in info.get("reasoning_options") or []:
            if isinstance(o, dict) and o.get("type") == "effort" and isinstance(o.get("values"), list):
                return [v for v in o["values"] if isinstance(v, str)]
        return None

    def offered_effort(self, model: str) -> str:
        """The model with an effort it offers: the nearest one when it lacks the one asked for (the lower of two as
        near: a helper started before the launcher knew, or a model whose efforts changed), none for a model that
        doesn't reason."""
        name, _, effort = model.partition("#")
        efforts = self.model_efforts(name, self.catalog()) if effort else None
        if efforts is None or effort in efforts:
            return model
        if effort not in EFFORT_SCALE or not (known := [e for e in efforts if e in EFFORT_SCALE]):
            return name
        at = EFFORT_SCALE.index(effort)
        return f"{name}#{min(known, key=lambda e: (abs(EFFORT_SCALE.index(e) - at), EFFORT_SCALE.index(e)))}"

    def config_model(self) -> str | None:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        return read_json(base / "opencode" / "opencode.json").get("model") or None

    def standalone(self, exe: str) -> bool:
        """opencode 2 runs every `opencode run` in one background service, which connects the user's own MCP servers
        once, without a helper's session token: both GTA San Andreas helpers worked as the user's one chat agent, on
        one claim, whatever their folders said. --standalone gives each helper a server of its own, started from its
        own process (before 2.0 there's no such service, and the flag would stop it)."""
        text = self.version(exe, run=False) or self.version(exe)
        m = re.search(r"(\d+)\.\d+", text or "")
        return bool(m) and int(m.group(1)) >= STANDALONE_FROM

    def session_command(self, exe: str, workdir: Path, mcp_url: str, token: str, model: str) -> tuple[list[str], dict]:
        # "deny" takes the tools out of the request, and OpenCode Zen's free models then refuse it ("can only be
        # used from within OpenCode"). "ask" keeps the usual tools, and `opencode run` rejects every ask itself.
        if model:
            model = self.offered_effort(model)
        zen = (model or self.config_model() or ZEN).startswith(ZEN)
        never = "ask" if zen else "deny"
        headers = {"Authorization": f"Bearer {token}"}
        if self.standalone(exe):
            # opencode 2: Mario Kart 64's helpers read the user's home and fetched a public decomp's code. Its own
            # format, since the old one loses `codemode`: off, the app's tools are the model's own, and `execute` (a
            # JavaScript runner whose fetch() reaches the internet, and which only "deny" removes) can go, with
            # subagents; nothing outside the helper's own folder either
            deny = {"execute", "subagent", "external_directory"}
            # #24: opencode 2 connects MCP servers asynchronously, so a helper's first model request could carry no
            # decompdecomp tools and the model guessed their names for ~18 s. This plugin waits for the server once,
            # before the first prompt; remove it once opencode waits itself (upstream #51812, fix #54942).
            (workdir / PLUGIN_DIR).mkdir(parents=True, exist_ok=True)
            (workdir / PLUGIN_DIR / "index.js").write_text(_wait_plugin(), encoding="utf-8")
            config = {"mcp": {"servers": {MCP_SERVER: {"type": "remote", "url": mcp_url, "headers": headers,
                                                       "codemode": False}}},
                      "plugins": [f"./{PLUGIN_DIR}"],
                      "permissions": [{"action": a, "resource": "*", "effect": "deny" if a in deny else never}
                                      for a in ("edit", "shell", "webfetch", "websearch", *sorted(deny))]}
            # its title agent, as small_model below: left alone, a helper on an OpenCode Go model titled each
            # session with Zen's paid one (402 and 403 refusals, one per session start)
            if (own := (model or self.config_model() or "").split("#", 1)[0]) and "/" in own:
                provider, name = own.split("/", 1)
                config["agents"] = {"title": {"model": {"providerID": provider, "model": name}}}
        else:
            config = {"mcp": {MCP_SERVER: {"type": "remote", "url": mcp_url, "enabled": True, "headers": headers}},
                      "permission": {"edit": never, "bash": never, "webfetch": never}}
            # its "small model" titles each session: by default OpenCode Zen's (a paid nano model, which a free-only
            # account saw called by every helper, "Insufficient account funds"); the helper's own model does it here
            if (own := (model or self.config_model() or "").split("#", 1)[0]):
                config["small_model"] = own
        (workdir / "opencode.json").write_text(json.dumps({"$schema": "https://opencode.ai/config.json", **config}),
                                               encoding="utf-8")
        # --print-logs: opencode's JSON error only says "Unexpected server error"; the log line says what failed.
        # (No --dir: it runs in workdir, and OpenCode before 1.4 stops at the flag. No --log-level either: before
        # 2.0 it took only ERROR, from 2.0 only error, and either stops the other at once.)
        cmd = [exe, "run", *(["--standalone"] if self.standalone(exe) else []), "--format", "json", "--print-logs"]
        return cmd + (["-m", model] if model else []), {}

    def parse(self, event: dict, state: dict) -> list[tuple[str, str] | None]:
        t = event.get("type")
        out: list[tuple[str, str] | None] = []
        if t == "error":  # {"error": {"name", "data": {"message"}}}
            text = error_text(event.get("error") or event.get("message"))
            if not text.startswith(PLACEHOLDER):  # its log line on stderr says what failed
                out.append(("error", text[:SAID_CHARS]))
        elif t == "tool_use":
            part = event.get("part") if isinstance(event.get("part"), dict) else event
            name = part.get("tool_name") or part.get("tool") or part.get("name") or ""
            args = part.get("parameters") or (part.get("state") or {}).get("input") or part.get("input")
            out.append(("tool", f"{tool_name(name)}({args_brief(args)})"))
        elif t == "text" and isinstance(event.get("part"), dict):
            text = event["part"].get("text", "").strip()
            if text:
                out.append(("text", text))
        elif t in ("step_finish", "step-finish") and isinstance(event.get("part"), dict):  # one step of the model
            part = event["part"]
            tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
            cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
            out.append(usage_item(usd=part.get("cost"), input=number(tokens, "input"),
                                  output=number(tokens, "output") + number(tokens, "reasoning"),
                                  cache_read=number(cache, "read"), cache_write=number(cache, "write"), turns=1))
        return out

    def clean_stderr(self, line: str) -> str:
        """--print-logs: keep the error itself, drop the stack noise."""
        line = line.strip()
        if "level=" not in line:
            return line
        m = re.search(r'\berror="((?:[^"\\]|\\.)*)"', line)
        return m.group(1).replace('\\"', '"') if m and re.search(r"level=error\b", line, re.I) else ""


OPENCODE = Opencode()
