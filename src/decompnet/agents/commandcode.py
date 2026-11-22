"""Command Code (commandcode.ai), a coding agent CLI for frontier and open models (Claude, GPT, Kimi, DeepSeek, GLM,
Qwen...), installed from npm (`command-code`; its commands are `cmd`, `cmdc` on Windows, and `command-code`).

Each session runs `command-code -p` (print mode: the prompt on stdin, as it reads it when -p comes without a query)
with `--output-format json`: one line a JSON object, `{"type": "event", "event": {...}}` for what the agent does (a
finished assistant message is a `message_end` event whose content holds text, thinking and tool_use blocks, as
Anthropic's do) and a last `{"type": "result", "subtype": "success" | "error" | "max_turns", "usage": {...}}`.

It runs with a private home (HOME): Command Code reads its settings, MCP servers, skills and mods from
~/.commandcode, so the user's own MCP servers, plugins and taste never reach a session. Its home holds only:
- settings.json: permissions in "dont-ask" mode, which runs nothing that isn't allowed and never asks, allowing
  decompdecomp's MCP server alone (`mcp__decomp`), with its shell, file, web and subagent tools denied besides; the
  model, when one is chosen; taste learning off (a session shouldn't learn from, or write to, the user's taste);
- mcp.json: decompdecomp's MCP endpoint, with the session's token (in the session's own folder, as Claude Code's);
- providers.json, copied when the user has one: the providers of their own keys (BYOK), for models run on those.
Its sign-in goes in by its environment (COMMAND_CODE_API_KEY, which it reads before ~/.commandcode/auth.json): the
user's own variable, else the key `command-code login` saved, so no credential file is copied.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from . import SAID_CHARS, Agent, args_brief, number, read_json, tool_name, usage_item

KEY_ENV = "COMMAND_CODE_API_KEY"
# A session's turns at most (each a model round trip): Command Code's own default is 100, and a helper's session
# runs to a hundred tool calls and more (Claude Code's took 70 and 80 a session on a GameCube game).
MAX_TURNS = 300
# its own tools a session may not use: decompdecomp's are all it needs, and it runs on the user's computer. The
# readers too: a session starts in its own folder, not the project's (read_file and search_code read that).
DENIED = ["Bash", "Shell", "Read", "Glob", "Grep", "Edit", "Write", "WebFetch", "WebSearch", "Agent"]
# a model line of `--list-models`: its id, two spaces or more, "FREE" maybe, what it is, "(default)" maybe
MODEL_LINE = re.compile(r"^(\S+)\s{2,}(?:FREE\s+)?(.*?)(\s*\(default\))?$")


def home() -> Path:
    return Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or Path.home())


class CommandCode(Agent):
    id = "commandcode"
    name = "Command Code"
    command = "command-code"  # (its `cmd` is Windows' own shell there; `command-code` names it everywhere)
    vendor = "Command Code"
    install = "npm install -g command-code@latest"
    signin = "Open a terminal and run `command-code login` (`cmd login`) once to sign in."
    docs = "https://commandcode.ai/docs"
    models_args = ("--list-models",)

    def read_models(self, lines: list[str]) -> list[dict]:
        """What `--list-models` prints: a heading, then each maker's models under its name, a line each ("id  what it
        is (default)"), then how to pass one; the ids are what --model takes."""
        out, started = [], False
        for line in lines:
            if line.startswith("Available models"):
                started = True
                continue
            if line.startswith("Pass the full id"):
                break
            m = MODEL_LINE.match(line) if started else None
            if m and not m.group(1).endswith(":"):
                note = m.group(2).strip() + (" (your default)" if m.group(3) else "")
                out.append({"id": m.group(1), "name": m.group(1), "note": note})
        return out

    def config_model(self) -> str | None:
        return read_json(home() / ".commandcode" / "settings.json").get("model") or None

    def session_command(self, exe: str, workdir: Path, mcp_url: str, token: str, model: str) -> tuple[list[str], dict]:
        mine = home() / ".commandcode"
        private = workdir / "home"
        config = private / ".commandcode"
        config.mkdir(parents=True, mode=0o700, exist_ok=True)
        settings = {"permissions": {"defaultMode": "dont-ask", "allow": ["mcp__decomp"], "deny": DENIED},
                    "tasteLearning": False}
        if model:
            settings["model"] = model
        (config / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
        mcp = config / "mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"decomp": {"type": "http", "url": mcp_url,
                                                             "headers": {"Authorization": f"Bearer {token}"}}}}),
                       encoding="utf-8")
        mcp.chmod(0o600)
        if (mine / "providers.json").is_file():  # (the user's own keys' providers, for models run on them)
            shutil.copyfile(mine / "providers.json", config / "providers.json")
            (config / "providers.json").chmod(0o600)
        env = {"HOME": str(private), "USERPROFILE": str(private), "NO_COLOR": "1"}
        key = os.environ.get(KEY_ENV) or read_json(mine / "auth.json").get("apiKey")
        if isinstance(key, str) and key.strip():
            env[KEY_ENV] = key.strip()
        cmd = [exe, "-p", "--output-format", "json", "--permission-mode", "dont-ask", "--trust", "--skip-onboarding",
               "--no-auto-update", "--no-session", "--safe-mode", "--no-skills", "--max-turns", str(MAX_TURNS)]
        return cmd + (["--model", model] if model else []), env

    def parse(self, event: dict, state: dict) -> list[tuple[str, str] | None]:
        out: list[tuple[str, str] | None] = []
        if event.get("type") == "event" and isinstance(event.get("event"), dict):
            e = event["event"]
            kind = e.get("type")
            if kind == "model_request_end":  # (a turn: what the result line's usage adds up)
                state["turns"] = state.get("turns", 0) + 1
            elif kind == "message_end" and isinstance(e.get("content"), list):
                for block in e["content"]:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and str(block.get("text", "")).strip():
                        out.append(("text", block["text"].strip()))
                    elif block.get("type") == "thinking" and str(block.get("thinking", "")).strip():
                        out.append(("think", block["thinking"].strip()))
                    elif block.get("type") == "tool_use":
                        out.append(("tool", f"{tool_name(block.get('name', ''))}({args_brief(block.get('input'))})"))
            elif kind == "run_error":
                err = e.get("error")
                out.append(("error", str(err.get("message") if isinstance(err, dict) else err or "run failed")[:SAID_CHARS]))
            elif kind == "tool_denied":
                out.append(("info", f"{tool_name(str(e.get('toolName') or e.get('name') or ''))} isn't allowed"))
        elif event.get("type") == "result":  # the end of the session, with what it spent
            usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
            if event.get("subtype") == "error":
                out.append(("error", str(event.get("error") or "session failed")[:SAID_CHARS]))
            elif event.get("subtype") == "max_turns":
                out.append(("info", f"session stopped at its {MAX_TURNS} turns"))
            else:
                out.append(("info", "session finished"))
            out.append(usage_item(input=number(usage, "inputTokens"), output=number(usage, "outputTokens"),
                                  cache_read=number(usage, "cacheReadTokens"),
                                  cache_write=number(usage, "cacheWriteTokens"), turns=state.get("turns", 0)))
        return out

    def fatal(self, error: str) -> bool:
        """An unknown model, or a mode it doesn't take: every try would meet it the same way."""
        return any(s in error.lower() for s in ("unknown model", "allowed choices are", "unknown option"))


COMMANDCODE = CommandCode()
