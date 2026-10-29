"""ZCode, Z.ai's agent CLI (`zcode`, the community zcode-app-cli package of the runtime ZCode Desktop ships), for Z.ai's
GLM models through a Z.ai sign-in (its Coding Plan, or the free Start Plan) or the user's own provider keys. Each
session runs `zcode -p <prompt> --output-format stream-json`: it can't read a prompt on stdin (`-p -` is the prompt
"-"), so the prompt is its argument. Its settings come from a file of the helper's own (ZCODE_CLI_SETTINGS_FILE,
which replaces the user's rather than merging), naming only the app's MCP server, with plugins, skills, subagents
and hooks off; --disallowed-tools takes its own tools out of the request (the settings' disallowedTools only refuses
them once called). It prints one JSON event a line: the model's text, reasoning and tool calls stream as
`model.streaming`, and each model request ends with a `session.updated` event of type `model_request_completed`
with its usage, or `model_request_failed` with what went wrong."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import SAID_CHARS, Agent, args_brief, number, read_json, tool_name, usage_item

MCP_SERVER = "decomp"  # (its tools are mcp__decomp__<name>: tool_name knows the prefix)
# its own tools (a helper uses decompdecomp's only): files, shell, web, planning and subagents, and the MCP servers it
# builds in (a JavaScript runner, a web reader). Listed by GLM-5.3-Flash under zcode 0.17.0, asked to name its tools
OWN_TOOLS = ("Agent", "AskUserQuestion", "Bash", "Edit", "EnterPlanMode", "ExitPlanMode", "Glob", "Grep", "Read",
             "ReadSessionContext", "SendMessage", "Skill", "TaskOutput", "TaskStop", "TodoRead", "TodoWrite",
             "WebFetch", "WebSearch", "Write", "mcp__node_repl__js", "mcp__web_reader__webReader")
SETTINGS = "zcode-settings.json"  # in the helper's folder
ZCODE_HOME = Path.home() / ".zcode"
# the model catalog its sign-in comes with: which models each provider has, and each model's reasoning levels
CATALOG = "v2/runtime/provider/*/*/*/zcode-builtin.json"
FAILED = ("model_request_failed",)


def _catalog() -> dict:
    """The newest copy of zcode's model catalog, {} when it has none yet (it fetches one at its first start)."""
    found = sorted(ZCODE_HOME.glob(CATALOG), key=lambda p: p.stat().st_mtime)
    return (read_json(found[-1]).get("config") or {}) if found else {}


class Zcode(Agent):
    id = "zcode"
    name = "ZCode"
    command = "zcode"
    vendor = "Z.ai (GLM)"
    install = "npm install -g zcode-app-cli@latest"
    signin = "Run `zcode login` once in a terminal (or `zcode` and /login), or add a provider key with `zcode`'s /setup."
    docs = "https://github.com/kingsword09/zcode-cli"
    family = ""  # GLM through a Z.ai sign-in, and any other model through a provider key: the model's name says
    takes_effort = True  # --effort, as the model's name says it: account:zai-start-plan/GLM-5.3-Flash#low
    efforts = ("low", "medium", "high", "xhigh", "max")  # each model takes some (models() says which: offered_effort)
    prompt_flag = "-p"

    def config_model(self) -> str | None:
        """The default model of its provider settings: "account:zai-start-plan/GLM-5.3-Flash"."""
        pick = (read_json(ZCODE_HOME / "v2" / "provider_config.json").get("config") or {}).get(
            "defaultModelSelection") or {}
        return f"{pick['providerId']}/{pick['modelId']}" if pick.get("providerId") and pick.get("modelId") else None

    def models(self, path: str | None, run: bool = True) -> list[dict]:
        """The models of the provider its default model is on (a Z.ai plan's GLM models), from its catalog, each with
        the reasoning levels it takes. No command lists them."""
        default = self.config_model()
        if not path or not default:
            return []
        provider = default.rsplit("/", 1)[0]
        catalog = _catalog()
        rule = next((r for r in (catalog.get("providerConfigRules") or {}).get("providerRules") or []
                     if isinstance(r, dict) and r.get("providerId") == provider), {})
        ids = (rule.get("config") or {}).get("builtinModelIds") or [default.rsplit("/", 1)[1]]
        return [{"id": f"{provider}/{m}", "name": m, "note": rule.get("providerName") or provider,
                 "efforts": self.model_efforts(m, catalog)} for m in ids if isinstance(m, str)]

    def model_efforts(self, model: str, catalog: dict) -> list[str]:
        """The reasoning levels its catalog gives a model (the last rule whose pattern matches it says): GLM-5.3-Flash
        takes low, high and max; GLM-5-Turbo only "enabled", which is no effort to pick."""
        levels: list = []
        for r in (catalog.get("modelConfigRules") or {}).get("modelRules") or []:
            spec = (((r.get("config") or {}).get("optionSpecs") or {}).get("reasoningLevel") or {}) \
                if isinstance(r, dict) else {}
            try:
                if spec.get("values") and re.fullmatch(r.get("modelMatch") or "", model, re.I):
                    levels = spec["values"]
            except re.error:
                continue
        return [e for e in self.efforts if e in levels]

    def offered_effort(self, name: str, effort: str) -> str:
        """The effort the model takes nearest the one asked for (the lower of two as near; none for a model without
        any): an unknown level stops zcode before it sends a prompt. As asked when its catalog isn't there yet."""
        catalog = _catalog()
        if not effort or not catalog:
            return effort
        levels = self.model_efforts(name.rsplit("/", 1)[-1], catalog)
        if effort in levels or not levels:
            return effort if levels else ""
        at = self.efforts.index(effort) if effort in self.efforts else 0
        return min(levels, key=lambda e: (abs(self.efforts.index(e) - at), self.efforts.index(e)))

    def session_command(self, exe: str, workdir: Path, mcp_url: str, token: str, model: str) -> tuple[list[str], dict]:
        name, _, effort = (model or "").partition("#")
        effort = self.offered_effort(name, effort)
        settings = {
            "permission": {"mode": "yolo", "allowedTools": [], "disallowedTools": list(OWN_TOOLS)},
            "features": {"compact": True, "rewind": False, "subagent": False, "skill": False, "mcp": True},
            "memory": {"autoConsolidate": False},
            "mcp": {"servers": {MCP_SERVER: {"type": "http", "url": mcp_url,
                                             "headers": {"Authorization": f"Bearer {token}"}}}},
            "plugins": {"enabled": False, "dirs": [], "enabledPlugins": {}, "options": {}, "suppressedBuiltins": []},
            "skills": {"enabled": False, "roots": []},
            "hooks": {"enabled": False},
        }
        (workdir / SETTINGS).write_text(json.dumps(settings, indent=1), encoding="utf-8")
        cmd = [exe, "--output-format", "stream-json", "--mode", "yolo", "--disallowed-tools", ",".join(OWN_TOOLS)]
        if name:  # (--effort only goes with --model)
            cmd += ["--model", name, *(["--effort", effort] if effort else [])]
        return cmd, {"ZCODE_CLI_SETTINGS_FILE": str(workdir / SETTINGS), "ZCODE_DISABLE_UPDATE_CHECK": "1",
                     "NO_COLOR": "1"}

    def parse(self, event: dict, state: dict) -> list[tuple[str, str] | None]:
        t = event.get("type")
        p = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if t == "model.streaming":
            kind = p.get("kind")
            if kind in ("text_delta", "reasoning_delta"):
                state[kind] = state.get(kind, "") + str(p.get("delta") or "")
            elif kind in ("text_end", "reasoning_end"):
                said = state.pop(kind.replace("_end", "_delta"), "").strip()
                return [("text" if kind == "text_end" else "think", said)]
            elif kind == "tool_call":
                return [("tool", f"{tool_name(str(p.get('toolName') or ''))}({args_brief(p.get('input'))})")]
            return []
        if t == "session.updated" and p.get("type") == "model_request_completed":
            usage = p.get("usage") if isinstance(p.get("usage"), dict) else {}
            cached, written = number(usage, "cacheReadTokens"), number(usage, "cacheWriteTokens")
            # (its inputTokens counts the cached ones too)
            return [usage_item(input=max(0, number(usage, "inputTokens") - cached - written),
                               output=number(usage, "outputTokens"), cache_read=cached, cache_write=written, turns=1)]
        if t == "session.updated" and p.get("type") in FAILED:
            said = str(p.get("providerErrorMessage") or p.get("message") or "")
            # a retry to come is news, not a failure: the last try's is the error
            return [("info" if p.get("retryable") else "error", said[:SAID_CHARS])]
        if t in ("error", "turn.failed"):
            return [("error", str(p.get("message") or event.get("message") or "")[:SAID_CHARS])]
        return []

    def clean_stderr(self, line: str) -> str:
        """Its stderr is Node's stack traces of the errors its events say already: only the first line of each."""
        line = line.strip()
        if line.startswith(("at ", "{", "}", "[", "]")) or (re.match(r"[\w.$]+: ", line) and "Error" not in line):
            return ""
        return line


ZCODE = Zcode()
