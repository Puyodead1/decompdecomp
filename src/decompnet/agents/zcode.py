"""ZCode CLI (`zcode`, the npm `zcode-app-cli`, the runtime ZCode Desktop ships), Z.ai's agent CLI, for Z.ai's GLM
models through a Z.ai sign-in (its Coding Plan, or the free Start Plan) or the user's own provider keys. Each session
runs `zcode --output-format stream-json` in a private folder, with the app's MCP server as its only one and every
built-in tool removed.

zcode has no stdin prompt (`-p/--prompt` is a text argument), so the prompt goes in a Markdown file the session
attaches with `--attach`: zcode reads that file into the model's context as text (not a path for a Read tool),
which keeps the prompt off the command line and out of the OS argument limit. The fixed `-p` sentence is ours, so
zcode cannot read the prompt as a slash command either. `--disallowed-tools` removes everything but the app's MCP
tools (the settings' disallowedTools only refuses them once called); the settings file (ZCODE_CLI_SETTINGS_FILE,
which replaces the user's rather than merging) names only the app's MCP server, with plugins, skills, subagents and
hooks off. Its models and each one's reasoning levels come from the catalog its sign-in brings.

It prints one JSON event a line: the model's text, reasoning and tool calls stream as `model.streaming`, and each
model request ends with a `session.updated` event of type `model_request_completed` with its usage, or
`model_request_failed` with what went wrong.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import SAID_CHARS, Agent, args_brief, error_text, number, read_json, tool_name, usage_item

MCP_SERVER = "decomp"  # the app's MCP server, and the prefix of its tools (mcp__decomp__claim_function)
PROMPT_FILE = "prompt.md"  # a text-like extension: zcode inlines it instead of handing the model a path to read
PROMPT_TEXT = "Follow the instructions in the attached file."
SETTINGS_FILE = "setting.json"
# zcode's attachment limits (vendor/zcode.cjs: m3 = 256 KiB, CM = 25,000 estimated tokens). Past either,
# it stops inlining: a path placeholder or a partial view, which our disallowed Read tool cannot recover. Refuse
# the session up front instead of letting a helper work without its instructions.
ATTACHMENT_BYTES = 256 * 1024
ATTACHMENT_TOKENS = 25_000
TOKEN_CHARS = 3  # zcode's estimate (qf): CJK counts 2, every other character 1, divided by 3, rounded up
_CJK = re.compile(r"[一-鿿]")


def estimated_tokens(text: str) -> int:
    """zcode's own estimate (vendor/zcode.cjs, `qf`), in UTF-16 code units as JavaScript counts them."""
    cjk = len(_CJK.findall(text))
    units = len(text.encode("utf-16-le")) // 2
    return (cjk * 2 + (units - cjk) + TOKEN_CHARS - 1) // TOKEN_CHARS


# zcode's own tools are not the app's: a helper works through decompdecomp's MCP tools only. The list is zcode's
# built-ins (its runtime's ZCODE_KNOWN_TOOL_NAMES), the Node REPL and web reader tools bundled with it, and the plan
# mode's (GLM-5.3-Flash, asked to name its tools under zcode 0.17.0, listed those too).
DISALLOWED = " ".join((
    "Read", "Write", "Edit", "ApplyPatch", "Bash", "Glob", "Grep", "WebFetch", "WebSearch", "web_search",
    "TodoRead", "TodoWrite", "GoalRead", "ReadSessionContext", "AskUserQuestion", "SendMessage",
    "RespondToCoordinator", "TaskOutput", "TaskStop", "js", "js_reset", "js_add_node_module_dir",
    "mcp__node_repl__js", "mcp__node_repl__js_reset", "mcp__node_repl__js_add_node_module_dir",
    "mcp__web_reader__webReader", "EnterPlanMode", "ExitPlanMode",
    "Agent", "Task", "Skill", "CreateWorkflow", "AmendWorkflow", "FillWorkflowHole", "submit_result",
))
# the Z.ai plans' models, as agent-watch lists them: offered while zcode has no catalog yet (it fetches one at its
# first start), and a user on another plan types its provider/model
ZCODE_MODELS = (("account:zai-start-plan/GLM-5.3", "GLM-5.3", "Start Plan"),
                ("account:zai-start-plan/GLM-5.3-Flash", "GLM-5.3-Flash", "Start Plan"),
                ("account:zai-individual-coding-plan/GLM-5.3", "GLM-5.3", "Coding Plan"),
                ("account:zai-individual-coding-plan/GLM-5.3-Flash", "GLM-5.3-Flash", "Coding Plan"))
ZCODE_HOME = Path.home() / ".zcode"
# the model catalog its sign-in comes with: which models each provider has, and each model's reasoning levels
CATALOG = "v2/runtime/provider/*/*/*/zcode-builtin.json"
# zcode's permanent model/effort errors: trying again with the same helper can't help.
FATAL = ("Unsupported reasoning effort", "does not support reasoning effort", "Invalid prompt model selection",
         "Cannot apply --effort without a current model")


def _catalog() -> dict:
    """The newest copy of zcode's model catalog, {} when it has none yet (it fetches one at its first start)."""
    found = sorted(ZCODE_HOME.glob(CATALOG), key=lambda p: p.stat().st_mtime)
    return (read_json(found[-1]).get("config") or {}) if found else {}


class Zcode(Agent):
    id = "zcode"
    name = "ZCode CLI"
    command = "zcode"
    vendor = "Z.ai (GLM)"
    install = "npm install -g zcode-app-cli"
    signin = "Run `zcode login` once and sign in through the browser, or add a provider key with `zcode`'s /setup."
    docs = "https://github.com/kingsword09/zcode-cli"
    family = ""  # GLM through a Z.ai sign-in, and any other model through a provider key: the model's name says
    takes_effort = True  # --effort, as the model's name says it: account:zai-start-plan/GLM-5.3-Flash#low
    # Z.ai's GLM models' levels (zcode's --effort also takes auto); each model takes some of them (models() says which,
    # offered_effort keeps a helper to them)
    efforts = ("low", "high", "max")

    def config_model(self) -> str | None:
        """The default model of its provider settings: "account:zai-start-plan/GLM-5.3-Flash"."""
        pick = (read_json(ZCODE_HOME / "v2" / "provider_config.json").get("config") or {}).get(
            "defaultModelSelection") or {}
        return f"{pick['providerId']}/{pick['modelId']}" if pick.get("providerId") and pick.get("modelId") else None

    def models(self, path: str | None, run: bool = True) -> list[dict]:
        """The models of the provider its default model is on (a Z.ai plan's GLM models), from its catalog, each with
        the reasoning levels it takes; the Z.ai plans' models while it has no catalog or default yet."""
        default, catalog = self.config_model(), _catalog()
        if not default or not catalog:
            return [{"id": i, "name": n, "note": note} for i, n, note in ZCODE_MODELS]
        provider = default.rsplit("/", 1)[0]
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
        settings = {
            "permission": {"mode": "yolo", "allowedTools": [], "disallowedTools": DISALLOWED.split()},
            "features": {"mcp": True, "subagent": False, "skill": False, "compact": True, "rewind": False},
            "memory": {"autoConsolidate": False},
            "mcp": {"servers": {MCP_SERVER: {"type": "http", "url": mcp_url,
                                             "headers": {"Authorization": f"Bearer {token}"}}}},
            "plugins": {"enabled": False, "dirs": [], "enabledPlugins": {}, "options": {}, "suppressedBuiltins": []},
            "skills": {"enabled": False, "roots": []},
            "hooks": {"enabled": False},
        }
        (workdir / SETTINGS_FILE).write_text(json.dumps(settings), encoding="utf-8")
        name, _, effort = (model or "").partition("#")
        effort = self.offered_effort(name, effort)
        cmd = [exe, "--output-format", "stream-json", "--mode", "yolo", "--disallowed-tools", DISALLOWED]
        if name:  # (--effort only goes with --model)
            cmd += ["--model", name, *(["--effort", effort] if effort else [])]
        cmd += ["--attach", str(workdir / PROMPT_FILE), "-p", PROMPT_TEXT]
        return cmd, {"ZCODE_CLI_SETTINGS_FILE": str(workdir / SETTINGS_FILE), "ZCODE_DISABLE_UPDATE_CHECK": "1",
                     "NO_COLOR": "1"}

    def prompt_file(self, workdir: Path, prompt: str) -> Path | None:
        """zcode reads the prompt from the file it attaches; `-p` only says to follow it. A prompt past zcode's
        attachment limits is refused here: past them zcode would replace the content with a path placeholder or a
        partial view, and with Read disallowed a helper would work without its instructions."""
        if len(prompt.encode("utf-8")) > ATTACHMENT_BYTES or estimated_tokens(prompt) > ATTACHMENT_TOKENS:
            raise ValueError("this project's prompt is too long for zcode, which only reads attachments up to "
                             "about 25,000 tokens (256 KiB): shorten the project's instructions, or use another "
                             "agent")
        path = workdir / PROMPT_FILE
        path.write_bytes(prompt.encode("utf-8"))  # exact bytes: write_text would translate newlines on Windows
        return path

    def parse(self, event: dict, state: dict) -> list[tuple[str, str] | None]:
        """model.streaming (text and reasoning in deltas, then a tool call), each model request's usage or failure,
        tool failures, turn.failed, and the final result (its usage only where no request said its own)."""
        out: list[tuple[str, str] | None] = []
        if event.get("sessionId"):
            state["zcode_session"] = event["sessionId"]
        t = event.get("type")
        p = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if t == "model.streaming":
            kind = p.get("kind")
            if kind == "reasoning_delta":
                state["zcode_think"] = state.get("zcode_think", "") + str(p.get("delta") or "")
            elif kind == "reasoning_end":
                if text := state.pop("zcode_think", "").strip():
                    out.append(("think", text))
            elif kind == "text_delta":
                state["zcode_text"] = state.get("zcode_text", "") + str(p.get("delta") or "")
            elif kind in ("text_end", "finish"):
                if text := state.pop("zcode_text", "").strip():
                    out.append(("text", text))
            elif kind == "tool_call":
                out.append(("tool", f"{tool_name(str(p.get('toolName') or ''))}({args_brief(p.get('input'))})"))
        elif t == "session.updated" and p.get("type") == "model_request_completed":
            # each request's usage as it ends, so the feed counts while the session runs (its inputTokens counts
            # the cached ones too)
            usage = p.get("usage") if isinstance(p.get("usage"), dict) else {}
            cached, written = number(usage, "cacheReadTokens"), number(usage, "cacheWriteTokens")
            state["zcode_usage"] = True
            out.append(usage_item(input=max(0, number(usage, "inputTokens") - cached - written),
                                  output=number(usage, "outputTokens"), cache_read=cached, cache_write=written,
                                  turns=1))
        elif t == "session.updated" and p.get("type") == "model_request_failed":
            said = str(p.get("providerErrorMessage") or p.get("message") or "")
            # a retry to come is news, not a failure: the last try's is the error
            out.append(("info" if p.get("retryable") else "error", said[:SAID_CHARS]))
        elif t == "tool.updated":
            result = p.get("result") if isinstance(p.get("result"), dict) else {}
            if p.get("kind") == "result" and not result.get("success", True):
                out.append(("error", str(result.get("error") or result.get("content") or "tool failed")[:SAID_CHARS]))
        elif t in ("turn.failed", "error"):
            out.append(("error", error_text(p.get("error") or p.get("message") or event.get("message") or p)
                        [:SAID_CHARS]))
        elif t == "result" and not state.get("zcode_usage"):  # the session's total, when no request said its own
            usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
            cached, written = number(usage, "cacheReadTokens"), number(usage, "cacheWriteTokens")
            out.append(usage_item(input=max(0, number(usage, "inputTokens") - cached - written),
                                  output=number(usage, "outputTokens"), cache_read=cached, cache_write=written,
                                  turns=number(usage, "modelRequestCount")))
        return out

    def clean_stderr(self, line: str) -> str:
        """Its stderr is Node's stack traces of the errors its events say already: only the first line of each, its
        `Error: ` prefix dropped."""
        line = line.strip()
        if line.startswith(("at ", "{", "}", "[", "]")) or (re.match(r"[\w.$]+: ", line) and "Error" not in line):
            return ""
        return line[len("Error: "):] if line.startswith("Error: ") else line

    def fatal(self, error: str) -> bool:
        return error.startswith(FATAL)


ZCODE = Zcode()
