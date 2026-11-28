"""The SDK's own inline functions, taken whole from the user's copy of a kit (`sdk_inline`).

A game's source called its SDK's inline functions, and some are no C at all: the Dolphin SDK's OSInitFastCast is an
asm block writing four GQRs, inlined into every caller. A GameCube game's main had those four `mtspr`s, agents may
write no assembly (forkengine's _CHEAT: a match has to come from C), and five of them set main aside as "no C makes
it". The SDK's header is what the original included: the app reads it from the user's copy, keeps what its
compiler compiles (`#if` resolved with the kit's `defines`), puts the header's own constants in (its macros are
the header's, not the project's), and hands the definition to the project as it is. Agents name the function; they
never write its body.
"""

from __future__ import annotations

import re
from collections import Counter

_DIRECTIVE = re.compile(r"^\s*#\s*(\w+)\s*(.*)$")
_DEFINE = re.compile(r"(\w+)(?:\s+(.*))?$")  # an object-like macro (a function-like one has `(` right after its name)
_EXPRESSION = re.compile(r"^[\s\d()!<>=&|+\-*/%xXa-fA-FuUlL]*$")  # what #if may still hold once names are numbers


def _value(expr: str, defines: dict[str, str]) -> bool:
    """An #if's expression, with `defines`: names not defined are 0, as the preprocessor has it."""
    expr = re.sub(r"\bdefined\s*\(\s*(\w+)\s*\)|\bdefined\s+(\w+)", lambda m: "1" if (m.group(1) or m.group(2)) in defines
                  else "0", expr.split("//")[0])
    expr = re.sub(r"\b[A-Za-z_]\w*\b", lambda m: defines.get(m.group(0)) or "0", expr)
    expr = re.sub(r"(\d)[uUlL]+\b", r"\1", expr)
    if not _EXPRESSION.match(expr):
        return False
    expr = expr.replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r"!(?!=)", " not ", expr)
    try:
        return bool(eval(expr, {"__builtins__": {}}))  # (numbers and operators only: _EXPRESSION)
    except Exception:
        return False


def preprocess(text: str, defines: dict[str, str]) -> tuple[str, dict[str, str]]:
    """The lines a compiler with `defines` reads (the others blank, so lines keep their numbers), and the object-like
    macros the kept lines define. #include isn't followed: what an inline function needs of another header the
    project has already."""
    defines = dict(defines)
    out, stack = [], []  # stack: (this branch is read, a branch of this #if was read already)
    for line in _without_comments(text).split("\n"):
        m = _DIRECTIVE.match(line)
        live = all(r for r, _ in stack)
        if m:
            word, rest = m.group(1), m.group(2).strip()
            if word in ("if", "ifdef", "ifndef"):
                cond = (rest.split()[0] in defines if word == "ifdef" else
                        rest.split()[0] not in defines if word == "ifndef" else _value(rest, defines)) if rest else False
                stack.append((live and cond, cond))
            elif word == "elif" and stack:
                parent = all(r for r, _ in stack[:-1])
                _, taken = stack[-1]
                cond = not taken and _value(rest, defines)
                stack[-1] = (parent and cond, taken or cond)
            elif word == "else" and stack:
                parent = all(r for r, _ in stack[:-1])
                _, taken = stack[-1]
                stack[-1] = (parent and not taken, True)
            elif word == "endif" and stack:
                stack.pop()
            elif word == "define" and live and (d := _DEFINE.match(rest)) and not rest[len(d.group(1)):].startswith("("):
                defines[d.group(1)] = (d.group(2) or "").strip()
            elif word == "undef" and live:
                defines.pop(rest.split()[0] if rest else "", None)
            out.append("")
            continue
        out.append(line if live else "")
    return "\n".join(out), defines


def _without_comments(text: str) -> str:
    """`text` with its comments blanked (newlines kept)."""
    return re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)


def _expand(body: str, macros: dict[str, str], depth: int = 8) -> str:
    """`body` with the header's object-like macros put in (a macro of macros too, `depth` deep)."""
    for _ in range(depth):
        new = re.sub(r"\b[A-Za-z_]\w*\b", lambda m: macros[m.group(0)] if macros.get(m.group(0)) else m.group(0), body)
        if new == body:
            break
        body = new
    return body


def definition(text: str, name: str, defines: tuple[str, ...]) -> str | None:
    """`name`'s inline definition in a header's `text`, as a compiler with `defines` reads it, its macros put in; None
    when the header defines no inline function by that name."""
    kept, macros = preprocess(text, {d: "1" for d in defines})
    head = re.search(rf"^[ \t]*(?:static\s+)?(?:inline|__inline)\b[^;{{}}()]*\b{re.escape(name)}\s*\(", kept, re.M)
    if head is None:
        return None
    brace = kept.find("{", head.end())
    if brace < 0 or ";" in kept[head.end():brace]:
        return None
    depth, end = 0, -1
    for k in range(brace, len(kept)):
        depth += (kept[k] == "{") - (kept[k] == "}")
        if depth == 0:
            end = k + 1
            break
    if end < 0:
        return None
    lines = [ln.rstrip() for ln in kept[head.start():end].split("\n")]
    return _expand("\n".join(ln for ln in lines if ln.strip()), macros)


def find(kids, name: str) -> tuple[str, str] | None:
    """(the definition, the header it's from, relative to its copy) of the inline function `name` in the headers of
    the user's copies of the kits `kids` (kits.headers), or None: the definition most of them give, from the last
    header (in path order) that gives it. A library of SDKs holds dozens of versions, and the first header in path
    order was an early 2001 revision's (a plain `inline` OSInitFastCast, with an empty fallback), not the one every
    released SDK has."""
    from . import folders, headers

    if not re.fullmatch(r"[A-Za-z_]\w*", name or ""):
        return None
    count: Counter = Counter()
    where: dict[str, tuple[str, str]] = {}
    for kit, path in headers(kids):
        try:
            text = path.read_text(errors="replace", encoding="utf-8")
        except OSError:
            continue
        if name not in text:
            continue
        found = definition(text, name, kit.defines)
        if found is not None:
            key = " ".join(found.split())
            base = next((f for f in folders(kit.id) if path.is_relative_to(f.resolve())), None)
            count[key] += 1
            where[key] = found, (path.relative_to(base.resolve()).as_posix() if base else path.name)
    return where[max(count, key=count.__getitem__)] if count else None
