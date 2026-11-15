"""A Visual C++ game built with /Gr (__fastcall by default) written as its developers wrote it.

A debug-built PC game written in C defined almost every function __fastcall (its first two integer arguments in ecx and
edx), and only its callbacks (qsort's comparisons, GLUT's handlers, varargs, main) __cdecl: the default its build
gave, /Gr. Built without it, its project said __fastcall on 1,299 files' declarations, and agents put an argument in
ecx with a method call on a made-up class (`((Dst*)1)->draw_ui_quad(...)`). With /Gr, __fastcall goes and what had no
convention says __cdecl, as the developers' code would have. Every change is the same code, and scratch.fastcall_
default keeps it for a file only where its matches hold. Its `#pragma optimize("", off)` lines go too: they repeat
the file's /Od.
"""

import re

CONV = ("__cdecl", "__stdcall", "__fastcall", "__thiscall", "WINAPI", "CALLBACK", "APIENTRY", "__pascal")
NOT_NAME = {"if", "while", "for", "switch", "return", "sizeof", "__declspec", "defined", "__asm", "_asm", "asm",
            "operator", "__alignof", "decltype", "typeof", "catch", "case", "do", "else", "new", "delete", "throw"}
PRAGMA = re.compile(r'^[ \t]*#[ \t]*pragma[ \t]+optimize[ \t]*\([ \t]*""[ \t]*,[ \t]*(?:on|off)[ \t]*\)[ \t]*\n?', re.M)
# a function pointer declarator: `(*name)(`, `(*)(`, `(**p)(`, with or without a convention inside
FNPTR = re.compile(r"\(\s*((?:__cdecl|__stdcall|__fastcall|__thiscall|WINAPI|CALLBACK)\s*)?(\*+)(\s*\w*\s*(?:\[[^\]]*\]\s*)*)\)(\s*\()")


def mask(text: str) -> str:
    """The text with comments, strings, chars and preprocessor lines blanked (same length), for scanning."""
    out = list(text)
    i, n = 0, len(text)
    line_start = True
    while i < n:
        c = text[i]
        if line_start and c in " \t":
            i += 1
            continue
        if line_start and c == "#":
            j = i
            while j < n and text[j] != "\n":
                if text[j] == "\\" and j + 1 < n and text[j + 1] == "\n":
                    j += 2
                    continue
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        line_start = c == "\n"
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def convert(text: str, header: bool = False) -> str:
    """`text` for /Gr: each free function's and function pointer's __fastcall gone (the default now), __cdecl where
    one had no convention (what it was without /Gr), and `#pragma optimize("", off/on)` gone (the file's flags say
    /Od). A `header` only gets its __cdecl: files built without /Gr include it too, so its __fastcall stays."""
    if not header:
        text = PRAGMA.sub("", text)
    m = mask(text)
    edits = []  # (start, end, replacement)
    # free functions declared or defined at file scope (and in extern "C" { } blocks): brace depth 0, not in a
    # struct/class/union/enum/namespace body nor a function body
    depth = 0
    stack = []  # for each open brace: whether it's transparent (extern "C" {, namespace {)
    stmt_start = 0
    i = 0
    n = len(m)
    while i < n:
        c = m[i]
        if c == "{":
            head = m[stmt_start:i]
            # extern "C" { (the string's inside is masked) and namespaces: their declarations are file scope
            transparent = bool(re.fullmatch(r'\s*extern\s*"\s*"\s*', head)) or \
                bool(re.search(r"\bnamespace\b[^;{}]*$", head))
            if all(stack):
                _maybe_function(text, m, stmt_start, i, edits, defining=True)
            stack.append(transparent)
            depth += 1
            stmt_start = i + 1
        elif c == "}":
            if stack:
                stack.pop()
            depth -= 1
            stmt_start = i + 1
        elif c == ";":
            if all(stack):
                _maybe_function(text, m, stmt_start, i, edits)
            stmt_start = i + 1
        i += 1
    if header:
        edits = [e for e in edits if e[2]]  # (insertions only)
    # function pointers anywhere: (*p)( with no convention gets __cdecl; (__fastcall *p)( loses it
    for fm in FNPTR.finditer(m):
        conv = fm.group(1)
        if conv is None:
            edits.append((fm.start(2), fm.start(2), "__cdecl "))
        elif conv.strip() == "__fastcall":
            edits.append((fm.start(1), fm.end(1), ""))
    return _apply(text, edits)


def conventions(text: str) -> dict[str, int]:
    """How many free functions `text` defines with each convention ("" for none): a game whose own files define
    most of theirs __fastcall was built with /Gr."""
    m = mask(text)
    found: dict[str, int] = {}
    depth, stmt_start = 0, 0
    for i, c in enumerate(m):
        if c == "{":
            if depth == 0:
                conv = _maybe_function(text, m, stmt_start, i, [], defining=True)
                if conv is not None:
                    found[conv] = found.get(conv, 0) + 1
            depth += 1
            stmt_start = i + 1
        elif c == "}":
            depth = max(depth - 1, 0)
            stmt_start = i + 1
        elif c == ";" and depth == 0:
            stmt_start = i + 1
    return found


def _maybe_function(text, m, start, end, edits, defining=False):
    """The declaration m[start:end] (a statement at file scope, or a function's head before its `{`): a free
    function's declarator gets its convention rewritten."""
    stmt = m[start:end]
    if not stmt.strip() or re.match(r"\s*(?:typedef\b|struct\b[^(]*$|class\b|union\b|enum\b|template\b|using\b|"
                                    r"namespace\b)", stmt):
        if not re.match(r"\s*typedef\b", stmt):
            return
    # the declarator: the first `name (` whose name isn't a keyword, outside parentheses
    level = 0
    for mm in re.finditer(r"[()]|(~?[A-Za-z_][\w:]*)\s*(?=\()", stmt):
        tok = mm.group(0)
        if tok == "(":
            level += 1
            continue
        if tok == ")":
            level -= 1
            continue
        if level != 0:
            continue
        name = mm.group(1)
        if re.match(r"\(\s*(?:(?:__cdecl|__stdcall|__fastcall|__thiscall|WINAPI|CALLBACK)\s*)?\*", stmt[mm.end():]):
            return  # `int (*p)(int)`: a pointer to a function, FNPTR's
        if name in NOT_NAME or name.split("::")[-1] in NOT_NAME:
            continue
        if "::" in name:
            return  # a method (thiscall, /Gr or not)
        if name in CONV:
            continue
        before = stmt[:mm.start()]
        if "=" in before:
            return  # a variable's initializer
        if not re.search(r"[\w*&]\s*$", before):
            return  # no type before it: a call or a macro
        words = re.findall(r"\w+", before)
        if not words or words[-1] in ("return",):
            return
        if re.search(r"\btypedef\b", before):
            return  # a typedef of a function type: rare, left
        a = start + mm.start()
        convs = [w for w in words if w in CONV]
        if "__fastcall" in convs:
            for cm in re.finditer(r"\b__fastcall\b\s*", m[start:a]):
                edits.append((start + cm.start(), start + cm.end(), ""))
        elif not convs:
            edits.append((a, a, "__cdecl "))
        return convs[0] if convs else ""
    return None


def _apply(text, edits):
    out, pos = [], 0
    for s, e, r in sorted(set(edits)):
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append(r)
        pos = e
    out.append(text[pos:])
    return "".join(out)
