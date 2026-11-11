"""A source file of the program made again from its matched functions, as one C file.

Each function was matched alone: its C is the function and whatever it declares for itself above it (a global's
extern, a callee's prototype, a struct, a file's static). Put back together in the original file's order (the
debug information's source file, the functions in the order its code has them), the file compiles to one object,
as the game's did. What the functions wrote for themselves is written once:

- a declaration every function writes the same way is written once, above the functions (the externs and
  prototypes in the file's own header, `<file>.h`, where they need nothing the file defines itself);
- a global or a callee two functions guessed differently (`extern void *hit_audits;` beside
  `extern THit *hit_audits;`) is declared inside each function that guessed it: block scope keeps both, as each
  function was compiled, and GCC accepts that;
- a function of the file is declared as its definition has it (its callers wrote `void auditInit();` where it is
  `int auditInit(void)`), `static` where it is; their own copies go;
- a static written in several functions is one static of the file;
- a macro is defined once at the top, or around each function defining it where two define it differently or
  another function uses that name.

What can't be made one file (two definitions of one struct, a static two functions type differently) is said, and
the file's functions stay one file each. Whether the file matches is the judge's to say (the caller links it)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import cfields
from .tidy import _ATTRIBUTE, _KEYWORDS, _KR_HEAD, _identifiers, _is_body, _item, _key, _split_top

# a K&R definition's head (`int f(a, b) int a; ...`), not a prototype with an attribute after it, nor a declaration
# whose type is `__typeof__(x)` (`extern __typeof__(x) y __asm__("x");`, what an export writes for a linked name)
_KR = re.compile(_KR_HEAD.pattern.replace(r"\b\w+\s*\(", r"\b(?!(?:__)?typeof(?:__)?\b)\w+\s*\(", 1)[:-len("[A-Za-z_]")]
                 + r"(?!__attribute__|__asm__|asm\b)[A-Za-z_]")


@dataclass
class Chunk:
    """One thing at file scope: a preprocessor line, a declaration, a function's definition. `text` has the
    comments and blank lines before it, and the line break after it."""
    text: str
    kind: str  # include, define, pp, func, type, extern, static, data, other
    names: tuple[str, ...] = ()
    key: str = ""
    static: bool = False  # (a function's definition: `static int helper(...)`)
    body: int = -1  # (a function's definition: where its body's `{` is in `text`)


@dataclass
class Merged:
    c: str | None  # the file's C, or None (and `problem`) where its functions can't be one file
    header: str = ""  # the file's own header's declarations (externs and prototypes): may be empty
    problem: str = ""
    scoped: list[str] = field(default_factory=list)  # names declared inside the functions that guessed them


def chunks(source: str) -> list[Chunk]:
    """`source` cut at file scope, every character in one chunk."""
    found: list[Chunk] = []
    text = _mask(source)
    i, n = 0, len(text)
    while i < n:
        j = i
        while j < n and text[j] in " \t\r\n":
            j += 1
        if j >= n:
            if found:
                found[-1].text += source[i:]
            break
        if text[j] == "#":  # a preprocessor line (and its continuations)
            k = j
            while k < n and text[k] != "\n":
                k += 2 if text[k] == "\\" else 1
            end = min(k + 1, n)
            found.append(_preprocessor(source[i:end], text[j:k]))
            i = end
            continue
        depth, k, body = 0, j, -1
        while k < n:
            c = text[k]
            if c in "\"'":  # a literal
                q, k = c, k + 1
                while k < n and text[k] != q:
                    k += 2 if text[k] == "\\" else 1
            elif c in "({[":
                if c == "{" and depth == 0 and body < 0:
                    body = k
                depth += 1
            elif c in ")}]":
                depth -= 1
                if depth == 0 and c == "}" and _is_body(text, j, k):
                    break
            elif c == ";" and depth == 0 and not _KR.match(text, j):  # (a K&R definition's parameters)
                break
            k += 1
        end = min(k + 1, n)
        while end < n and text[end] in " \t\r":
            end += 1
        if end < n and text[end] == "\n":
            end += 1
        found.append(_classify(source[i:end], text[j:k + 1], body - i if body >= 0 else -1, text[i:j]))
        i = end
    return found


_NOT_A_VALUE = re.compile(r"(?:return|goto|break|continue|if|else|for|while|do|switch|case|default|"
                         r"__asm__|asm)\b|\w+\s*:(?!:)")


def returned(source: str, name: str) -> str | None:
    """`source` with function `name`'s last statement returned, where it is an expression and the function's type
    isn't void: what GCC 2.95 left in %eax returned it by accident (`load_grx_now_if_not_loaded(fix, 0);` at the end
    of a function that returns the texture), which a newer GCC doesn't keep (`-Wreturn-type`). None where it isn't
    that; the caller judges it still compiles to the same code."""
    pieces = chunks(source)
    at = 0
    for chunk in pieces:
        if chunk.kind == "func" and name in chunk.names and chunk.body >= 0:
            break
        at += len(chunk.text)
    else:
        return None
    text = _mask(chunk.text)
    head = text[:chunk.body]
    if re.search(rf"\bvoid\s+{re.escape(name)}\s*\(", head) or re.search(r"\b(?:__)?inline(?:__)?\b", head):
        return None
    depth, start, last, k = 0, -1, None, chunk.body
    while k < len(text):
        c = text[k]
        if c in "\"'":
            q, k = c, k + 1
            while k < len(text) and text[k] != q:
                k += 2 if text[k] == "\\" else 1
        elif c in "({[":
            depth += 1
            if depth == 1:
                start = k + 1
        elif c in ")}]":
            depth -= 1
            if depth == 0:
                break
            if depth == 1 and c == "}":
                start, last = k + 1, None
        elif c == ";" and depth == 1:
            last, start = (start, k), k + 1
        k += 1
    if last is None or depth != 0 or text[last[1] + 1:k].strip():
        return None
    begin = last[0] + len(text[last[0]:last[1]]) - len(text[last[0]:last[1]].lstrip())
    statement = text[begin:last[1]]
    if not statement.strip() or _NOT_A_VALUE.match(statement) or re.match(r"[A-Za-z_][\w\s*]*\s+\**[A-Za-z_]\w*\s*(?:=|\[|$)",
                                                                       statement):
        return None  # (a declaration, a jump, a label, a block)
    where = at + begin
    return source[:where] + "return " + source[where:]


def _mask(source: str) -> str:
    """`source` with its comments blanked, every offset (and line) where it was."""
    return cfields._COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)


def _preprocessor(original: str, line: str) -> Chunk:
    flat = " ".join(line.replace("\\\n", " ").split())
    m = re.match(r"#\s*include\b\s*(.*)", flat)
    if m:
        return Chunk(original, "include", (m.group(1),), flat)
    m = re.match(r"#\s*define\s+(\w+)", flat)
    if m:
        return Chunk(original, "define", (m.group(1),), flat)
    return Chunk(original, "pp", (), flat)


def _classify(original: str, decl: str, body: int, lead: str) -> Chunk:
    flat = " ".join(_ATTRIBUTE.sub(" ", decl).split())
    if body >= 0 and decl.rstrip().endswith("}") and _is_body(decl, 0, len(decl.rstrip()) - 1):
        head = flat[:flat.index("{")] if "{" in flat else flat
        name = next((m.group(1) for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", head)
                     if m.group(1) not in _KEYWORDS and not m.group(1).startswith("__")), "")
        static = bool(re.search(r"\bstatic\b", head.split("(")[0]))
        return Chunk(original, "func", (name,) if name else (), " ".join(cfields._COMMENT.sub(" ", decl).split()),
                     static, body)
    key = _key(decl)
    if re.fullmatch(r"(?:struct|union|enum)\s+\w+\s*;", flat):  # (a forward declaration)
        return Chunk(original, "type", (), key)
    if re.match(r"(?:__asm__|asm)\b", flat):
        return Chunk(original, "other", (), key)
    item = _item(decl, decl)
    if item is not None and item[1]:
        return Chunk(original, item[0], item[1], key)
    names = _declared(flat)
    if flat.startswith("extern ") and names:  # (`extern struct { ... } Gp[];`)
        return Chunk(original, "extern", names, key)
    if flat.startswith("typedef ") or re.match(r"(?:struct|union|enum)\s+\w*\s*\{", flat):
        return Chunk(original, "type", names, key)
    if re.match(r"(?:\w+\s+)*?static\b", flat):
        if "(" in flat and "=" not in flat and not re.search(r"\(\s*\*", flat):  # (a static function's prototype)
            return Chunk(original, "extern", names, key, static=True)
        return Chunk(original, "static", names, key, static=True)
    return Chunk(original, "data" if names else "other", names, key)


def _declared(flat: str) -> tuple[str, ...]:
    """The names a declaration declares: `static int a = 1, *b[4];` -> a, b."""
    body = re.sub(r"\{.*\}", "{}", flat).rstrip(";")
    names = []
    for part in _split_top(body):
        part = re.split(r"=(?![=])", part, 1)[0]
        m = re.search(r"\(\s*\*+\s*(\w+)\s*(?:\[[^\]]*\]\s*)*\)\s*[(\[]", part) or \
            re.search(r"(\w+)\s*\(", part) or \
            re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*$", part.strip())
        if m and m.group(1) not in _KEYWORDS:
            names.append(m.group(1))
    return tuple(names)


_INLINE = re.compile(r"\b(?:inline|__inline__|__inline)\b")


def _without_copies(cs: list[Chunk], own: set[str]) -> list[Chunk]:
    """A function's chunks without the definitions of functions of other files it carried (a function's C that
    defines three more, compiled alone: they'd be this file's too), each its prototype instead. Inline helpers stay."""
    out = []
    for c in cs:
        if c.kind == "func" and c.names and c.names[0] not in own and not _INLINE.search(_mask(c.text)[:c.body]):
            proto = prototype(c)
            if proto is not None:
                proto = re.sub(r"^static\s+", "", proto)
                out.append(Chunk(proto + "\n", "extern", c.names, _key(proto)))
            continue
        out.append(c)
    return out


_NOT_A_TYPE = {"return", "if", "else", "for", "while", "do", "switch", "case", "goto", "break", "continue", "default",
               "sizeof", "typedef"}
_DECLARATION = re.compile(r"(?:(?:register|static|const|volatile|unsigned|signed|struct|union|enum|extern)\s+)*"
                          r"([A-Za-z_]\w*)(?:\s+|\s*\*[\s*]*)(\(\s*\*\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*)\s*(\[[^\]]*\]\s*)*")


def declared_locals(source: str, name: str) -> set[str] | None:
    """The variables `name`'s definition in `source` declares in its body (each block's too), or None where it
    doesn't define it. `int i, *p = q;` declares i and p; `int (*read)();` read; a prototype nothing."""
    func = next((c for c in chunks(source) if c.kind == "func" and c.names == (name,)), None)
    if func is None or func.body < 0:
        return None
    body = _mask(func.text[func.body + 1:])
    body = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', body)
    out: set[str] = set()
    for piece in body.split(";"):
        statement = re.split(r"[{}:]", piece)[-1].strip()  # (after a block's brace, or a label's colon)
        m = _DECLARATION.match(statement)
        if not m or m.group(1) in _NOT_A_TYPE or m.group(2) in _NOT_A_TYPE:
            continue
        rest = statement[m.end():].lstrip()
        if rest and rest[0] not in "=,":
            continue  # (an expression, or a prototype: `int f(void)`)
        first = re.search(r"\w+", m.group(2).replace("*", " ")).group(0)
        names = [first]
        # the other declarators, after each comma not inside an initializer's parentheses or braces
        depth, part = 0, ""
        for ch in rest + ",":
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            if ch == "," and depth == 0:
                if (d := re.match(r"\s*\**\s*(?:\(\s*\*\s*(\w+)\s*\)|(\w+))", part)) and part.strip()[:1] != "=":
                    names.append(d.group(1) or d.group(2))
                part = ""
            else:
                part += ch
        out.update(n for n in names if n and n not in _NOT_A_TYPE)
    return out


def debug_local_names(locals_: list[str]) -> set[str]:
    """The names of a function's locals as its brief lists them from the debug information (`int width (the stack,
    frame offset -0x44, declared on line 251)`, `int (*myfread)() (...)`), not an inlined system header's own
    (`__result`)."""
    out = set()
    for entry in locals_:
        if m := re.search(r"\(\*\s*(\w+)\)", entry.split(" (the ")[0].split(" (register")[0]):
            name = m.group(1)
        else:
            decl = re.sub(r"\[.*?\]", "", re.split(r" \((?:the |register |st\(|e[a-ds][xip]|static|[a-z]+,)", entry)[0])
            words = re.findall(r"[A-Za-z_]\w*", decl)
            name = words[-1] if words else ""
        if name and not name.startswith("__"):
            out.add(name)
    return out


def only_own(source: str, name: str, others: set[str]) -> str:
    """A function's matched C as its own file: without the definitions it carried of `others` (the program's
    functions with files of their own), each its prototype instead (_without_copies). The judge compares only the
    function judged, so an agent's C for one function of a Linux program's file defined three more of it as well,
    and its export defined them twice, one of them never judged ("undefined reference to `sin'")."""
    cs = chunks(source)
    if not any(c.kind == "func" and c.names and c.names[0] in others and c.names[0] != name for c in cs):
        return source
    return "".join(c.text for c in _without_copies(cs, {name} | {c.names[0] for c in cs if c.kind == "func"
                                                                  and c.names and c.names[0] not in others}))


def _top_level_asm(source: str) -> str:
    """A function's GNU assembly as top-level asm in C, aligned as GCC aligns a function, and back in whatever
    section GCC was in after it (`.previous`)."""
    lines = [line for line in source.splitlines() if line.strip() and line.strip() != ".text"]
    body = "".join(f'    "{line.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34)).replace(chr(9), chr(92) + "t")}\\n"\n'
                   for line in [".text", ".align 4"] + lines + [".previous"])
    name = next((line[:-1] for line in lines if line.endswith(":") and not line.startswith(".")), "it")
    return f"/* {name} isn't C yet: its code as the program has it */\n__asm__(\n{body});\n"


def _loose(key: str) -> str:
    """A declaration as far as C tells two apart: `int (*asked)(void);` is `int (*asked)();`, `char s[15];` is
    `char s[];`."""
    return re.sub(r"\[\s*\w*\s*\]", "[]", key.replace("(void)", "()"))


def _one_per_name(cs: list[Chunk]) -> list[Chunk]:
    """Each declaration of several names (`extern float spos_01, spos_02[4];`) as one per name, so that each is
    written once, or another function's guess at one of them aliased, on its own."""
    out = []
    for c in cs:
        if c.kind != "extern" or len(c.names) < 2 or "{" in c.text:
            out.append(c)
            continue
        flat = " ".join(cfields._COMMENT.sub(" ", c.text).split()).rstrip().rstrip(";")
        parts = _split_top(flat)
        first = re.search(rf"\b{re.escape(c.names[0])}\b", parts[0])
        if first is None or len(parts) != len(c.names):
            out.append(c)
            continue
        base = parts[0][:first.start()].rstrip(" *(")
        declarators = [parts[0][len(base):].strip()] + [part.strip() for part in parts[1:]]
        for name, declarator in zip(c.names, declarators):
            text = f"{base} {declarator};"
            out.append(Chunk(text + "\n", "extern", (name,), _key(text)))
    return out


def _renames(parsed: list[tuple[str, list[Chunk]]]) -> dict[str, dict[str, str]]:
    """{function: {name: its own name for it}} for the types and inline helpers its C defines otherwise than most."""
    ways: dict[str, dict[str, list[str]]] = {}
    own = {name for name, _ in parsed}
    for name, cs in parsed:
        for c in cs:
            if c.kind == "type" or (c.kind == "func" and c.names and c.names[0] not in own):
                for n in c.names:
                    ways.setdefault(n, {}).setdefault(c.key, []).append(name)
    out: dict[str, dict[str, str]] = {}
    for n, keys in ways.items():
        if len(keys) < 2:
            continue
        common = max(keys, key=lambda k: len(keys[k]))  # (the first of the most common: dicts keep their order)
        for key, users in keys.items():
            if key != common:
                for user in users:
                    if not n.split()[-1].endswith(f"_{user}"):
                        out.setdefault(user, {})[n] = f"{n.split()[-1]}_{user}"
    return out


_TOKENS = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*|[A-Za-z_]\w*', re.S)


def _rename(text: str, old: str, new: str, calls_only: bool = False) -> str:
    """`text` with the identifier `old` written `new`: not in a string, a character or a comment, not a field
    (`p->old`, `s.old`) or a tag (`struct old`); `calls_only`: only where it's called."""
    def one(m: re.Match) -> str:
        if m.group(0) != old:
            return m.group(0)
        before = text[max(0, m.start() - 16):m.start()].rstrip()
        if before.endswith((".", "->")) or re.search(r"\b(?:struct|union|enum)$", before):
            return old
        if calls_only and not re.match(r"\s*\(", text[m.end():]):
            return old
        return new
    return _TOKENS.sub(one, text)


def _alias(view: str, name: str, alias: str, note: str) -> str:
    """A declaration (`extern THit *hit_audits;`) as the same symbol under another name, for one function:
    `extern THit *hit_audits__f __asm__("hit_audits");`. GCC 2.95 and a newer GCC alike make the same code for it,
    and neither sees two types for one name."""
    decl = re.sub(r"^\s*extern\s+", "", " ".join(cfields._COMMENT.sub(" ", view).split())).rstrip().rstrip(";")
    decl = _rename(decl, name, alias)
    head, attr, rest = decl.partition("__attribute__")
    return f'extern {head.rstrip()} __asm__("{name}"){" " + attr + rest if attr else ""};  /* {note} */'


def _renamed(source: str, names: dict[str, str]) -> str:
    """`source` with each of `names` its own: a tag (`struct X`) where it's written as one, a typedef or a helper
    where it isn't a tag or a field (`p->X`)."""
    for old, new in names.items():
        if " " in old:
            tag, word = old.split()
            source = re.sub(rf"\b{tag}\s+{re.escape(word)}\b", f"{tag} {new}", source)
        else:
            source = _rename(source, old, new)
    return source


def prototype(chunk: Chunk) -> str | None:
    """A function's declaration as its definition has it (`int auditInit(void);`, a K&R one's `int f();`); None
    for an inline one (each file that calls it defines it)."""
    text = _mask(chunk.text)
    lead = len(text) - len(text.lstrip())
    head = text[lead:chunk.body].strip()
    if re.search(r"\b(?:inline|__inline__|__inline)\b", head) or not chunk.names:
        return None
    if _KR.match(head):
        m = re.match(rf"(.*?\b{re.escape(chunk.names[0])}\s*\()", head, re.S)
        return " ".join(m.group(1).split()) + ");" if m else None
    return " ".join(head.split()) + ";"


def merge(functions: list[tuple[str, str]], include: str, own_header: str | None = None, context=None,
          statics_at: dict[str, dict[str, int]] | None = None, as_called: bool = False, shared: str = "",
          own_data: dict[str, str] | None = None, forward: str = "", placed: list[tuple[int, str]] = (),
          func_lines: dict[str, int] | None = None, asm_pieces: dict[str, str] | None = None) -> Merged:
    """The source file of `functions` ((name, its matched C), in the file's order) as one C file starting with
    `#include "<include>"`, then its own header `own_header` where it declares anything (else those declarations
    are the C file's). `context` (re.Pattern): an include of the shared header the agents wrote themselves
    (context.h), dropped: the file includes it first.

    `statics_at` ({function: {static: its address in the game}}, as each function was judged): a static two functions
    define with one name at two addresses is two statics (`static int first;` of two functions, each its own in
    the game: `first.12`, `first.13`), each inside its function. `as_called`: each function calls the file's
    functions as it declared them (`void write_console();` called with two arguments, `float` arguments passed as
    `double` by a function that didn't declare it at all) where that isn't how they're defined, through a
    declaration of its own under another name for the same symbol: what the file needs when it doesn't match with
    every call made as defined. `shared`: the shared header (what it declares, a function didn't leave undeclared).

    The file's data as C (consoles/linux/export_data.py): `own_data` ({name: its declaration as compared}) are the
    variables it defines itself, so its functions' definitions of them go and a function that declared one another
    way has its own declaration of it (as for a guess); `forward` declares them (and what their values name) before
    the functions; `placed` ((line, definition)) goes before the first function whose `func_lines` entry is after it, as
    the file had them. `asm_pieces` ({name: GNU assembly}): a function that isn't C yet, at its place in the file
    as top-level assembly (GCC writes it out where it is, between the functions)."""
    from .compiler import NO_CONTEXT

    own_data = own_data or {}
    asm_pieces = asm_pieces or {}
    # C judged without the shared header (`#pragma decompdecomp no_context`, the real headers it includes itself)
    # can't share a file that starts with it: <math.h> after a Linux program's common.h is "redefinition of `_IEEE_'"
    alone = [name for name, source in functions if name not in asm_pieces and NO_CONTEXT.search(source)]
    if alone:
        return Merged(None, problem=f"{alone[0]}'s C was matched without the shared header (no_context)")
    order = [name for name, _ in functions]  # (with the functions in assembly, at their places)
    functions = [(name, source) for name, source in functions if name not in asm_pieces]
    own = [name for name, _ in functions]
    sources = {name: context.sub("", source) if context is not None else source for name, source in functions}
    parsed = [(name, _one_per_name(_without_copies(chunks(sources[name]), set(own)))) for name in own]
    # a struct or an inline helper two functions define differently: the most common way keeps its name, and each
    # function writing it another way has its own (`FontDef_drawText`), as it was compiled
    # (again while renaming one makes another differ: a typedef of the renamed struct)
    renames: dict[str, dict[str, str]] = {}
    for _ in range(8):
        more = _renames(parsed)
        if not more:
            break
        for name, names in more.items():
            renames.setdefault(name, {}).update(names)
        parsed = [(name, _one_per_name(_without_copies(chunks(_renamed(sources[name], renames[name])), set(own))))
                  if name in renames else (name, cs) for name, cs in parsed]
    defs: dict[str, Chunk] = {}
    for name, cs in parsed:
        mine = [c for c in cs if c.kind == "func" and c.names == (name,)]
        if len(mine) != 1:
            return Merged(None, problem=f"{name}'s C doesn't define {name} once")
        defs[name] = mine[0]

    # what each name is declared as, by kind
    ways: dict[str, set[str]] = {}
    types: dict[str, set[str]] = {}
    statics: dict[str, set[str]] = {}
    macros: dict[str, set[str]] = {}
    helpers: dict[str, set[str]] = {}
    for name, cs in parsed:
        for c in cs:
            if c.kind == "extern":
                for n in c.names:
                    ways.setdefault(n, set()).add(c.key)
            elif c.kind == "type":
                for n in c.names:
                    types.setdefault(n, set()).add(c.key)
            elif c.kind in ("static", "data"):
                for n in c.names:
                    if n not in own_data:
                        statics.setdefault(n, set()).add(c.key)
            elif c.kind == "define":
                macros.setdefault(c.names[0], set()).add(c.key)
            elif c.kind == "func" and c.names and c.names[0] not in defs:
                helpers.setdefault(c.names[0], set()).add(c.key)
    # a static that is two in the game (two functions' at two addresses): each function's own, inside it
    inner = set()
    for n in statics:
        places = {(statics_at or {}).get(name, {}).get(n) for name, cs in parsed
                  if any(c.kind == "static" and n in c.names for c in cs)} - {None}
        if len(places) > 1:
            inner.add(n)
    statics = {n: keys for n, keys in statics.items() if n not in inner}
    for kind, table in (("defines", types), ("defines", statics), ("defines the helper", helpers)):  # (left)
        for n, keys in table.items():
            if len(keys) > 1:
                return Merged(None, problem=f"two of its functions' C {kind} {n} differently")
    for n in statics:
        if n in defs:
            return Merged(None, problem=f"{n} is both a function of the file and data one of them defines")
    defined_here = set(defs) | set(statics) | set(helpers) | inner
    # a name declared outside a function is seen by all of them: only where each function using it declares it the
    # same way (or the shared header does). One that calls it undeclared (write_console with two arguments, where
    # the others declare one) keeps doing so, and the others' declarations are theirs
    flat_shared = cfields._COMMENT.sub(" ", shared)
    in_shared = {n for n in ways if re.search(rf"(?<![\w.>]){re.escape(n)}\b", flat_shared)}
    uses = {name: _identifiers("".join(c.text for c in cs if c.kind == "func" and c.names == (name,))) for name, cs in parsed}
    declares = {name: {n for c in cs if c.kind == "extern" for n in c.names} for name, cs in parsed}
    undeclared = {n for n in ways if n not in in_shared and n not in defined_here and n not in own_data
                  and any(n in uses[name] and n not in declares[name] for name in own)}
    scoped = sorted(n for n, keys in ways.items() if ((len(keys) > 1 or n in undeclared) and n not in defined_here
                                                      and n not in own_data)
                    or (n in own_data and {_loose(k) for k in keys} - {_loose(own_data[n])}))
    # each of those as the file declares it: the shared header's way, else the way most of its functions wrote it;
    # a function that wrote another (or called it undeclared) has its own declaration of the same symbol under its
    # own name (_alias): GCC 2.95 took two types for one name in two functions, a newer GCC refuses them
    majority: dict[str, str | None] = {}
    shared_keys: dict[str, set[str]] = {}
    for n in scoped:
        if any(c.kind == "extern" and n in c.names and len(c.names) > 1 for _, cs in parsed for c in cs):
            return Merged(None, problem=f"its functions declare {n} differently, one with other names in one line")
        if n in own_data:
            majority[n] = own_data[n]  # (as the file defines it; declared before its functions: `forward`)
        elif n in in_shared:
            majority[n] = None
            shared_keys[n] = {_key(line) for line in flat_shared.splitlines() if line.rstrip().endswith(";")
                              and re.search(rf"(?<![\w.>]){re.escape(n)}\b", line)}
        else:
            counts: dict[str, int] = {}
            for _, cs in parsed:
                for c in cs:
                    if c.kind == "extern" and c.names == (n,):
                        counts[c.key] = counts.get(c.key, 0) + 1
            majority[n] = max(counts, key=lambda k: counts[k]) if counts else None

    # a macro is the file's (at the top) unless two functions define it differently, or one that doesn't define it
    # uses the name otherwise (`#define FreeVec ((xyz *) 0x8f785a0)` beside `&FreeVec`): then it's defined before
    # each function that defines it, and undefined after (where the shared header defines it, it stays the file's:
    # undefined, the header's would be gone)
    definers = {m: {name for name, cs in parsed for c in cs if c.kind == "define" and c.names[0] == m} for m in macros}
    local_macros = {m for m, keys in macros.items()
                    if len(keys) > 1 or (not re.search(rf"#\s*define\s+{re.escape(m)}\b", shared)
                                         and any(m in uses[name] for name in own if name not in definers[m]))}

    # each function's own declarations of what it guessed otherwise: {function: {name: (its declaration, note)}}
    aliased: dict[str, dict[str, tuple[str, str]]] = {}
    for name, cs in parsed:
        for n in scoped:
            said = next((c for c in cs if c.kind == "extern" and c.names == (n,)), None)
            if said is not None:
                if said.key == majority[n] or said.key in shared_keys.get(n, ()) or \
                        (n in own_data and _loose(said.key) == _loose(own_data[n])):
                    continue
                aliased.setdefault(name, {})[n] = (said.text, f"{n} as this function declares it")
            elif n in uses[name] and n not in in_shared:
                aliased.setdefault(name, {})[n] = (f"int {n}();", f"{n} as this function calls it, undeclared")
        # (and a macro of its own that names one, `#define GRV D_080F2EA0`: its own too, renamed alike)
        local_macros |= {c.names[0] for c in cs if c.kind == "define"
                         and _identifiers(c.text.split(c.names[0], 1)[-1]) & set(aliased.get(name, {}))}

    local_names = set(macros) | {n.split()[-1] for n in types}  # (what the file defines itself: a header can't use)
    includes, top_macros, top_types, own_decls, header_decls, data, others = [], [], [], [], [], [], []
    seen: set[str] = set()

    def once(c: Chunk, into: list) -> None:
        if c.key not in seen:
            seen.add(c.key)
            into.append(c.text.strip("\n") + "\n")

    for name, cs in parsed:
        for c in cs:
            if c.kind == "include":
                once(c, includes)
            elif c.kind == "define" and c.names[0] not in local_macros:
                once(c, top_macros)
            elif c.kind == "type":
                once(c, top_types)
            elif c.kind == "extern":
                if set(c.names) & set(defs) and "__attribute__" in c.text:
                    once(c, own_decls)  # (`void setup(void) __attribute__((constructor));`: what it says stays)
                    continue
                if set(c.names) & set(own_data):
                    continue  # (the file's own data: declared before its functions, `forward`)
                if len(c.names) == 1 and c.names[0] in majority and majority[c.names[0]] == c.key:
                    once(c, own_decls if _identifiers(c.text) & local_names else header_decls)
                    continue  # (the file's way of a name its functions guessed differently)
                if set(c.names) & (defined_here | set(scoped)):
                    continue  # (the file's own functions and statics: as defined; another guess: its function's)
                once(c, own_decls if _identifiers(c.text) & local_names else header_decls)
            elif c.kind in ("static", "data"):
                if not set(c.names) & (inner | set(own_data)):
                    once(c, data)
            elif c.kind == "func" and c.names and c.names[0] not in defs:
                once(c, data)  # (an inline helper its functions define)
            elif c.kind in ("other", "pp"):
                once(c, others)

    prototypes_h, prototypes_c = [], []
    for name in own:
        proto = prototype(defs[name])
        if proto is None:
            continue
        if defs[name].static or _identifiers(proto) & local_names:
            prototypes_c.append(proto + "\n")
        else:
            prototypes_h.append(proto + "\n")

    defined_as = {name: _key(proto) for name in own if (proto := prototype(defs[name])) is not None}
    body = []
    pending = sorted(placed, key=lambda p: p[0])
    asm_left = [n for n in order if n in asm_pieces]

    def asm_before(name: str | None) -> None:
        while asm_left and (name is None or order.index(asm_left[0]) < order.index(name)):
            body.append("\n" + _top_level_asm(asm_pieces[asm_left.pop(0)]))

    for name, cs in parsed:
        asm_before(name)
        here = (func_lines or {}).get(name)  # (the file's data defined before this function: before its macros too)
        while here is not None and pending and pending[0][0] < here:
            body.append("\n" + pending.pop(0)[1].rstrip("\n") + "\n")
        mine = [c for c in cs if c.kind == "define" and c.names[0] in local_macros]
        for c in mine:
            text = c.text.strip("\n") + "\n"
            for n, (_, note) in aliased.get(name, {}).items():
                text = _rename(text, n, f"{n}__{name}", calls_only="undeclared" in note)
            body.append(text)
        func = defs[name]
        # (a static as written: its initializer may be a string; a guess on one line)
        lines = [c.text.strip() for c in cs if c.kind == "static" and set(c.names) & inner]
        text = func.text.strip("\n") + "\n"
        at = func.body - (len(func.text) - len(func.text.lstrip("\n")))
        for n, (view, note) in aliased.get(name, {}).items():
            lines.append(_alias(view, n, f"{n}__{name}", note))
            text = text[:at + 1] + _rename(text[at + 1:], n, f"{n}__{name}", calls_only="undeclared" in note)
        if as_called:
            calls = {}
            for g in own:
                if g == name or g not in defined_as or not re.search(rf"(?<![\w.>]){re.escape(g)}\s*\(", text[at:]):
                    continue
                said = next((c for c in cs if c.kind == "extern" and g in c.names and len(c.names) == 1), None)
                if said is not None:
                    view = " ".join(cfields._COMMENT.sub(" ", said.text).split())
                elif re.search(rf"(?<![\w.>]){re.escape(g)}\s*\(", cfields._COMMENT.sub(" ", shared)):
                    continue  # (the shared header's declaration: as the definition has it, or it wouldn't compile)
                else:
                    view = f"int {g}();"  # (called undeclared: as C does)
                if _key(view) != defined_as[g]:
                    calls[g] = view
            for g, view in calls.items():
                lines.append(_alias(view, g, f"{g}__{name}", f"{g} as this function calls it"))
                text = text[:at + 1] + _rename(text[at + 1:], g, f"{g}__{name}", calls_only=True)
        if lines:
            text = text[:at + 1] + "\n" + "".join(f"    {line}\n" for line in lines) + text[at + 1:].lstrip("\n")
        body.append("\n" + text)
        body += [f"#undef {c.names[0]}\n" for c in mine]

    asm_before(None)
    if pending:
        body.append("\n" + "\n".join(text.rstrip("\n") for _, text in pending) + "\n")
    header = "".join(header_decls + prototypes_h)
    if not own_header:
        own_decls, header = header_decls + prototypes_h + own_decls, ""
    parts = [f'#include "{include}"\n', "".join(includes), f'#include "{own_header}"\n' if header else "",
             "".join(top_macros), "".join(top_types), "".join(own_decls), "".join(prototypes_c), forward,
             "".join(others), "".join(data)]
    c = "\n".join(p for p in parts if p) + "".join(body)
    return Merged(c, header, scoped=scoped)
