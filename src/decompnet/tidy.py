"""The declarations matched functions make for themselves, moved into the shared header once.

A function's C is judged alone, after the shared header: whatever else it needs (a callee's prototype, a global's
extern, a struct the header lacks) it declares itself, above its code. On a 2000s Linux game that was about 3,100
lines in 1,587 functions, the same `extern void xfPush(void);` in dozens of them and a struct such as
CoinStateStruct defined inside one function's file. Fine for matching; not for people reading the tree, nor for
relinking it whole. `plan` reads each function's file-scope declarations and says which go into the header (one
copy, grouped by the source file that first needed it) and which stay where they are:

- what the header already declares the same way is dropped from the function (a second copy changes nothing);
- what every function declares the same way, and the header doesn't, moves (types before the externs using them);
- what two functions declare differently (two guesses at one global's type), what uses a type that stays local,
  statics, macros and inline helpers stay.

The caller (Readability.tidy_declarations) judges every function again with the new header and C, and puts back
what any of them needs: nothing is weakened."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import cfields

_KEYWORDS = {"extern", "static", "const", "volatile", "struct", "union", "enum", "unsigned", "signed", "int", "char",
             "short", "long", "float", "double", "void", "typedef", "register", "inline", "__inline__", "return",
             "sizeof", "if", "else", "for", "while", "do", "switch", "case", "default", "break", "continue", "goto"}


# an old-style definition: `void renOOWTV(count, lookup) ushort count; ... { ... }`
_KR_HEAD = re.compile(r"[^;{}()]*\b\w+\s*\(\s*[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*\)\s*[A-Za-z_]")


@dataclass
class Item:
    """One file-scope declaration of a function's C."""
    start: int
    end: int  # (its text is source[start:end], the line break after it included)
    text: str
    kind: str  # "type" (typedef, struct, union, enum) or "extern" (a global's or a function's declaration)
    names: tuple[str, ...]  # what it declares: a typedef's name, a struct's tag (struct X), a global or function

    @property
    def key(self) -> str:
        return _key(self.text)


@dataclass
class Plan:
    moved: list[tuple[str, Item]] = field(default_factory=list)  # (source file, item) for the header, in order
    sources: dict[int, str] = field(default_factory=dict)  # function id -> its C without what moved or repeated

    def header(self, header: str) -> str:
        if not self.moved:
            return header
        out, unit = [header.rstrip("\n"), "", "/* Declarations the functions made for themselves, gathered here */"], None
        for u, item in self.moved:
            if u != unit:
                out.append(f"\n/* {u or 'the program'} */")
                unit = u
            out.append(item.text.strip())
        return "\n".join(out) + "\n"


def _key(text: str) -> str:
    """A declaration as compared: `extern void *malloc(unsigned int size);` is the header's
    `void *malloc(unsigned int);` (`extern` and parameter names say nothing of its type)."""
    flat = re.sub(r"^extern\s+", "", " ".join(cfields._COMMENT.sub(" ", text).split()))
    m = re.match(r"([^(){}]*\w\s*)\(([^(){}]*)\)\s*;$", flat)
    if not m:
        return flat
    params = []
    for param in _split_top(m.group(2)):
        param = param.strip()
        named = re.match(r"(.*?[\w*\s])\s*\b([A-Za-z_]\w*)\s*((?:\[[^\]]*\]\s*)*)$", param)
        if named and named.group(2) not in _KEYWORDS and re.search(r"[\w*]", named.group(1)) and \
                not re.fullmatch(r"\s*(?:struct|union|enum)\s*", named.group(1)):
            param = (named.group(1).strip() + (" " + named.group(3).strip() if named.group(3) else "")).strip()
        params.append(" ".join(param.replace("*", " * ").split()).replace(" *", "*").replace("* ", "*"))
    return f"{' '.join(m.group(1).split())}({', '.join(params)});"


def items(source: str) -> list[Item]:
    """The declarations at file scope `source` makes before and between its functions that could move: externs,
    prototypes, typedefs, struct/union/enum definitions. Statics, definitions, macros, inline helpers aren't."""
    found = []
    text = cfields._COMMENT.sub(lambda m: " " * len(m.group(0)), source)  # (offsets kept)
    i, n = 0, len(text)
    while i < n:
        j = i
        while j < n and text[j] in " \t\r\n":
            j += 1
        if j >= n:
            break
        if text[j] == "#":  # a preprocessor line (and its continuations)
            while j < n and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        depth, k = 0, j
        while k < n:
            c = text[k]
            if c in "\"'":  # a literal
                q, k = c, k + 1
                while k < n and text[k] != q:
                    k += 2 if text[k] == "\\" else 1
            elif c in "({[":
                depth += 1
            elif c in ")}]":
                depth -= 1
                if depth == 0 and c == "}" and _is_body(text, j, k):
                    break
            elif c == ";" and depth == 0 and not _KR_HEAD.match(text, j):  # (a K&R definition's parameters)
                break
            k += 1
        end = k + 1
        while end < n and text[end] in " \t\r":
            end += 1
        if end < n and text[end] == "\n":
            end += 1
        decl = text[j:k + 1]
        item = _item(decl, source[j:k + 1])
        if item is not None:
            found.append(Item(j, end, source[j:end].rstrip() + "\n", item[0], item[1]))
        i = k + 1
    return found


def _is_body(text: str, start: int, close: int) -> bool:
    """Whether the braces closing at `close` are a function's body (`int f(int a) { ... }`), not a struct's."""
    head = text[start:text.index("{", start)] if "{" in text[start:close] else ""
    return head.rstrip().endswith(")") or bool(re.search(r"\)\s*(?:[A-Za-z_][\w\s,*]*;\s*)+$", head))


_ATTRIBUTE = re.compile(r"__attribute__\s*\(\((?:[^()]|\([^()]*\))*\)\)")


def _item(decl: str, original: str) -> tuple[str, tuple[str, ...]] | None:
    flat = " ".join(_ATTRIBUTE.sub(" ", decl).split())
    if re.match(r"(?:static|inline|__inline__|extern\s+\"C\")\b", flat) or "=" in _without_parens(flat):
        return None
    if flat.startswith("typedef "):
        body = _without_braces(flat)
        m = re.search(r"\(\s*\*\s*(\w+)\s*\)\s*\(", body) or re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*;$", body)
        if not m:
            return None
        tag = re.match(r"typedef\s+(struct|union|enum)\s+(\w+)\s*\{", flat)
        return "type", (m.group(1),) + ((f"{tag.group(1)} {tag.group(2)}",) if tag else ())
    tag = re.match(r"(struct|union|enum)\s+(\w+)\s*\{.*\}\s*;$", flat)
    if tag:
        return "type", (f"{tag.group(1)} {tag.group(2)}",)
    if "{" in flat:
        return None
    body = re.sub(r"^extern\s+", "", flat)
    names = []
    for part in _split_top(body.rstrip(";")):
        m = re.search(r"\(\s*\*\s*(\w+)\s*\)\s*\(", part) or re.search(r"(\w+)\s*\(", part) or \
            re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*$", part)
        if not m or m.group(1) in _KEYWORDS:
            return None
        names.append(m.group(1))
    if not flat.startswith("extern ") and "(" not in flat:  # `int g_score;` defines it: it stays
        return None
    return ("extern", tuple(names)) if names else None


def _without_braces(text: str) -> str:
    return re.sub(r"\{.*\}", "{}", text)


def _without_braces_all(text: str) -> str:
    """`text` with every brace's contents gone, nested ones too: `typedef struct { ... } X;` -> `typedef struct {} X;`."""
    out, depth = [], 0
    for c in text:
        if c == "}":
            depth = max(depth - 1, 0)
        if depth == 0:
            out.append(c)
        if c == "{":
            depth += 1
    return "".join(out)


def _without_parens(text: str) -> str:
    out, depth = [], 0
    for c in text:
        depth += c == "("
        if depth == 0:
            out.append(c)
        depth -= c == ")" and depth > 0
    return "".join(out)


def _split_top(text: str) -> list[str]:
    """`int a, *b` -> the declarators after the first one's type: `int a`, `*b`."""
    parts, depth, cur = [], 0, ""
    for c in text:
        depth += c in "([{"
        depth -= c in ")]}"
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    return parts + [cur]


def _identifiers(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_]\w*", cfields._COMMENT.sub(" ", text)))


def plan(functions: list[dict], header: str, keep: set[str] = frozenset()) -> Plan:
    """What moves into `header` and each function's C after (`functions`: id, unit, matched_source, in the
    program's order). `keep`: names that stay where they are (a function needed its own copy)."""
    top = cfields._without_braces(cfields._COMMENT.sub(" ", header))
    parsed = cfields.Header(header)
    found = {f["id"]: items(f["matched_source"]) for f in functions}

    def in_header(item: Item) -> str | None:
        """'same' when the header declares this exactly, 'other' when it declares one of its names otherwise."""
        if item.key in header_keys:
            return "same"
        for name in item.names:
            if name.startswith(("struct ", "union ", "enum ")):
                if re.search(rf"\b{name.split()[0]}\s+{name.split()[1]}\s*\{{", top):
                    return "other"
            elif name in parsed.typedefs or name in parsed.bodies or re.search(
                    rf"(?<![\w.>]){re.escape(name)}\s*(?:\[[^\]]*\]\s*)*[;(),]", top):
                return "other"
        return None
    header_keys = {_key(line) for line in header.splitlines() if line.strip().endswith(";")}

    # a name -> how many functions declare it each way, and where each way is first: the most common way moves,
    # and functions declaring it another way keep theirs (a conflict the judging finds puts the name in `keep`)
    counts: dict[str, dict[str, int]] = {}
    first: dict[str, tuple[str, Item]] = {}
    for f in functions:
        for item in found[f["id"]]:
            for name in item.names:
                counts.setdefault(name, {})[item.key] = counts.get(name, {}).get(item.key, 0) + 1
                first.setdefault(item.key, (f["unit"] or "", item))
    chosen = {name: max(ways, key=lambda k: ways[k]) for name, ways in counts.items()}
    # a matched function's prototype moves only as its definition has it: its callers agreed on `void auditInit();`
    # where it is `int auditInit(void)`, and 525 of a Linux game's functions no longer compiled with that header
    defined = {}
    for f in functions:
        head = re.search(rf"^([^;{{}}#\n][^;{{}}]*?\b{re.escape(f['name'])}\s*\([^;{{}}]*\))\s*\{{",
                         cfields._COMMENT.sub(" ", f["matched_source"]), re.M)
        if head:
            defined[f["name"]] = _key(re.sub(r"^\s*(?:static\s+|inline\s+)*", "", head.group(1)) + ";")
    movable: dict[str, Item] = {}
    for name, key in chosen.items():
        unit, item = first[key]
        if name not in keep and in_header(item) is None and \
                all(chosen.get(other) == key and other not in keep for other in item.names) and \
                all(defined.get(other, key) == key for other in item.names if item.kind == "extern"):
            movable[key] = item
    # a moved declaration may only use the header's types and moved ones: what uses a local type stays
    # (and what the functions' files define otherwise: a macro, a type the reading above missed)
    local_types = {name for f in functions for item in found[f["id"]] if item.kind == "type" for name in item.names}
    defined = set()
    for f in functions:
        text = _ATTRIBUTE.sub(" ", cfields._COMMENT.sub(" ", f["matched_source"]))
        defined |= set(re.findall(r"^[ \t]*#[ \t]*define[ \t]+(\w+)", text, re.M))
        defined |= set(re.findall(r"\btypedef\b[^;]*?\b(\w+)\s*(?:\[[^\]]*\]\s*)*;", _without_braces_all(text)))
        defined |= set(re.findall(r"\b(?:struct|union|enum)\s+(\w+)\s*\{", text))
    known = set(parsed.typedefs) | set(parsed.bodies) | set(re.findall(r"^[ \t]*#[ \t]*define[ \t]+(\w+)", header, re.M))
    while True:
        moved_names = {name for item in movable.values() for name in item.names}
        moved_words = {name.split()[-1] for name in moved_names}
        stays = {name.split()[-1] for name in local_types - moved_names} | (defined - moved_words - known)
        dropped = [key for key, item in movable.items() if (_identifiers(item.text) - set(item.names)
                                                             - {n.split()[-1] for n in item.names}) & stays]
        if not dropped:
            break
        for key in dropped:
            movable.pop(key)
    out = Plan()
    order = {key: i for i, key in enumerate(movable)}
    units = {key: first[key][0] for key in movable}
    ranked = sorted(movable.items(), key=lambda kv: (kv[1].kind != "type", units[kv[0]], order[kv[0]]))
    out.moved = [(units[key], item) for key, item in ranked]
    for f in functions:
        gone = [it for it in found[f["id"]] if it.key in movable or in_header(it) == "same"]
        if not gone:
            continue
        source = f["matched_source"]
        for it in sorted(gone, key=lambda it: it.start, reverse=True):
            source = source[:it.start] + source[it.end:]
        out.sources[f["id"]] = re.sub(r"\n{3,}", "\n\n", source)
    return out
