"""Ghidra's C for a PC game's function, made into a draft the project's Visual C++ compiles: what autopilot tries on PC,
where m2c (which reads no x86) has nothing to offer.

Ghidra decompiles the whole program once (forks/ghidra_scripts/DecompWtfDrafts.java): each function's C and, for
every name the C uses, what it is, read from the decompiler's own tokens: a function it calls (its address, and the
types the call passes and gets back there), an import, or global data (its address and type). This gives them the
project's names (func_00401020, D_00402034; imports keep theirs, as __imp__Sleep@4 in the code) and declares them as
the C uses them, and gives the function the project's calling convention: _f is __cdecl, _f@8 __stdcall, @f@8
__fastcall; a method (this in ecx: Ghidra's __thiscall, or a __fastcall of one argument where the project says no
registers) is written as a method of a struct of its own. It leaves out what can't compile as it is: values Ghidra
couldn't place (in_EAX, unaff_ESI, extraout_ECX), names it couldn't resolve, thunks. Ghidra's own types and helpers
(undefined4, CONCAT44...) come from GHIDRA_TYPES, which autopilot adds to the project's common.h.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from pathlib import Path

# What a draft can't be compiled with: values in registers Ghidra couldn't place, and code it couldn't read
_UNPLACED = re.compile(r"\b(in_|unaff_|extraout_|in_stack_)\w+|\bhalt_baddata\b|\bswi\(|Bad instruction|"
                       r"\bLOCK\(\)|\bUNLOCK\(\)|\bfunc_0x[0-9a-f]+")
_HEAD = re.compile(r"(?P<ret>[^\n(]*?)\s*\b(?P<conv>__cdecl|__stdcall|__fastcall|__thiscall|__vectorcall)?\s*"
                   r"(?P<name>[A-Za-z_][\w:]*)\((?P<params>[^)]*)\)\s*$", re.M)
MAX_POPS = 1024  # bytes of arguments a function pops: a decorated name saying more is Ghidra's "don't know"
_GHIDRA_NAME = re.compile(r"\b(?:FUN|DAT|PTR|LAB|thunk_FUN)_[0-9a-fA-F]{8}\b")

GHIDRA_TYPES = r"""
/* GHIDRA_TYPES: the types and helpers of Ghidra's C, which autopilot's machine drafts (on PC) use as they are. */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3;
typedef unsigned int undefined4;
typedef unsigned __int64 undefined5;
typedef unsigned __int64 undefined6;
typedef unsigned __int64 undefined7;
typedef unsigned __int64 undefined8;
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned __int64 qword;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef __int64 longlong;
typedef unsigned __int64 ulonglong;
typedef long double float10;
typedef long double longdouble;
typedef void *pointer;
typedef void *pointer32;
typedef void *addr;
typedef int code(...);
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef long LONG;
typedef unsigned long ULONG;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char CHAR;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef unsigned short WCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef DWORD *LPDWORD;
typedef LONG *PLONG;
typedef unsigned long SIZE_T;
#define CONCAT11(a, b) ((ushort)(((uint)(uchar)(a) << 8) | (uchar)(b)))
#define CONCAT12(a, b) ((uint)(((uint)(uchar)(a) << 16) | (ushort)(b)))
#define CONCAT13(a, b) ((uint)(((uint)(uchar)(a) << 24) | ((uint)(b) & 0xFFFFFF)))
#define CONCAT21(a, b) ((uint)(((uint)(ushort)(a) << 8) | (uchar)(b)))
#define CONCAT22(a, b) ((uint)(((uint)(ushort)(a) << 16) | (ushort)(b)))
#define CONCAT31(a, b) ((uint)(((uint)(a) << 8) | (uchar)(b)))
#define CONCAT44(a, b) ((ulonglong)(((ulonglong)(uint)(a) << 32) | (uint)(b)))
#define SUB41(x, n) ((uchar)((uint)(x) >> ((n) * 8)))
#define SUB42(x, n) ((ushort)((uint)(x) >> ((n) * 8)))
#define SUB21(x, n) ((uchar)((ushort)(x) >> ((n) * 8)))
#define SUB81(x, n) ((uchar)((ulonglong)(x) >> ((n) * 8)))
#define SUB84(x, n) ((uint)((ulonglong)(x) >> ((n) * 8)))
#define ZEXT12(x) ((ushort)(uchar)(x))
#define ZEXT14(x) ((uint)(uchar)(x))
#define ZEXT24(x) ((uint)(ushort)(x))
#define ZEXT48(x) ((ulonglong)(uint)(x))
#define SEXT12(x) ((short)(char)(x))
#define SEXT14(x) ((int)(char)(x))
#define SEXT24(x) ((int)(short)(x))
#define SEXT48(x) ((longlong)(int)(x))
#define CARRY4(a, b) ((uint)(a) + (uint)(b) < (uint)(a))
#define SCARRY4(a, b) ((int)(((uint)(a) + (uint)(b)) ^ (uint)(a)) < 0 && (int)((uint)(a) ^ (uint)(b)) >= 0)
#define SBORROW4(a, b) ((int)(((uint)(a) ^ (uint)(b)) & ((uint)(a) ^ ((uint)(a) - (uint)(b)))) < 0)
/* GHIDRA_TYPES end */
"""
# Type names a declaration may use: C's own and GHIDRA_TYPES' (any other pointer is declared void *)
KNOWN = set(re.findall(r"typedef [^;]*?\b(\w+)(?:\(\.\.\.\))?;", GHIDRA_TYPES)) | {
    "void", "char", "short", "int", "long", "float", "double", "bool", "signed", "unsigned", "const", "__int64",
    "wchar_t", "s8", "u8", "s16", "u16", "s32", "u32", "s64", "u64", "f32", "f64", "BOOL"}


def add_types(header_text: str) -> str | None:
    """common.h with GHIDRA_TYPES before its last #endif; None when it has them already."""
    if "GHIDRA_TYPES" in header_text:
        return None
    end = header_text.rstrip().rfind("#endif")
    return (header_text[:end] + GHIDRA_TYPES.lstrip("\n") + "\n" + header_text[end:] if end >= 0
            else header_text.rstrip("\n") + "\n" + GHIDRA_TYPES)


def convention(decorated: str) -> tuple[str, int | None]:
    """(convention, bytes of stack arguments it pops) for a decorated name: _f, _f@8, @f@8."""
    m = re.fullmatch(r"([_@])\w+?(?:@(\d+))?", decorated or "")
    if not m:
        return "__cdecl", None
    if m.group(1) == "@":
        return "__fastcall", int(m.group(2) or 0)
    return ("__stdcall", int(m.group(2))) if m.group(2) else ("__cdecl", None)


def _type(t: str) -> str | None:
    """A type Ghidra's tokens give, as a declaration may use it: pointers to types unknown here become void *."""
    t = re.sub(r"\s+", " ", (t or "").strip())
    if not t:
        return None
    words = re.findall(r"[A-Za-z_]\w*", t)
    if all(w in KNOWN for w in words):
        return t
    return "void *" if t.endswith("*") else None


def _params(text: str) -> list[str]:
    text = text.strip()
    return [] if text in ("", "void") else [p.strip() for p in text.split(",")]


def _split(param: str) -> tuple[str, str]:
    """(type, name) of a parameter as Ghidra writes it: `undefined4 param_1`, `char *p` (the * goes with the type)."""
    m = re.fullmatch(r"(.+?)\s*(\**)\s*(\w+)", param.strip())
    if not m:
        return param, ""
    return (m.group(1) + (" " + m.group(2) if m.group(2) else "")).strip(), m.group(3)


def _size(param: str) -> int:
    """Bytes a stack parameter takes (Ghidra's declarations: `undefined4 param_1`, `double param_2`, `char *p`)."""
    t = _split(param)[0]
    if "*" in t:
        return 4
    return {"double": 8, "longlong": 8, "ulonglong": 8, "undefined8": 8, "qword": 8, "__int64": 8,
            "float10": 12, "longdouble": 12}.get(t.replace("unsigned ", "").strip(), 4)


def _data_decl(name: str, info: dict) -> str | None:
    t, size = (info.get("type") or "").strip(), int(info.get("size") or 0)
    m = re.fullmatch(r"(.+?)\s*\[(\d+)\]", t)
    if m:
        base = _type(m.group(1))
        return f"extern {base} {name}[{m.group(2)}];" if base else None
    if t in ("string", "TerminatedCString"):
        return f"extern char {name}[];"
    if t in ("unicode", "TerminatedUnicode"):
        return f"extern WCHAR {name}[];"
    base = _type(t) or {1: "undefined1", 2: "undefined2", 8: "undefined8"}.get(size, "undefined4")
    return f"extern {base} {name};"


def draft(row: dict, project: dict) -> tuple[str, str] | None:
    """(the draft, what it needs before it at file scope) for one function, or None when it can't compile as it is.

    `row`: the Ghidra script's line for the function. `project`: {"names": address -> decorated name of every
    function in functions.json, "imports": API name -> its __imp__ symbol in the program's code}."""
    c, entry = row.get("c") or "", int(row["entry"])
    names = project["names"]
    own = names.get(entry)
    if own is None or row.get("thunk") or _UNPLACED.search(c):
        return None
    body_at = c.find("{")
    m = _HEAD.search(c[:body_at]) if body_at > 0 else None
    if m is None or "::" in m.group("name"):
        return None
    conv, pops = convention(own)
    ghidra_conv, params = m.group("conv") or "", _params(m.group("params"))
    ret = m.group("ret").strip() or "void"
    if _type(ret) is None:
        return None
    me = f"func_{entry:08X}"
    body = c[body_at:].rstrip()
    outer: list[str] = []
    first: list[str] = []
    method = ghidra_conv == "__thiscall" or (ghidra_conv == "__fastcall" and conv != "__fastcall" and len(params) == 1)
    if method:  # this in ecx: a method of a struct of its own; Ghidra's name for this, declared from it
        if not params:
            return None
        rest = params[1:]
        this_type, this_name = _split(params[0])
        this_type = _type(this_type) or "void *"
        if this_name == "this":
            body = re.sub(r"\bthis\b", "this_", body)
            this_name = "this_"
        first.append(f"{this_type} {this_name} = ({this_type})this;")
        if any(_type(_split(p)[0]) is None for p in rest):
            return None
        struct = f"M_{entry:08X}"
        outer.append(f"struct {struct} {{ {ret} {me}({', '.join(rest) or 'void'}); }};")
        head = f"{ret} {struct}::{me}({', '.join(rest) or 'void'})"
    else:
        if conv == "__fastcall" and ghidra_conv != "__fastcall":
            return None
        if any(_type(_split(p)[0]) is None for p in params):
            return None
        if conv == "__stdcall" and pops is not None:  # the bytes the original pops: unused arguments Ghidra left out
            have = sum(_size(p) for p in params)
            # (a name holding Ghidra's "don't know", _f@2147483647, made a list of 500 million parameters here: an
            # 8 GB server ran out of memory and locked up)
            if have > pops or pops > MAX_POPS:
                return None
            params += [f"undefined4 unused_{i}" for i in range((pops - have) // 4)]
        head = f"{ret} {conv} {me}({', '.join(params) or 'void'})"

    inner: list[str] = []
    for name, info in sorted((row.get("refs") or {}).items(), key=lambda kv: -len(kv[0])):
        if name == m.group("name") or not re.search(rf"(?<![\w:]){re.escape(name)}\b", body):
            continue
        at, kind = int(info.get("at") or 0), info.get("kind")
        if kind in ("func", "import"):
            r = _type(info.get("ret") or "void")
            args = [_type(a) for a in info.get("args") or []]
            if r is None or None in args:
                return None
            if kind == "import":
                api = re.sub(r"^(?:__imp_|_)+", "", name).split("@")[0]
                sym = project["imports"].get(api)
                if sym is None:
                    return None
                cconv = "__stdcall" if re.search(r"@\d+$", sym) else "__cdecl"
                outer.append(f'extern "C" __declspec(dllimport) {r} {cconv} {api}({", ".join(args) or "void"});')
                new = api
            else:
                callee = names.get(at)
                if callee is None:
                    return None  # code the project didn't cut out as a function: no name to call it by
                cconv, _ = convention(callee)
                if cconv == "__fastcall":
                    return None  # (arguments in registers, or a method: the call as Ghidra writes it won't match)
                new = f"func_{at:08X}"
                if at != entry:
                    inner.append(f"{r} {cconv} {new}({', '.join(args) or 'void'});")
        else:
            if not at:
                return None
            new = f"D_{at:08X}"
            decl = _data_decl(new, info)
            if decl is None:
                return None
            inner.append(decl)
        body = re.sub(rf"(?:\b\w+::)*(?<![\w:]){re.escape(name)}\b", new, body)
    if _GHIDRA_NAME.search(body.replace("goto LAB_", "goto L_").replace("LAB_", "L_")):
        return None  # a name Ghidra printed that no token said what it is
    body = re.sub(r"\bLAB_", "L_", body)
    decls = list(dict.fromkeys(inner)) + first
    if decls:
        nl = body.index("{") + 1
        body = body[:nl] + "\n" + "".join(f"  {d}\n" for d in decls) + body[nl:].lstrip("\n")
    return f"{head}\n{body}\n", "\n".join(dict.fromkeys(outer))


_LOCK = threading.Lock()  # (the run itself is one at a time app-wide: forks/ghidra.py)
# project root -> (the cache file, where each function's line starts and ends in it, the project's names); None: no
# drafts (Ghidra couldn't run; tried again when the app starts again). Lines are read when asked for: a big game's
# drafts are tens of megabytes, which the app shouldn't hold for as long as it runs.
_LOADED: dict[Path, tuple[Path, dict[int, tuple[int, int]], dict] | None] = {}
_RUNNING: dict[Path, threading.Event] = {}  # projects whose drafts Ghidra is making: set when it's done


def project_names(functions_json: dict) -> dict:
    """What draft() needs to know of the project: every function's decorated name by address, and the imports its
    code calls (API name -> __imp__ symbol)."""
    names, imports = {}, {}
    for fns in functions_json["units"].values():
        for f in fns:
            names[f["addr"]] = f["name"]
            for r in f["relocs"]:
                if r[2] and r[2].startswith("__imp__"):
                    imports[r[2][len("__imp__"):].split("@")[0]] = r[2]
    return {"names": names, "imports": imports}


def _make(root: Path, exe: Path, addresses: list[int], cache: Path, done: threading.Event, log) -> None:
    from ...forks import ghidra

    try:
        log(f"Ghidra decompiles {exe.name} for machine drafts, once (a big game takes ten minutes or more)")
        ghidra.program_drafts(exe, addresses, cache)
    finally:
        with _LOCK:
            _RUNNING.pop(root, None)
        done.set()


def _load(fp, log=print, wait: bool = True) -> tuple[Path, dict[int, tuple[int, int]], dict] | None:
    """The project's drafts: Ghidra decompiles every function of the program once (minutes; kept in
    .decomp-wtf/ghidra, by the program's checksum), smallest first. `wait`: for that run, if they aren't made yet
    (autopilot, in the background); else it starts in the background and there are none yet (an agent's
    get_function must not wait minutes, nor start a Ghidra of its own: eight agents' runs ran a server out of
    memory)."""
    from ...forks.project import STATE

    root = Path(fp.root)
    with _LOCK:
        if root in _LOADED:
            return _LOADED[root]
        manifest = fp.manifest or {}
        exe = root / ((manifest.get("game") or {}).get("path") or "")
        config = root / "config" / str(manifest.get("version")) / "functions.json"
        try:
            info = json.loads(config.read_text(encoding="utf-8"))
            key = hashlib.sha1(exe.read_bytes()).hexdigest()[:16]
        except (OSError, ValueError):
            return None
        cache = root / STATE / "ghidra" / f"program-{key}.jsonl"
        done, mine = None, False
        if not cache.exists():
            done = _RUNNING.get(root)
            if done is None:
                done, mine = threading.Event(), True
                _RUNNING[root] = done
    if done is not None:
        if mine:
            fns = sorted((f for u in info["units"].values() for f in u), key=lambda f: (f["size"], f["addr"]))
            args = (root, exe, [f["addr"] for f in fns], cache, done, log)
            if not wait:
                threading.Thread(target=_make, args=args, daemon=True, name="ghidra-drafts").start()
                return None
            _make(*args)
        elif not wait:
            return None
        done.wait()
        if not cache.exists():
            with _LOCK:
                _LOADED[root] = None  # (Ghidra couldn't make them: tried again when the app starts again)
            return None
    at: dict[int, tuple[int, int]] = {}
    with open(cache, "rb") as f:
        pos = 0
        for line in f:
            m = re.match(rb'\{"entry": (\d+)', line)
            if m:
                at[int(m.group(1))] = (pos, len(line))
            pos += len(line)
    with _LOCK:
        _LOADED[root] = (cache, at, project_names(info))
        return _LOADED[root]


def _row(fp, symbol: str, log=print, wait: bool = True) -> tuple[dict, dict] | None:
    """(Ghidra's line for the function `symbol`, the project's names), or None."""
    m = re.search(r"func_([0-9A-Fa-f]{8})", symbol)
    loaded = _load(fp, log, wait) if m else None
    if loaded is None:
        return None
    cache, at, project = loaded
    where = at.get(int(m.group(1), 16))
    if where is None:
        return None
    try:
        with open(cache, "rb") as f:
            f.seek(where[0])
            return json.loads(f.read(where[1])), project
    except (OSError, ValueError):
        return None


def program_draft(fp, symbol: str, log=print) -> tuple[str, str] | None:
    """The draft of a project's function (its symbol: _func_00401000@4) that compiles as it is, for autopilot: waits
    for Ghidra's run the first time."""
    found = _row(fp, symbol, log)
    return draft(*found) if found else None


def program_c(fp, symbol: str) -> str | None:
    """Ghidra's C of a function for an agent to read: the compilable draft when there is one (the project's names),
    else Ghidra's own. None when Ghidra hasn't decompiled the program yet: that starts now, in the background."""
    found = _row(fp, symbol, wait=False)
    if found is None:
        return None
    row, project = found
    made = draft(row, project)
    if made:
        return (made[1] + "\n" if made[1] else "") + made[0]
    return (row.get("c") or "").strip() or None
