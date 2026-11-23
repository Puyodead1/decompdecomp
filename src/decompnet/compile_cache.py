"""A persistent, content-addressed store of the objects `compiler.compile_source` built successfully.

The permuter compiles thousands of variants of one function, many of them the same C again (its rewrites undo each
other, a restarted turn starts from the same base), and a room's host compiles again every attempt its members send:
each compile of an old compiler costs from a tenth of a second to several seconds. This store keeps the objects on
disk in the data home, shared by every process and kept across restarts, so the same C with the same compiler is
compiled once.

Its key is everything that decides the object: the compiler by content (the pinned install's manifest, which records
its pack id and the SHA-256 of its archives, and the SHA-256 of every program on the command line), the whole command
line with its flags (which fix the target processor too), the prelude, the C++ retry and system-header settings, the
language asked for, the shared header, the function's C, every file of the extra header folders, the code that writes
the compiler's input (this module's and compiler.py's), the sandbox mode, the platform and this store's format.
A compiler this process can't fingerprint (a folder no manifest pins, a program found on PATH, a kit the user
brought, WSL's and the Linux VM's copies) compiles as before, every time.

It stores objects, never a verdict: a cached object is linked and compared byte for byte exactly like a fresh one,
so the judge is as exact as it was. Failures, timeouts and cancelled compiles are never written (a timeout depends on
the machine's load). Each entry carries a SHA-256 of its contents and is written whole or not at all (os.replace); a
corrupt or truncated one is a miss, and is removed. The store's size is bounded (DECOMP_OBJECT_CACHE_MB, default 512,
0 turns it off) by removing the least recently used entries.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
import sys
import threading
import time
from pathlib import Path

FORMAT = 1
MAGIC = b"DDOBJ\x00\x01\n"
DIGEST_BYTES = 32
META_LENGTH = struct.Struct(">I")
DEFAULT_LIMIT_MB = 512
MAX_ENTRY_BYTES = 4 * 1024 * 1024  # one function's object; a bigger one isn't worth a slot
# A process sweeps on its first store, then after writing this fraction of the limit: the store isn't scanned on
# every compile, and entries from earlier runs are counted all the same.
SWEEP_FRACTION = 16
KEEP_FRACTION = 0.9  # a sweep leaves room, so the next stores don't start another at once
STALE_SECONDS = 3600  # temporary files a killed writer left, and a sweep lock a killed sweeper left
SWEEP_LOCK = ".sweep.lock"
HEADER_SUFFIXES = (".h", ".hpp", ".hxx", ".inc", ".inl")
_PACKAGE = Path(__file__).resolve().parent
# What writes the compiler's input (func.c's wrapper, the C++ retry, the placeholders) and this key: an object another
# version of that code stored is not reused.
_PIPELINE = hashlib.sha256(b"".join(p.read_bytes() for p in (_PACKAGE / "compiler.py", Path(__file__)))).digest()
_MEMO_LIMIT = 256

_lock = threading.Lock()
_digests: dict = {}
_written: dict = {}
_sweepers: dict = {}
log = logging.getLogger("decompdecomp")


def limit_bytes() -> int:
    """The store's size limit; 0 when DECOMP_OBJECT_CACHE_MB turns it off. A value that isn't a number keeps the
    default rather than turning the store off by accident."""
    try:
        megabytes = int(os.environ.get("DECOMP_OBJECT_CACHE_MB", DEFAULT_LIMIT_MB))
    except ValueError:
        megabytes = DEFAULT_LIMIT_MB
    return max(0, megabytes) * 1024 * 1024


def directory() -> Path:
    """Beside the app's other private state in the data home (DECOMP_HOME), one folder per format."""
    from .app import edition
    return edition.home_dir() / ".decomp" / "object-cache" / f"v{FORMAT}"


def key(cfg, mode: str, context_header: str, source: str, language: str | None) -> bytes | None:
    """The key of one compile_source call, or None when the store is off or the compiler can't be fingerprinted
    beyond this process. `mode` is the sandbox the compile runs in (it decides the compiler's view of its folder)."""
    if limit_bytes() <= 0:
        return None
    toolchain = _compiler_identity(cfg, mode)
    if toolchain is None:
        return None
    try:
        headers = [_folder_digest(Path(d), recursive=True) for d in cfg.include_dirs]
    except OSError:
        return None
    settings = json.dumps({"format": FORMAT, "mode": mode, "platform": sys.platform, "cmd": list(cfg.cmd),
                           "prelude": cfg.prelude, "cplusplus": cfg.cplusplus, "system_headers": cfg.system_headers,
                           "language": language, "include_dirs": list(cfg.include_dirs)}, sort_keys=True).encode()
    digest = hashlib.sha256(b"decompdecomp object cache\0")
    # Each part with its length first: no two different inputs make the same stream.
    for part in (_PIPELINE, settings, toolchain, *headers, context_header.encode(), source.encode()):
        digest.update(len(part).to_bytes(8, "little"))
        digest.update(part)
    return digest.digest()


def _compiler_identity(cfg, mode: str) -> bytes | None:
    """What the compiler is, by content: a pinned install's manifest (its pack id, version and archives' SHA-256)
    and every program its command line runs. A path or a size and date would be enough within one process, not for
    an object kept across reinstalls."""
    if mode in ("wsl", "linux-vm"):
        # The programs run from copies inside another system, by paths this process can't read. shortcut: these
        # compile fresh every time; fingerprinting WSL's and the VM's copies would include them.
        return None
    from . import toolchains
    roots, parts = [], []
    for folder in dict.fromkeys(filter(None, (*cfg.ro_paths, cfg.runtime32))):
        where = Path(folder).resolve()
        manifest = where / toolchains.MANIFEST
        try:
            if manifest.is_file():
                parts.append(("toolchain", str(where), manifest.read_bytes().hex()))
            elif where == _PACKAGE or _PACKAGE in where.parents:
                # A driver shipped with the app (an SDK's wrapper script): its folder's code, by content.
                parts.append(("app", str(where), _folder_digest(where).hex()))
            else:
                return None  # a folder nothing pins (a library's headers, a kit's copy): it can change unnoticed
        except OSError:
            return None
        roots.append(where)
    if not cfg.cmd or not os.path.isabs(cfg.cmd[0]):
        return None  # a program found on PATH: which one runs, and what it is, can change between runs
    for arg in cfg.cmd:
        if not os.path.isabs(arg) or not Path(arg).is_file():
            continue
        program = Path(arg).resolve()
        if not any(root == program or root in program.parents for root in roots) \
                and program != Path(sys.executable).resolve():
            return None
        try:
            parts.append(("program", arg, _file_digest(program).hex()))
        except OSError:
            return None
    if not any(kind == "program" for kind, *_ in parts):
        return None
    return json.dumps(parts).encode()


def _memo(signature, compute):
    with _lock:
        if signature in _digests:
            return _digests[signature]
    value = compute()
    with _lock:
        if len(_digests) >= _MEMO_LIMIT:
            _digests.clear()
        _digests[signature] = value
    return value


def _file_digest(path: Path) -> bytes:
    """A program's SHA-256, read once per process per version of the file (compilers can be tens of MB)."""
    st = path.stat()

    def compute():
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.digest()
    return _memo(("file", str(path), st.st_size, st.st_mtime_ns, getattr(st, "st_ctime_ns", 0)), compute)


def _folder_digest(folder: Path, recursive: bool = False) -> bytes:
    """A folder's files by name and content: a driver's folder (it may import its neighbours), or a header folder
    compile_source copies beside context.h (`recursive`, headers only, as it reads them)."""
    found = []
    for path in sorted(folder.rglob("*") if recursive else folder.iterdir()):
        if path.is_file() and (not recursive or path.suffix.lower() in HEADER_SUFFIXES):
            st = path.stat()
            found.append((path.relative_to(folder).as_posix(), st.st_size, st.st_mtime_ns))

    def compute():
        digest = hashlib.sha256()
        for name, *_ in found:
            data = (folder / name).read_bytes()
            digest.update(name.encode() + b"\0" + len(data).to_bytes(8, "little") + data)
        return digest.digest()
    return _memo(("folder", str(folder), recursive, tuple(found)), compute)


def _path(entry: bytes, root: Path | None = None) -> Path:
    name = entry.hex()
    return (root or directory()) / name[:2] / name


def load(entry: bytes):
    """A stored object as a new CompileResult, or None. A damaged entry is a miss, and is removed."""
    from .compiler import CompileResult
    path = _path(entry)
    try:
        data = path.read_bytes()
    except OSError:
        return None
    result = _decode(data)
    if result is None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass  # (Windows: another process still reads it; a later miss removes it)
        return None
    try:
        os.utime(path)  # most recently used: what a sweep keeps
    except OSError:
        pass
    obj, text, language = result
    return CompileResult(True, obj, text, language)


def _decode(data: bytes):
    header = len(MAGIC) + DIGEST_BYTES
    if len(data) < header + META_LENGTH.size or not data.startswith(MAGIC):
        return None
    payload = data[header:]
    if hashlib.sha256(payload).digest() != data[len(MAGIC):header]:
        return None
    (length,) = META_LENGTH.unpack_from(payload)
    if META_LENGTH.size + length > len(payload):
        return None
    try:
        meta = json.loads(payload[META_LENGTH.size:META_LENGTH.size + length])
        obj = payload[META_LENGTH.size + length:]
        if len(obj) != meta["size"]:
            return None
        return obj, str(meta["log"]), str(meta["language"])
    except (ValueError, KeyError, TypeError):
        return None


def _encode(result) -> bytes:
    meta = json.dumps({"log": result.log, "language": result.language, "size": len(result.obj)}).encode()
    payload = META_LENGTH.pack(len(meta)) + meta + result.obj
    return MAGIC + hashlib.sha256(payload).digest() + payload


def store(entry: bytes, result) -> None:
    """Keep a successful compile's object. Written whole or not at all (a file beside it, then os.replace), so
    another process reads the old entry, the new one or none, never half. A failure to write never fails a compile."""
    limit = limit_bytes()
    if not limit or not result.ok or result.obj is None:
        return
    data = _encode(result)
    if len(data) > MAX_ENTRY_BYTES or len(data) > limit // 8:
        return
    path = _path(entry)
    if path.exists():
        return  # (another worker stored the same object meanwhile)
    root = path.parent.parent
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError as error:
        log.debug("the compiled-object cache could not store an object: %s", error)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return
    _schedule_sweep(root, limit, len(data))


def _schedule_sweep(root: Path, limit: int, size: int) -> None:
    with _lock:
        written = _written.get(root)
        _written[root] = (written or 0) + size
        due = written is None or _written[root] >= limit // SWEEP_FRACTION
        running = _sweepers.get(root)
        if not due or (running is not None and running.is_alive()):
            return
        _written[root] = 0
        thread = _sweepers[root] = threading.Thread(target=sweep, args=(root, limit), daemon=True,
                                                    name="object-cache-sweep")
    thread.start()  # in the background: a sweep scans the whole store, which no compile should wait for


def wait_for_sweeps(timeout: float = 30) -> None:
    """Let running sweeps finish (tests)."""
    with _lock:
        threads = list(_sweepers.values())
    for thread in threads:
        thread.join(timeout)


def sweep(root: Path | None = None, limit: int | None = None) -> int:
    """Remove the least recently used entries until the store is within its limit, and what killed writers left.
    One process sweeps at a time (a lock file); the others skip. Returns how many entries were removed."""
    root = root or directory()
    limit = limit_bytes() if limit is None else limit
    lock = root / SWEEP_LOCK
    try:
        root.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.time() - lock.stat().st_mtime < STALE_SECONDS:
                return 0
            lock.unlink(missing_ok=True)  # a sweeper that was killed
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(descriptor)
    except OSError:
        return 0  # (another process took it between the two steps, or the folder is unavailable)
    try:
        return _remove_oldest(root, limit)
    finally:
        try:
            lock.unlink(missing_ok=True)
        except OSError:
            pass


def _remove_oldest(root: Path, limit: int) -> int:
    entries, total, now = [], 0, time.time()
    with os.scandir(root) as shards:
        for shard in shards:
            if not shard.is_dir(follow_symlinks=False):
                continue
            with os.scandir(shard.path) as files:
                for item in files:
                    try:
                        st = item.stat(follow_symlinks=False)
                    except OSError:
                        continue  # (removed meanwhile)
                    if item.name.startswith("."):
                        if item.name.endswith(".tmp") and now - st.st_mtime > STALE_SECONDS:
                            _remove(item.path)
                        continue
                    entries.append((st.st_mtime_ns, st.st_size, item.path))
                    total += st.st_size
    removed = 0
    if total > limit:
        entries.sort()
        target = int(limit * KEEP_FRACTION)
        for _, size, path in entries:
            if total <= target:
                break
            if _remove(path):
                removed += 1
            total -= size
    return removed


def _remove(path) -> bool:
    try:
        os.unlink(path)
        return True
    except OSError:
        return False  # (gone already, or open in another process on Windows)
