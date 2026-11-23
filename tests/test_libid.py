"""Finding the libraries a game has built in (libid/, app/engine/libraryid.py): its text, the catalog's constants,
the user's signature files (ours, IDA's FLIRT .pat and .sig), and agents' report_library."""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

import pytest

from decompnet import libid
from decompnet.libid import flirt

MD5_T = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf]
MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def x86(*words: int, pad: int = 40) -> bytes:
    """Code holding these words as `add eax, imm32` (05 imm32), then `ret`."""
    return b"\x55\x8b\xec" + b"".join(b"\x05" + struct.pack("<I", w) for w in words) + b"\x90" * pad + b"\xc3"


def empty_catalog(tmp_path: Path) -> libid.Catalog:
    return libid.load(tmp_path / "none")


def test_a_hash_is_found_by_its_constants_with_the_functions_beside_it(tmp_path):
    """A 1999 PC game's RSA MD5: MD5Transform holds MD5's round constants; MD5Init only the starting values, which
    SHA-1 shares (counted only beside MD5's own code); MD5Update and MD5Final hold none, but lie between them. The
    game's own functions around them, and one far away with the same starting values, aren't taken."""
    codes = [
        libid.Code(1, "game_before", 0x4AF000, x86(1, 2, 3)),
        libid.Code(2, "MD5Init", 0x4AFA28, x86(*MD5_INIT)),
        libid.Code(3, "MD5Update", 0x4AFA72, x86(7, 8)),
        libid.Code(4, "MD5Final", 0x4AFBB3, x86(9)),
        libid.Code(5, "MD5Transform", 0x4AFD11, x86(*MD5_T)),
        libid.Code(6, "game_far", 0x510000, x86(*MD5_INIT)),
    ]
    report = libid.identify(None, codes, empty_catalog(tmp_path), arch="x86")
    md5 = next(lib for lib in report["libraries"] if lib["id"] == "md5")
    assert set(md5["keys"]) == {2, 3, 4, 5} and md5["aside"]
    why = {f["name"]: f["why"] for f in md5["functions"]}
    assert "5 of its constants" in why["MD5Transform"] and "between two of its own" in why["MD5Update"]
    assert not any(lib["id"] == "sha1" for lib in report["libraries"])


def test_constants_split_in_two_halves_are_found_on_mips():
    """MIPS builds a 32-bit constant from lui and ori (or addiu, whose negative low half adds one to the high)."""
    def lui(hi):  # lui $t0, hi
        return 0x3C080000 | hi

    def addiu(lo):  # addiu $t0, $t0, lo
        return 0x25080000 | lo
    words = []
    for c in MD5_T[:4]:
        hi, lo = c >> 16, c & 0xFFFF
        words += [lui((hi + 1) & 0xFFFF if lo & 0x8000 else hi), addiu(lo)]
    code = libid.Code(1, "f", 0x80001000, struct.pack(">%dI" % len(words), *words))
    assert libid.constants_in(code, MD5_T, "mips", True) == set(MD5_T[:4])
    assert libid.constants_in(code, MD5_T, "x86", True) == set()  # (x86 keeps them whole)


def test_the_programs_text_says_which_library_and_version(tmp_path):
    """zlib's copyright string names its version, and where its source is; text no catalog entry knows (another
    company's notice, the source paths its assertions keep) is listed for the user to look up."""
    program = (b"\0 inflate 1.1.3 Copyright 1995-1998 Mark Adler \0incorrect header check\0"
               b"(c) 1999 Some Middleware Inc.\0..\\src\\thirdparty\\foo\\foo_decode.c\0")
    report = libid.identify(program, [], empty_catalog(tmp_path))
    z = next(lib for lib in report["libraries"] if lib["id"] == "zlib")
    assert z["version"] == "1.1.3" and z["download"] == "https://zlib.net/fossils/zlib-1.1.3.tar.gz"
    assert any("Mark Adler" in e for e in z["evidence"]) and not z["functions"]
    assert [n["text"] for n in report["notices"]] == ["(c) 1999 Some Middleware Inc."]
    assert report["paths"] == [{"folder": "src/thirdparty/foo", "files": ["foo_decode.c"], "count": 1}]


def test_our_signature_files_find_a_librarys_functions_with_relocations_left_out(tmp_path):
    """Our own format: a function's bytes with what a relocation fills in left out ("..")."""
    body = bytes(range(0x40, 0x70))
    sig = libid.signature_file("zlib", "1.2.3", [("adler32", b"\xe8\0\0\0\0" + body, frozenset(range(1, 5)))])
    folder = tmp_path / "sigs"
    folder.mkdir()
    (folder / "zlib-1.2.3.json").write_text(json.dumps(sig))
    catalog = libid.load(folder)
    assert catalog.files == [{"file": "zlib-1.2.3.json", "kind": "signatures", "count": 1}]
    game = libid.Code(7, "func_00401000", 0x401000, b"\xe8\x12\x34\x56\x78" + body)
    other = libid.Code(8, "func_00402000", 0x402000, b"\xe8\x12\x34\x56\x78" + body[:-1] + b"\x00")
    report = libid.identify(None, [game, other], catalog)
    z = report["libraries"][0]
    assert z["id"] == "zlib" and z["version"] == "1.2.3" and z["keys"] == [7]
    assert "adler32 of zlib 1.2.3 (zlib-1.2.3.json)" in z["functions"][0]["why"]


def test_flirt_pattern_files_are_read(tmp_path):
    """sigmake's .pat lines: 32 bytes of pattern, the CRC-16 of what follows, the length, the names."""
    code = bytes(range(0x10, 0x10 + 0x50))
    pattern = code[:32].hex().upper()
    pattern = pattern[:8] + "........" + pattern[16:]  # (bytes 4-7: a relocation)
    crc = libid._crc16(code[32:0x30])
    line = f"{pattern} 10 {crc:04X} {len(code):04X} :0000 _inflate_fast ^0010 _memcpy (0040) {code[0x40]:02X}\n---\n"
    sigs = flirt.read_pat(line, "zlib", "zlib.pat")
    assert [(s.name, s.size, s.crc, s.tail) for s in sigs] == [("_inflate_fast", 0x50, (32, 0x10, crc),
                                                                 ((0x40, code[0x40]),))]
    game = libid.Code(1, "func_0", 0, code[:4] + b"\xaa\xbb\xcc\xdd" + code[8:])
    assert libid.signature_matches(sigs[0], game)
    assert not libid.signature_matches(sigs[0], libid.Code(2, "f", 0, code[:0x28] + b"\0" + code[0x29:]))


def _sig_file(code: bytes, name: str, compressed: bool) -> bytes:
    """A FLIRT .sig (version 6) of one module: a tree of one node (its 32-byte pattern, bytes 4-7 variant), then a
    leaf."""
    tree = bytearray([1, 32])  # one child, 32 bytes long
    variant = sum(1 << (31 - j) for j in range(4, 8))
    tree += bytes([0xC0 | (variant >> 24) & 0x3F, (variant >> 16) & 0xFF, (variant >> 8) & 0xFF, variant & 0xFF])
    tree += bytes(b for j, b in enumerate(code[:32]) if not 4 <= j < 8)
    tree += bytes([0])  # its children: none, a leaf
    crc_len = len(code) - 32
    tree += bytes([crc_len]) + struct.pack(">H", libid._crc16(code[32:]))
    tree += bytes([len(code)])  # the module's length (max2)
    tree += bytes([0]) + name.encode() + bytes([0])  # offset 0, its name, flags: nothing more
    body = zlib.compress(bytes(tree)) if compressed else bytes(tree)
    header = b"IDASGN" + bytes([6, 0]) + struct.pack("<IHHH", 1, 1, 1, 0x10 if compressed else 0)
    header += struct.pack("<HH", 1, 0) + bytes(12) + bytes([len("Test library")]) + struct.pack("<H", 0)
    header += struct.pack("<I", 1)  # functions (version 6)
    return header + b"Test library" + body


@pytest.mark.parametrize("compressed", [False, True])
def test_flirt_signature_files_are_read(tmp_path, compressed):
    code = bytes(range(0x20, 0x20 + 0x30))
    sigs = flirt.read_sig(_sig_file(code, "_crc32", compressed), "test.sig")
    assert [(s.library, s.name, s.size) for s in sigs] == [("Test library", "_crc32", 0x30)]
    assert libid.signature_matches(sigs[0], libid.Code(1, "f", 0, code[:4] + b"\x99" * 4 + code[8:]))
    assert not libid.signature_matches(sigs[0], libid.Code(1, "f", 0, code[:-1] + b"\x00"))
    with pytest.raises(ValueError):
        flirt.read_sig(b"NOTASIG" + bytes(40), "x.sig")


def test_the_users_catalog_entries_add_and_replace(tmp_path):
    """A .toml in the signatures folder adds libraries the catalog doesn't know and replaces the ones it does; a
    file that can't be read says why and the rest still count."""
    folder = tmp_path / "sigs"
    folder.mkdir()
    (folder / "mine.toml").write_text('[[library]]\nid = "acme"\nname = "Acme Sound"\nkind = "middleware"\n'
                                      'strings = [\'Acme Sound v(?P<version>\\d+\\.\\d+)\']\n')
    (folder / "broken.pat").write_bytes(b"")
    (folder / "bad.sig").write_bytes(b"junk")
    catalog = libid.load(folder)
    assert any(lib.id == "acme" for lib in catalog.libraries)
    assert {f["file"] for f in catalog.files if "error" in f} == {"bad.sig"}
    report = libid.identify(b"\0Acme Sound v2.5\0", [], catalog)
    assert [(lib["name"], lib["version"]) for lib in report["libraries"]] == [("Acme Sound", "2.5")]


def test_find_libraries_sets_aside_a_hash_in_a_rom_project_and_agents_report_library(tmp_path, monkeypatch):
    """The engine: a ROM project's MD5 functions (by their bytes in the database) are set aside as library code and
    the report kept for the panel; an agent's report_library counts, and a second agent's sets the function aside."""
    from decompnet.app.engine import RomNetwork

    monkeypatch.setattr(libid, "signature_folder", lambda: tmp_path / "sigs")
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / "game.bin").write_bytes(b"\0 deflate 1.2.3 Copyright 1995-2005 Jean-loup Gailly \0")
    cfg = {"kind": "rom", "platform": "pc", "rom": {"file": "game.bin"}}
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                   ("demo", "demo", "", "x86", 0, str(root), json.dumps(cfg)))
        pid = db.execute("SELECT id FROM projects WHERE slug='demo'").fetchone()["id"]
        for i, (name, addr, code) in enumerate([("MD5Init", 0x1000, x86(*MD5_INIT)), ("MD5Update", 0x1080, x86(1)),
                                                ("MD5Transform", 0x1100, x86(*MD5_T)), ("game", 0x9000, x86(2)),
                                                ("rc5_decrypt", 0x9100, x86(3))]):
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,status,vram,meta,"
                       "attempts,abandons) VALUES(?,?,?,?,?,?,?,?,?,?,0,0)",
                       (pid, name, len(code), 4, code, "[]", "", "open", addr, "{}"))
    monkeypatch.setattr(RomNetwork, "is_rom", lambda self, proj: True)
    report = net.find_libraries("demo", log=lambda *_: None, fid=False)
    assert report["set_aside"] == 3
    status = {r["name"]: (r["status"], json.loads(r["meta"])) for r in net.store.all(
        "SELECT name, status, meta FROM functions WHERE project_id=?", pid)}
    assert {n for n, (s, _) in status.items() if s == "asm"} == {"MD5Init", "MD5Update", "MD5Transform"}
    assert status["MD5Transform"][1]["set_aside"].startswith("library code: MD5")
    found = net.libraries_found("demo")
    assert {lib["id"] for lib in found["libraries"]} == {"md5", "zlib"}
    assert next(lib for lib in found["libraries"] if lib["id"] == "zlib")["version"] == "1.2.3"

    a, b = (net.authenticate(net.register_agent(n)) for n in ("claude-sonnet-1", "codex-gpt-1"))
    said = net.report_library(a, "rc5_decrypt", "RC5 (RFC 2040)", "rotates by data, 12 rounds", "demo")
    assert "1 of 2" in said and net._function("rc5_decrypt", "demo")["status"] == "open"
    said = net.report_library(b, "rc5_decrypt", "RC5 (RFC 2040)", "RC5 decryption rounds", "demo")
    fn = net._function("rc5_decrypt", "demo")
    assert fn["status"] == "asm" and json.loads(fn["meta"])["library"] == "RC5 (RFC 2040)" and "set aside" in said


def test_relocation_names_read_as_their_source_names_them():
    assert libid.called("__imp____glutInitWithExit@12") == "__glutInitWithExit"
    assert libid.called("___glutCreateWindowWithExit") == "__glutCreateWindowWithExit"
    assert libid.called("_func_0049B730") == "func_0049B730"


def test_libraries_loaded_from_their_own_files_are_named_and_their_headers_wrappers_taken(tmp_path):
    """A 2005 PC game loads OpenGL, GLUT and OpenAL from their DLLs: nothing of them to write, but each is named, the
    decomp includes its headers. glut.h's own inline code (glutInit's exit wrapper, which calls __glutInitWithExit)
    is compiled into the game: that function is GLUT's. The import's thunk for __glutInitWithExit, named for it, is
    the linker's, and a DLL neither the catalog nor the system has is listed for the user to look up."""
    codes = [
        libid.Code(1, "_func_004604D0@8", 0x4604D0, x86(1), calls=frozenset({"__glutInitWithExit", "func_0049B730"})),
        libid.Code(2, "___glutInitWithExit", 0x4AF400, b"\xff\x25\0\0\0\0", calls=frozenset({"__glutInitWithExit"})),
        libid.Code(3, "_game", 0x401000, x86(2), calls=frozenset({"glutMainLoop"})),
    ]
    links = ["OPENGL32.dll", "glut32.dll", "OpenAL32.dll", "KERNEL32.dll", "WINMM.dll", "acmesound.dll"]
    report = libid.identify(None, codes, empty_catalog(tmp_path), arch="x86", links=links)
    by = {lib["id"]: lib for lib in report["libraries"]}
    assert {"opengl", "glut", "openal"} <= set(by) and all(by[k]["linked"] for k in ("opengl", "glut", "openal"))
    assert by["glut"]["keys"] == [1] and by["glut"]["aside"] and "it loads glut32.dll" in by["glut"]["evidence"]
    assert by["opengl"]["kind"] == "sdk" and not by["opengl"]["keys"]
    assert report["links"] == ["acmesound.dll"]


def test_a_linux_programs_libraries_are_read_from_its_dynamic_section():
    from decompnet import consoles

    sh = Path("/bin/sh")
    if not sh.is_file() or sh.read_bytes()[:4] != b"\x7fELF":
        pytest.skip("no ELF /bin/sh here")
    names = consoles.get("linux").linked_libraries(sh.read_bytes())
    assert any(n.startswith("libc.so") for n in names)
    assert consoles.get("linux").linked_libraries(b"not a program") == []


def test_a_pc_programs_dlls_are_read_from_its_imports():
    """A Windows program's import table names the DLLs it loads (Visual C++ 6.0's own cl.exe: Windows' kernel)."""
    from decompnet import consoles, toolchains

    where = toolchains.path("msvc") if toolchains.installed("msvc") else None
    exe = next(iter(sorted(where.glob("*/Bin/[Cc][Ll].[Ee][Xx][Ee]"))), None) if where else None
    if exe is None:
        pytest.skip("no Visual C++ installed (Setup)")
    names = [n.lower() for n in consoles.get("pc").linked_libraries(exe.read_bytes())]
    assert "kernel32.dll" in names
    assert consoles.get("pc").linked_libraries(b"MZ junk") == []


def test_a_libs_folder_is_a_librarys_by_its_name_as_released():
    from decompnet.app.engine.libraryid import _holds

    assert _holds("freealut-1.0.1", "alut") and _holds("openal-1.1-core-sdk-3.05", "openal")
    assert _holds("glut-3.7.6", "glut") and _holds("freeglut", "glut") and _holds("jpeg-6b", "libjpeg")
    assert _holds("zlib-1.1.3", "zlib") and _holds("lua5.1", "lua")
    assert not _holds("glut-3.7.6", "glu") and not _holds("openal-1.1", "alut")


def test_code_several_objects_of_a_kit_have_says_too_little_which_it_is(tmp_path):
    """A 2001 GameCube SDK's empty callbacks and getters (CARDProbe or GXSaveCPUFifo, in different objects) are the
    game's own code too: a function only some of one object's functions fit is theirs, one several objects' fit isn't."""
    body = bytes(range(0x20, 0x40))
    one = [libid.Signature("os.a", "", n, 32, body, b"\1" * 32, unit="OSThread.o")
           for n in ("OSInitMutexQueue", "OSInitThreadQueue")]
    other = libid.Signature("card.a", "", "CARDProbe", 32, body, b"\1" * 32, unit="CARDBios.o")
    game = libid.Code(1, "fn_803C0000", 0x803C0000, body)
    found = libid.identify(None, [game], libid.Catalog([], one, [], []))["libraries"]
    assert found[0]["keys"] == [1] and "OSInitMutexQueue or OSInitThreadQueue of os.a" in found[0]["functions"][0]["why"]
    assert libid.identify(None, [game], libid.Catalog([], [*one, other], [], []))["libraries"] == []


@pytest.mark.skipif(__import__("decompnet.toolchains", fromlist=["x"]).installed("gc-wii-binutils") is None,
                    reason="needs the GameCube binutils")
def test_a_gamecube_sdk_copy_is_a_kit_whose_functions_the_library_finder_matches(tmp_path, monkeypatch):
    """The user's GameCube SDK (kits/dolphin.py): its archives' functions, relocations left out, are signatures the
    library finder matches against the game's; one too short to say it's theirs (li, stw, stw, blr) is left out."""
    import subprocess

    from decompnet import consoles, kits, toolchains
    from decompnet.app.engine.libraryid import kit_names, kit_signatures, object_code

    bin_dir = toolchains.path("gc-wii-binutils")
    (tmp_path / "os.s").write_text("""
    .text
    .globl OSInitThreadQueue
    .type OSInitThreadQueue, @function
OSInitThreadQueue:
    li r0, 0
    stw r0, 0(r3)
    stw r0, 4(r3)
    blr
    .size OSInitThreadQueue, .-OSInitThreadQueue
    .globl OSReport
    .type OSReport, @function
OSReport:
    stwu r1, -0x70(r1)
    mflr r0
    stw r0, 0x74(r1)
    lis r3, msg@ha
    addi r3, r3, msg@l
    bl vprintf
    lwz r0, 0x74(r1)
    mtlr r0
    addi r1, r1, 0x70
    blr
    .size OSReport, .-OSReport
    .weak Hu_IsStub
    .type Hu_IsStub, @function
Hu_IsStub:
    li r3, 0
    blr
    .size Hu_IsStub, .-Hu_IsStub
    .type bitrev, @function
bitrev:
    blr
    .size bitrev, .-bitrev
""")
    lib = tmp_path / "Dolphin" / "HW2" / "lib"
    lib.mkdir(parents=True)
    subprocess.run([str(bin_dir / "powerpc-eabi-as"), "-mgekko", "-mregnames", "-o", str(tmp_path / "OS.o"),
                    str(tmp_path / "os.s")], check=True)
    subprocess.run([str(bin_dir / "powerpc-eabi-ar"), "rcs", str(lib / "os.a"), str(tmp_path / "OS.o")], check=True)
    monkeypatch.setenv("DECOMPNET_TOOLCHAINS", str(tmp_path / "toolchains"))
    assert "dolphin-sdk" in consoles.get("gc").kits and "dolphin-sdk" in consoles.get("wii").kits
    toolchains.install("dolphin-sdk", folder=tmp_path / "Dolphin", accept_license=True, log=lambda *_: None)
    assert kits.libraries(consoles.get("gc").kits) == [(lib / "os.a").resolve()]
    sigs = kit_signatures(kits.libraries(["dolphin-sdk"]))
    assert [(s.name, s.unit) for s in sigs] == [("OSReport", "OS.o")]
    # by names: what the archive exports, short ones and weak ones too, never a file's own static (`bitrev`)
    assert kit_names(kits.libraries(["dolphin-sdk"])) == {n: ("os.a", "OS.o, your own copy")
                                                          for n in ("OSInitThreadQueue", "OSReport", "Hu_IsStub")}
    raw, _, _ = object_code((tmp_path / "OS.o").read_bytes())["OSReport"]
    game = bytearray(raw)
    game[14:16] = b"\x80\x48"  # (the game's own address of its message: a relocated field)
    found = libid.identify(None, [libid.Code(5, "fn_803C1000", 0x803C1000, bytes(game))],
                           libid.Catalog([], sigs, [], []))["libraries"]
    assert found[0]["id"] == "os.a" and found[0]["aside"] and found[0]["keys"] == [5]
    assert "OSReport of os.a (OS.o, your own copy)" in found[0]["functions"][0]["why"]


def test_a_clone_of_a_game_started_from_scratch_sets_its_library_code_aside_and_commits_it(tmp_path):
    """A GameCube game decompdecomp started from scratch, cloned from its folder (another computer's copy) was taken
    for a public decomp: its 14 SDK libraries were found and none set aside (only a scratch project's are), and a
    try's leftover compiler was never put back. Its manifest says what it is; an older clone is fixed at start. The
    set-aside list is committed: config/ is the app's (an uncommitted change is a try's leftover, put back) and a
    room's members follow commits."""
    import subprocess as sp

    from decompnet.app.engine import RomNetwork

    repo = tmp_path / "theirs"
    (repo / "config" / "V").mkdir(parents=True)
    (repo / ".decomp.wtf.json").write_text(json.dumps({"created": "from scratch", "platform": "gc", "version": "V"}))
    (repo / "config" / "V" / "config.yml").write_text("name: V\n")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    sp.run(["git", "init", "-q", str(repo)], check=True)
    sp.run([*git, "-C", str(repo), "add", "-A"], check=True)
    sp.run([*git, "-C", str(repo), "commit", "-q", "-m", "first"], check=True)
    net = RomNetwork(tmp_path / "app.db", tmp_path / "home")
    slug = net.forks.clone(str(repo), name="Theirs", platform="gc", log=lambda *_: None)
    proj = net._project(slug)
    assert json.loads(proj["config"])["origin"] == "scratch"

    cfg = json.loads(proj["config"]) | {"origin": None}  # (cloned before the manifest was read)
    with net.store.tx() as db:
        db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,status,vram,meta,attempts,abandons,unit) "
                   "VALUES(?,?,?,?,?,?,?,0,0,?)", (proj["id"], "OSInitAlarm", 64, 16, "open", 0x80001000,
                                                   json.dumps({"symbol": "OSInitAlarm"}), "main/os"))
    net.forks.put_back_tries(slug, log=lambda *_: None)
    proj = net._project(slug)
    assert json.loads(proj["config"])["origin"] == "scratch"

    rows = {r["id"]: r for r in net.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"])}
    assert net._library_aside(proj, rows, {next(iter(rows)): "os.a's OSInitAlarm"}, {"name": "os.a"}) == 1
    root = Path(proj["root"])
    assert "OSInitAlarm" in json.loads((root / "config" / "V" / "set_aside.json").read_text())
    assert sp.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True).stdout == ""
    assert "os.a" in sp.run(["git", "-C", str(root), "log", "-1", "--format=%s"], capture_output=True, text=True).stdout


def test_a_function_named_as_the_users_libraries_export_is_theirs_in_another_version_too(tmp_path, monkeypatch):
    """A GameCube game's SDK came between the user's 2001 and 2004 copies: a dozen CARD functions had other bytes in
    each and agents spent hours on them. A function by a name the copies export is that library's; one whose code is
    in several objects (the CARD wrappers, byte for byte the same) is the one its name says."""
    monkeypatch.setattr(libid, "signature_folder", lambda: tmp_path / "sigs")
    wrapper = bytes(range(1, 33))
    sigs = [libid.Signature("card.a", "", n, 32, wrapper, b"\1" * 32, origin=f"{n}.o, your own copy", unit=f"{n}.o")
            for n in ("CARDRead", "CARDWrite")]
    codes = [libid.Code(1, "CARDRead", 0x100, wrapper), libid.Code(2, "__CARDEraseSector", 0x200, bytes(32)),
             libid.Code(3, "Game_Run", 0x300, bytes(range(40, 72)))]
    named = {"__CARDEraseSector": ("card.a", "CARDBios.o, your own copy"), "CARDRead": ("card.a", "CARDRead.o")}

    def card(named):
        catalog = libid.load()
        catalog.signatures += sigs
        report = libid.identify(None, codes, catalog, arch="ppc", big_endian=True, named=named)
        lib = next((x for x in report["libraries"] if x["id"] == "card.a"), {"functions": []})
        return {f["name"]: f["why"] for f in lib["functions"]}

    found = card(named)
    assert set(found) == {"CARDRead", "__CARDEraseSector"}
    assert "your own copy" in found["CARDRead"] and "by its name" not in found["CARDRead"]  # (its code said so)
    assert "by its name" in found["__CARDEraseSector"]
    assert set(card(None)) == {"CARDRead"}  # by code alone


def test_going_by_names_is_the_projects_choice_and_off_gives_them_back(tmp_path):
    """Off: what names set aside is open to agents again, out of the project's committed set-aside list too."""
    import subprocess as sp

    from decompnet.app.engine import RomNetwork
    from decompnet.app.engine.libraryid import BY_NAME, LIBRARY_WHY

    repo = tmp_path / "theirs"
    (repo / "config" / "V").mkdir(parents=True)
    (repo / ".decomp.wtf.json").write_text(json.dumps({"created": "from scratch", "platform": "gc", "version": "V"}))
    why = LIBRARY_WHY.format(why=f"__CARDEraseSector of card.a {BY_NAME}CARDBios.o, your own copy); another version")
    (repo / "config" / "V" / "set_aside.json").write_text(json.dumps({"__CARDEraseSector": why, "OSInit": "os.a"}))
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    sp.run(["git", "init", "-q", str(repo)], check=True)
    sp.run([*git, "-C", str(repo), "add", "-A"], check=True)
    sp.run([*git, "-C", str(repo), "commit", "-q", "-m", "first"], check=True)
    net = RomNetwork(tmp_path / "app.db", tmp_path / "home")
    slug = net.forks.clone(str(repo), name="Theirs", platform="gc", log=lambda *_: None)
    proj = net._project(slug)
    with net.store.tx() as db:
        for name, text in (("__CARDEraseSector", why), ("OSInit", LIBRARY_WHY.format(why="OSInit of os.a"))):
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,status,vram,meta,attempts,abandons,unit) "
                       "VALUES(?,?,?,?,?,?,?,0,0,?)", (proj["id"], name, 64, 16, "asm", 0x80001000,
                                                       json.dumps({"symbol": name, "asm_code": text}), "main/x"))
    assert net.libraries_found(slug)["names"] is True  # (on unless the project says otherwise)
    assert net.set_library_names(slug, False) == 1
    assert net.libraries_found(slug)["names"] is False
    status = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")}
    assert status == {"__CARDEraseSector": "open", "OSInit": "asm"}  # (what its code found stays)
    root = Path(proj["root"])
    assert set(json.loads((root / "config" / "V" / "set_aside.json").read_text())) == {"OSInit"}
    assert sp.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True).stdout == ""


@pytest.mark.skipif(__import__("decompnet.toolchains", fromlist=["x"]).installed("binutils-mips") is None,
                    reason="needs the PS2 binutils")
def test_a_ps2_sdk_copy_is_a_kit_whose_ee_libraries_the_library_finder_reads(tmp_path, monkeypatch):
    """Sony's PS2 libraries, the user's own copy (kits/ps2sdk.py): the EE's archives give the library finder their
    functions, by code and by name; the IOP's (another processor's) are left out. A C++ game said in its own text it
    was built with SDK 3.1.0, and agents had been working on its library code."""
    import subprocess

    from decompnet import consoles, kits, toolchains
    from decompnet.app.engine.libraryid import kit_names, kit_signatures

    bin_dir = toolchains.path("binutils-mips")
    (tmp_path / "pad.s").write_text("""
    .set noreorder
    .text
    .globl scePadRead
    .type scePadRead, @function
scePadRead:
    lui $2, %hi(pad_state)
    lw $2, %lo(pad_state)($2)
    addiu $sp, $sp, -16
    sd $31, 0($sp)
    daddu $4, $2, $0
    ld $31, 0($sp)
    jr $31
    addiu $sp, $sp, 16
    .size scePadRead, .-scePadRead
""")
    ee, iop = tmp_path / "sdk" / "sce" / "ee" / "lib", tmp_path / "sdk" / "sce" / "iop" / "lib"
    ee.mkdir(parents=True)
    iop.mkdir(parents=True)
    obj = tmp_path / "pad.o"
    subprocess.run([str(bin_dir / "mips-ps2-decompals-as"), "-EL", "-march=r5900", "-mabi=eabi", "-o", str(obj),
                    str(tmp_path / "pad.s")], check=True)
    for lib in (ee / "libpad.a", iop / "libpad.a"):
        subprocess.run([str(bin_dir / "mips-ps2-decompals-ar"), "rcs", str(lib), str(obj)], check=True)
    monkeypatch.setenv("DECOMPNET_TOOLCHAINS", str(tmp_path / "toolchains"))
    assert "ps2-sdk" in consoles.get("ps2").kits
    toolchains.install("ps2-sdk", folder=tmp_path / "sdk", accept_license=True, log=lambda *_: None)
    assert kits.libraries(consoles.get("ps2").kits) == [(ee / "libpad.a").resolve()]
    sigs = kit_signatures(kits.libraries(["ps2-sdk"]))
    assert [(s.name, s.library, s.unit) for s in sigs] == [("scePadRead", "libpad.a", "pad.o")]
    assert kit_names(kits.libraries(["ps2-sdk"])) == {"scePadRead": ("libpad.a", "pad.o, your own copy")}


def test_a_stripped_games_library_functions_get_their_librarys_names(tmp_path, monkeypatch):
    """A PS2 game of 3,223 functions, stripped, had 195 of Sony's functions: set aside, they were still called from
    everywhere as func_00..., and agents read those calls in every brief. Find libraries names what its code says,
    from an automatic name only, never a name another function has."""
    from decompnet import kits
    from decompnet.app.engine import RomNetwork, libraryid

    monkeypatch.setattr(libid, "signature_folder", lambda: tmp_path / "sigs")
    pad, mc, own = x86(*MD5_INIT), x86(*MD5_T), x86(7)
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / "game.bin").write_bytes(b"\0")
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                         ("demo", "demo", "", "x86", 0, str(root), json.dumps({"kind": "rom", "platform": "pc",
                                                                             "rom": {"file": "game.bin"}}))).lastrowid
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,1,'void func_00009100(void);',NULL,'',0,'')", (pid,))
        for name, addr, code in (("func_00009000", 0x9000, pad), ("func_00009100", 0x9100, mc),
                                 ("Game_Pad", 0x9200, pad), ("func_00009300", 0x9300, own)):
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,status,vram,meta,"
                       "attempts,abandons) VALUES(?,?,?,?,?,?,?,?,?,?,0,0)",
                       (pid, name, len(code), 4, code, "[]", "", "open", addr, "{}"))
            db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                       (pid, name, addr, len(code), "func"))
    sig = lambda name, code, unit: libid.Signature("libpad.a", "", name, len(code), code, b"\1" * len(code),  # noqa: E731
                                                   origin=f"{unit}, your own copy", unit=unit)
    monkeypatch.setattr(kits, "libraries", lambda kids: [tmp_path / "libpad.a"])
    monkeypatch.setattr(libraryid, "kit_signatures", lambda archives: [sig("scePadRead", pad, "pad.o"),
                                                                     sig("sceMcOpen", mc, "mc.o")])
    monkeypatch.setattr(libraryid, "kit_names", lambda archives: {})
    monkeypatch.setattr(RomNetwork, "is_rom", lambda self, proj: True)
    report = net.find_libraries("demo", log=lambda *_: None, fid=False)
    names = {r["vram"]: (r["name"], r["status"]) for r in net.store.all("SELECT * FROM functions WHERE project_id=?", pid)}
    assert names[0x9100] == ("sceMcOpen", "asm") and report["named"] == 1
    # (two of the game's functions are scePadRead's code: neither takes the name, and a real name stays)
    assert names[0x9000][0] == "func_00009000" and names[0x9200][0] == "Game_Pad"
    assert names[0x9300] == ("func_00009300", "open")
    found = net.libraries_found("demo")
    assert any(f["name"] == "sceMcOpen" and f.get("real") == "sceMcOpen" for lib in found["libraries"]
               for f in lib["functions"])


# ---------------------------------------------------------------------------------------------- CodeWarrior's own

_PLAIN = struct.pack(">4I", 0x9421FFF0, 0x7C0802A6, 0x38210010, 0x4E800020)  # (no constant of anyone's)


def _gamecube_runtime() -> list[libid.Code]:
    """A stripped GameCube game's runtime stretch as dtk names it: the runtime, MSL, MetroTRK and the SDK, one after
    the other, a few of each named by dtk's analysis and the rest fn_<address>."""
    layout = [
        ("Game_Update", _PLAIN), ("strlen", _PLAIN),  # the game's own: a strlen of its own too, far from MSL's
        *[(f"fn_8000{i:04X}", _PLAIN) for i in range(12)],
        ("__va_arg", _PLAIN), ("fn_803AD1C8", _PLAIN), ("__save_gpr", _PLAIN), ("fn_803ADCA4", _PLAIN),
        ("__register_fragment", _PLAIN), ("fn_803AF878", _PLAIN),  # (runtime or MSL: the seam, left alone)
        ("exit", _PLAIN), ("fn_803AFA2C", _PLAIN), ("__close_all", _PLAIN), ("fn_803B0094", _PLAIN),
        ("longlong2str_803B6218", _PLAIN),  # (dtk keeps a static function's name with its address)
        ("fn_803B6C88", _PLAIN), ("fwide", _PLAIN), ("fn_803B9A0C", _PLAIN),
        ("fn_803BA210", struct.pack(">4I", 0x3C604086, 0x38632E42, 0x3C803FD6, 0x38842E42)),  # e_exp's, lis/addi
        ("fn_803BB3B0", struct.pack(">4I", 0x3C603FE9, 0x386321FB, 0x3C804002, 0x3884D97C)),  # e_rem_pio2's
        ("fn_803BCCD0", struct.pack(">2I", 0x3C603FE9, 0x386321FB)),  # pi/4 alone, beside MSL's own
        ("fn_803BD388", _PLAIN),  # (MSL or MetroTRK: the seam)
        ("TRKNubMainLoop", _PLAIN), ("fn_803BD74C", _PLAIN), ("TRKDoWriteMemory", _PLAIN),
        *[(f"fn_803BE{i:03X}", _PLAIN) for i in range(20)],  # (msghndlr's, between two of its own)
        ("TRKInterruptHandler", _PLAIN), ("MWTRACE", _PLAIN), ("fn_803C32C4", _PLAIN),
        ("PPCMfmsr", _PLAIN), ("TRKGetLength", _PLAIN),  # the SDK's, and a racing game's own for its tracks
        ("fn_80469000", struct.pack(">2I", 0x3C603FE9, 0x386321FB)),  # the game's own pi/4, far from MSL
    ]
    return [libid.Code(i, name, 0x80300000 + 0x100 * i, raw) for i, (name, raw) in enumerate(layout)]


def test_codewarriors_own_libraries_are_found_by_their_names_in_a_gamecube_game(tmp_path):
    """MSL, MetroTRK and CodeWarrior's runtime in a GameCube game: no one may publish their code, so their names (the
    game's symbols, dtk's analysis) say which functions are theirs, each library linked whole, so what's between two
    of its own is its too. The seams between two libraries, and every function of the game's (a strlen of its own,
    a TRKGetLength for its tracks, a pi/4 of its own), stay open. MSL's math is fdlibm's: its high-word constants."""
    from decompnet import consoles

    catalog = libid.load(tmp_path / "none", console=consoles.get("gc").library_catalog())
    text = b"\0MetroTRK for GAMECUBE v2.0\0" + b"542101086242752217003726400434970855712890625\0"
    codes = _gamecube_runtime()
    report = libid.identify(text, codes, catalog, arch="ppc", big_endian=True)
    found = {lib["id"]: lib for lib in report["libraries"]}
    names = {lib: {f["name"] for f in found[lib]["functions"]} for lib in found}
    key = {c.name: c.key for c in codes}

    def run(first: str, last: str) -> set[str]:
        return {c.name for c in codes if key[first] <= c.key <= key[last]}
    assert names["mw-runtime"] == run("__va_arg", "__register_fragment")
    assert names["msl"] == run("exit", "fn_803BCCD0")
    assert names["metrotrk"] == run("TRKNubMainLoop", "MWTRACE")
    taken = set().union(*names.values())
    for own in ("Game_Update", "strlen", "fn_803AF878", "fn_803BD388", "fn_803C32C4", "PPCMfmsr", "TRKGetLength",
                "fn_80469000"):
        assert own not in taken
    assert found["metrotrk"]["version"] == "2.0"
    assert all(found[lib]["aside"] and found[lib]["kind"] == "runtime" for lib in ("mw-runtime", "msl", "metrotrk"))
    why = {f["name"]: f["why"] for lib in found.values() for f in lib["functions"]}
    assert "longlong2str, a function only it has" in why["longlong2str_803B6218"]
    assert "between two of its own functions (TRKDoWriteMemory, TRKInterruptHandler)" in why["fn_803BE000"]
    assert "constants" in why["fn_803BA210"] and "beside its own code" in why["fn_803BCCD0"]


def test_only_codewarriors_consoles_have_its_libraries(tmp_path):
    """A PS2 game's memcpy and __save_gpr aren't MSL's: CodeWarrior's libraries are the GameCube's and the Wii's
    catalog, not the one every console reads."""
    from decompnet import consoles

    assert {lib.id for lib in consoles.get("wii").library_catalog()} == {"mw-runtime", "msl", "metrotrk"}
    for other in ("ps2", "n64", "pc"):
        assert consoles.get(other).library_catalog() == []
    report = libid.identify(None, _gamecube_runtime(), libid.load(tmp_path / "none"), arch="ppc", big_endian=True)
    assert not {lib["id"] for lib in report["libraries"]} & {"mw-runtime", "msl", "metrotrk"}


def test_find_libraries_sets_metrotrk_aside_in_a_gamecube_project_by_where_its_functions_are(tmp_path, monkeypatch):
    """A dtk project's functions have no address in their names (TRKNubMainLoop): where they are is the row's, from
    objdiff's report. Without it nothing was between two of MetroTRK's own and only the named were set aside; with
    it the ones between are too, into the project's set_aside.json."""
    import subprocess as sp

    from decompnet import kits
    from decompnet.app.engine import RomNetwork, libraryid
    from decompnet.forks import project

    repo = tmp_path / "theirs"
    (repo / "config" / "V").mkdir(parents=True)
    (repo / ".decomp.wtf.json").write_text(json.dumps({"created": "from scratch", "platform": "gc", "version": "V"}))
    (repo / "config" / "V" / "config.yml").write_text("name: V\n")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    sp.run(["git", "init", "-q", str(repo)], check=True)
    sp.run([*git, "-C", str(repo), "add", "-A"], check=True)
    sp.run([*git, "-C", str(repo), "commit", "-q", "-m", "first"], check=True)
    net = RomNetwork(tmp_path / "app.db", tmp_path / "home")
    slug = net.forks.clone(str(repo), name="Theirs", platform="gc", log=lambda *_: None)
    proj = net._project(slug)
    layout = [("Game_Update", 0x803BD000), ("TRKNubMainLoop", 0x803BD630), ("fn_803BD74C", 0x803BD74C),
              ("fn_803BD764", 0x803BD764), ("TRKDoWriteMemory", 0x803BD844), ("fn_803BD900", 0x803BD900)]
    with net.store.tx() as db:
        for name, vram in layout:
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,status,vram,meta,attempts,abandons,unit) "
                       "VALUES(?,?,?,?,?,?,?,0,0,?)", (proj["id"], name, 16, 4, "open", vram,
                                                       json.dumps({"symbol": name}), "main/auto/text_803AF810"))
    target = tmp_path / "text.o"
    target.write_bytes(b"")
    monkeypatch.setattr(project.ForkProject, "unit", lambda self, name: type("U", (), {"target": target})())
    monkeypatch.setattr(libraryid, "object_code", lambda data: {n: (_PLAIN, frozenset(), frozenset()) for n, _ in layout})
    monkeypatch.setattr(kits, "libraries", lambda kids: [])
    monkeypatch.setattr(libid, "signature_folder", lambda: tmp_path / "sigs")

    codes, _ = net._library_codes(proj)
    assert {c.name: c.addr for c in codes} == dict(layout)
    report = net.find_libraries(slug, log=lambda *_: None, fid=False)
    trk = next(lib for lib in report["libraries"] if lib["id"] == "metrotrk")
    assert {f["name"] for f in trk["functions"]} == {"TRKNubMainLoop", "fn_803BD74C", "fn_803BD764", "TRKDoWriteMemory"}
    status = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions")}
    assert status["fn_803BD764"] == "asm" and status["Game_Update"] == status["fn_803BD900"] == "open"
    aside = json.loads((Path(proj["root"]) / "config" / "V" / "set_aside.json").read_text())
    assert "fn_803BD74C" in aside and "MetroTRK" in aside["fn_803BD74C"]
