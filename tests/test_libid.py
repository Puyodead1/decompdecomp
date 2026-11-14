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
