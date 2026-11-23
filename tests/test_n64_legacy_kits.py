"""Unpublished N64 compiler builds are usable from the owner's folder without downloading or copying them."""

from pathlib import Path

import pytest

from decompnet import kits, toolchains
from decompnet.consoles.n64 import N64
from decompnet.project import compiler_config

PROFILES = ('sn-n64-281', 'sn-n64-272-0004', 'ido-5.2', 'ido-5.3-cxx', 'ido-6.0', 'mipspro-7.4.4')


@pytest.mark.parametrize('profile', PROFILES)
def test_unpublished_profile_requires_the_users_own_kit(tmp_path, monkeypatch, profile):
    monkeypatch.setenv('DECOMPNET_TOOLCHAINS', str(tmp_path / 'toolchains'))
    monkeypatch.setattr(toolchains, 'current_platform', lambda: 'linux-x86_64')
    monkeypatch.setattr(toolchains.wsl, 'wanted', lambda: False)
    kit = kits.get('own-' + profile)
    tc = toolchains.get(profile)
    assert tc.kind == 'compiler' and tc.parts == [] and not tc.supported
    assert tc.source == 'your own compiler kit: no download'
    assert profile not in {c.id for c in N64.compilers}
    assert kit.id in N64.kits and toolchains.get(kit.id).local

    folder = tmp_path / profile
    for rel in kit.files:
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((profile + rel).encode())
    compiler = next(c for c in kit.compilers(folder) if c.like == profile)
    assert compiler.root == folder.resolve()
    assert 'unverified' in kit.build(folder)
    assert "doesn't know" in kit.verify(folder)
    with pytest.raises(toolchains.ToolchainError, match='accept'):
        toolchains.install(kit.id, folder=folder, log=lambda *_: None)
    toolchains.install(kit.id, folder=folder, accept_license=True, log=lambda *_: None)
    assert compiler.version in {c.id for c in N64.compilers}
    assert kits.own_compiler(compiler.version) == compiler
    assert toolchains.declared_family(compiler.version) == tc.family
    assert not (tmp_path / 'toolchains' / kit.id / Path(kit.program)).exists()

    # Resolving the matching command keeps the user's folder as {tc}; only free runtime tools are pinned.
    monkeypatch.setattr(toolchains, 'require', lambda dep, linux=None: tmp_path / 'free-tools' / dep)
    cfg = compiler_config(tmp_path, {'compiler': {'toolchain': compiler.version}})
    assert str(folder) in ' '.join(cfg.cmd)
    assert str(folder.resolve()) in cfg.ro_paths


def test_incomplete_or_wrong_host_kit_is_not_offered(tmp_path, monkeypatch):
    kit = kits.get('own-ido-5.3-cxx')
    for rel in kit.files[:-1]:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
    monkeypatch.setattr(toolchains, 'current_platform', lambda: 'linux-x86_64')
    assert kit.locate(tmp_path) is None  # C++ frontend is required, not merely the C driver
    (tmp_path / kit.files[-1]).touch()
    assert kit.compilers(tmp_path)
    monkeypatch.setattr(toolchains, 'current_platform', lambda: 'macos-arm64')
    assert kit.compilers(tmp_path) == []  # IRIX emulator profile is Linux x86_64 only


@pytest.mark.parametrize('host,unavailable', [
    ('windows-x86_64', PROFILES),  # (no kit's command runs on Windows yet: neither the IRIX emulator nor SN's)
    ('macos-arm64', ('ido-5.2', 'ido-5.3-cxx', 'ido-6.0', 'mipspro-7.4.4')),
])
def test_a_kit_for_another_computer_says_so_and_takes_no_folder(tmp_path, monkeypatch, host, unavailable):
    """On Windows the SGI and SN kits' cards read like any kit's, and Setup then said the folder didn't look like
    the compiler (it offered none there). The card says it's not available on this computer, and giving a folder
    says which computers it runs on."""
    monkeypatch.setenv('DECOMPNET_TOOLCHAINS', str(tmp_path / 'toolchains'))
    monkeypatch.setattr(toolchains, 'current_platform', lambda: host)
    rows = {r['id']: r for r in toolchains.status()}
    for profile in PROFILES:
        kit = kits.get('own-' + profile)
        folder = tmp_path / profile
        for rel in kit.files:
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_bytes(rel.encode())
        if profile not in unavailable:
            assert rows[kit.id]['supported'] and kit.compilers(folder)
            continue
        assert not rows[kit.id]['supported'] and kit.compilers(folder) == []
        with pytest.raises(toolchains.ToolchainError, match=rf"doesn't run on this computer \({host}\).*linux-x86_64"):
            toolchains.install(kit.id, folder=folder, accept_license=True, log=lambda *_: None)
        assert toolchains.installed(kit.id) is None
