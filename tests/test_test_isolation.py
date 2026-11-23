"""The test run itself keeps off the user's own setup (tests/conftest.py)."""

import shutil
import subprocess

import pytest


@pytest.mark.skipif(not shutil.which("git"), reason="git isn't installed")
def test_no_commit_a_test_makes_is_signed(tmp_path):
    """A user with commit.gpgsign had every test's commit wait on a passphrase prompt, and the run hung behind it."""
    for key in ("commit.gpgsign", "tag.gpgsign"):
        got = subprocess.run(["git", "config", "--get", key], cwd=tmp_path, capture_output=True, text=True).stdout
        assert got.strip() == "false"
