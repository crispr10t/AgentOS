"""Comprehensive edge-case tests for security/sandbox.py: Canonical Sandbox Jail, Path Traversal, and Sanitization."""

from pathlib import Path
import os
import pytest

from security.sandbox import (
    PathSecurityViolation,
    ensure_sandbox_root,
    get_sandbox_root,
    is_safe_path,
    validate_safe_path,
)


@pytest.fixture
def isolated_sandbox(tmp_path: Path) -> Path:
    """Fixture providing a fresh isolated sandbox root directory."""
    sandbox = tmp_path / "jail_root"
    sandbox.mkdir(parents=True, exist_ok=True)
    return sandbox


# --- 1. Path Traversal Attacks (Exhaustive Vectors) ---

@pytest.mark.parametrize("traversal_vector", [
    "../secret.txt",
    "..\\secret.txt",
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "foo/../../outside.txt",
    "foo/bar/../../../outside.txt",
    "a/b/c/../../../../escape",
    "./../../root",
    "sub/../../..",
    "nested/deep/../../../../../../etc/shadow",
])
def test_sandbox_path_traversal_blocked(isolated_sandbox: Path, traversal_vector: str):
    """Verify various directory traversal attack vectors are reliably blocked."""
    with pytest.raises(PathSecurityViolation, match="Path traversal detected"):
        validate_safe_path(traversal_vector, allowed_root=isolated_sandbox)

    # is_safe_path must return False without raising
    assert is_safe_path(traversal_vector, allowed_root=isolated_sandbox) is False


@pytest.mark.parametrize("external_absolute", [
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Program Files",
    "D:\\OtherFolder\\secret.doc",
    "/etc/passwd",
    "/var/log/syslog",
    "/usr/bin/bash",
])
def test_sandbox_external_absolute_paths_blocked(isolated_sandbox: Path, external_absolute: str):
    """Verify absolute paths outside the sandbox root are blocked."""
    with pytest.raises(PathSecurityViolation, match="Path traversal detected"):
        validate_safe_path(external_absolute, allowed_root=isolated_sandbox)

    assert is_safe_path(external_absolute, allowed_root=isolated_sandbox) is False


# --- 2. Legitimate Paths Inside Sandbox ---

@pytest.mark.parametrize("valid_relative", [
    "file.txt",
    "./file.txt",
    "subdir/nested.py",
    "a/b/c/deep/file.json",
    "with space/another file (1).txt",
    "hyphen-name/under_score/dot.file.tar.gz",
    "foo/../foo/file.txt",  # Traversal that stays inside
    "a/b/../../a/b/file.txt",
])
def test_sandbox_valid_paths_resolved(isolated_sandbox: Path, valid_relative: str):
    """Verify legitimate paths inside the sandbox resolve accurately."""
    resolved = validate_safe_path(valid_relative, allowed_root=isolated_sandbox)
    assert resolved.is_relative_to(isolated_sandbox)
    assert is_safe_path(valid_relative, allowed_root=isolated_sandbox) is True


def test_sandbox_root_itself_is_safe(isolated_sandbox: Path):
    """Querying the root directory itself should resolve to root."""
    assert validate_safe_path(".", allowed_root=isolated_sandbox) == isolated_sandbox
    assert validate_safe_path("", allowed_root=isolated_sandbox) == isolated_sandbox
    assert is_safe_path(".", allowed_root=isolated_sandbox) is True
    assert is_safe_path("", allowed_root=isolated_sandbox) is True


def test_sandbox_absolute_path_inside_root(isolated_sandbox: Path):
    """Absolute paths that point inside the sandbox root must be permitted."""
    internal_file = isolated_sandbox / "sub" / "valid.txt"
    resolved = validate_safe_path(internal_file, allowed_root=isolated_sandbox)
    assert resolved == internal_file.resolve()
    assert is_safe_path(internal_file, allowed_root=isolated_sandbox) is True


# --- 3. Directory Creation and Environment Invariants ---

def test_ensure_sandbox_root_idempotent(tmp_path: Path):
    """ensure_sandbox_root should be safely callable multiple times."""
    target_dir = tmp_path / "ensure_dir"
    assert not target_dir.exists()

    res1 = ensure_sandbox_root(target_dir)
    assert target_dir.exists()
    assert res1 == target_dir.resolve()

    res2 = ensure_sandbox_root(target_dir)
    assert res2 == res1


def test_get_sandbox_root_env_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Verify get_sandbox_root reads SANDBOX_ROOT environment variable when omitted."""
    custom_root = tmp_path / "env_sandbox"
    monkeypatch.setenv("SANDBOX_ROOT", str(custom_root))

    resolved = get_sandbox_root()
    assert resolved == custom_root.resolve()
