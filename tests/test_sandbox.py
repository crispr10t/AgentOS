"""Tests for security/sandbox.py: Canonical Sandbox Jail and Path Validation."""

from pathlib import Path
import pytest

from security.sandbox import (
    PathSecurityViolation,
    ensure_sandbox_root,
    get_sandbox_root,
    is_safe_path,
    validate_safe_path,
)


@pytest.fixture
def temp_sandbox(tmp_path: Path) -> Path:
    """Fixture providing an isolated sandbox directory for testing."""
    sandbox = tmp_path / "sandbox_jail"
    sandbox.mkdir(parents=True, exist_ok=True)
    return sandbox


def test_ensure_sandbox_root_creates_directory(tmp_path: Path):
    """Verify that ensure_sandbox_root creates directory on disk."""
    target = tmp_path / "new_sandbox"
    assert not target.exists()
    ensured = ensure_sandbox_root(target)
    assert ensured.exists()
    assert ensured.is_dir()
    assert ensured == target.resolve()


def test_validate_safe_path_relative_inside(temp_sandbox: Path):
    """Verify relative paths within sandbox resolve correctly."""
    safe = validate_safe_path("docs/report.txt", allowed_root=temp_sandbox)
    assert safe == (temp_sandbox / "docs" / "report.txt").resolve()
    assert is_safe_path("docs/report.txt", allowed_root=temp_sandbox) is True


def test_validate_safe_path_absolute_inside(temp_sandbox: Path):
    """Verify absolute paths inside sandbox resolve correctly."""
    inside = (temp_sandbox / "sub" / "file.py").resolve()
    safe = validate_safe_path(inside, allowed_root=temp_sandbox)
    assert safe == inside
    assert is_safe_path(inside, allowed_root=temp_sandbox) is True


def test_validate_safe_path_directory_traversal_blocked(temp_sandbox: Path):
    """Verify that '../' path traversal outside sandbox raises PathSecurityViolation."""
    with pytest.raises(PathSecurityViolation) as exc_info:
        validate_safe_path("../outside.txt", allowed_root=temp_sandbox)

    assert "Path traversal detected" in str(exc_info.value)
    assert is_safe_path("../outside.txt", allowed_root=temp_sandbox) is False


def test_validate_safe_path_deep_traversal_blocked(temp_sandbox: Path):
    """Verify that nested '../../../../etc/passwd' or similar is blocked."""
    with pytest.raises(PathSecurityViolation):
        validate_safe_path("sub/../../../../escaped.txt", allowed_root=temp_sandbox)

    assert is_safe_path("sub/../../../../escaped.txt", allowed_root=temp_sandbox) is False


def test_validate_safe_path_external_absolute_path_blocked(temp_sandbox: Path, tmp_path: Path):
    """Verify that absolute paths pointing to external directories are blocked."""
    external_dir = tmp_path / "outside_jail"
    external_dir.mkdir(parents=True, exist_ok=True)
    external_file = external_dir / "secret.key"

    with pytest.raises(PathSecurityViolation):
        validate_safe_path(external_file, allowed_root=temp_sandbox)

    assert is_safe_path(external_file, allowed_root=temp_sandbox) is False


def test_validate_safe_path_root_itself_is_safe(temp_sandbox: Path):
    """Verify that querying the sandbox root itself is valid."""
    safe = validate_safe_path(".", allowed_root=temp_sandbox)
    assert safe == temp_sandbox.resolve()
