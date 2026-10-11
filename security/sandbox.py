"""Canonical Sandbox Jail and Path Validation.

Enforces directory containment so that all file operations are confined
strictly within the configured SANDBOX_ROOT. Prevents path traversal (e.g. '../'),
absolute path escapes, and symlink breakouts.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


class PathSecurityViolation(PermissionError):
    """Raised when an operation attempts to access paths outside the sandbox jail."""

    pass


def get_sandbox_root(default_root: Optional[Path | str] = None) -> Path:
    """Returns the canonical absolute path of the sandbox root directory.

    Args:
        default_root: Optional explicit root directory path. If None, reads from
            the SANDBOX_ROOT environment variable (default: './sandbox_workspace').

    Returns:
        Canonical absolute Path to the sandbox directory.
    """
    if default_root is not None:
        root_path = Path(default_root)
    else:
        env_root = os.getenv("SANDBOX_ROOT", "./sandbox_workspace")
        root_path = Path(env_root)

    return root_path.resolve()


def ensure_sandbox_root(root: Optional[Path | str] = None) -> Path:
    """Ensures that the sandbox root directory exists on disk and returns its path.

    Args:
        root: Optional explicit root directory path.

    Returns:
        Canonical absolute Path to the existing sandbox directory.
    """
    sandbox_dir = get_sandbox_root(root)
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    return sandbox_dir


def validate_safe_path(
    target_path: Path | str,
    allowed_root: Optional[Path | str] = None,
) -> Path:
    """Validates that target_path resides safely within allowed_root.

    Resolves canonical absolute paths, expands user home paths, and verifies
    that the target path does not escape the sandbox boundary via '..' components
    or symlink redirection.

    Args:
        target_path: File or directory path to validate. Can be relative or absolute.
        allowed_root: The boundary root. Defaults to the configured sandbox root.

    Returns:
        Resolved canonical absolute Path.

    Raises:
        PathSecurityViolation: If the resolved path lies outside allowed_root.
    """
    root = get_sandbox_root(allowed_root)
    raw_path = Path(target_path).expanduser()

    if raw_path.is_absolute():
        resolved_path = raw_path.resolve()
    else:
        # Relative paths are anchored to the sandbox root
        resolved_path = (root / raw_path).resolve()

    try:
        resolved_path.relative_to(root)
    except ValueError:
        raise PathSecurityViolation(
            f"Path traversal detected: '{target_path}' resolves to '{resolved_path}', "
            f"which is outside the authorized sandbox root '{root}'."
        )

    return resolved_path


def is_safe_path(
    target_path: Path | str,
    allowed_root: Optional[Path | str] = None,
) -> bool:
    """Checks whether target_path is within allowed_root without raising an exception.

    Args:
        target_path: Path to verify.
        allowed_root: The boundary root.

    Returns:
        True if the path is safely inside allowed_root, False otherwise.
    """
    try:
        validate_safe_path(target_path, allowed_root)
        return True
    except (PathSecurityViolation, ValueError):
        return False
