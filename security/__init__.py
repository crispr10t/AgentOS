"""AgentOS Security and Protection Layer.

Provides canonical sandbox path verification and dual-mode privilege ring gating.
"""

from security.privilege import PrivilegeGate, PrivilegeViolation
from security.sandbox import (
    PathSecurityViolation,
    ensure_sandbox_root,
    get_sandbox_root,
    is_safe_path,
    validate_safe_path,
)

__all__ = [
    "PrivilegeGate",
    "PrivilegeViolation",
    "PathSecurityViolation",
    "ensure_sandbox_root",
    "get_sandbox_root",
    "is_safe_path",
    "validate_safe_path",
]
