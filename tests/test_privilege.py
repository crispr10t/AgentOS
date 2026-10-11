"""Tests for security/privilege.py: Dual-Mode Privilege Ring and Security Gate."""

import pytest

from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallType
from security.privilege import PrivilegeGate, PrivilegeViolation


def test_privilege_classification():
    """Verify default ring classification for all syscall types."""
    gate = PrivilegeGate()
    assert gate.classify(SyscallType.FILE_SEARCH) == PrivilegeRing.RING_3
    assert gate.classify(SyscallType.FILE_READ) == PrivilegeRing.RING_3
    assert gate.classify(SyscallType.SYS_INFO) == PrivilegeRing.RING_3

    assert gate.classify(SyscallType.PROC_SPAWN) == PrivilegeRing.RING_0
    assert gate.classify(SyscallType.PROC_KILL) == PrivilegeRing.RING_0
    assert gate.classify(SyscallType.FILE_WRITE) == PrivilegeRing.RING_0
    assert gate.classify(SyscallType.FILE_MOVE) == PrivilegeRing.RING_0
    assert gate.classify(SyscallType.FILE_DELETE) == PrivilegeRing.RING_0


def test_ring3_requires_no_elevation():
    """Verify that Ring 3 operations do not require elevation."""
    gate = PrivilegeGate(enable_ring0_prompt=True)
    req = SyscallRequest(syscall=SyscallType.FILE_READ, params={"path": "a.txt"})
    assert req.ring == PrivilegeRing.RING_3
    assert gate.requires_elevation(req) is False
    assert gate.check_privilege(req, user_confirmed=False) is True


def test_ring0_requires_elevation_when_prompt_enabled():
    """Verify that Ring 0 operations require elevation when prompt is enabled."""
    gate = PrivilegeGate(enable_ring0_prompt=True)
    req = SyscallRequest(syscall=SyscallType.FILE_DELETE, params={"path": "a.txt"})
    assert req.ring == PrivilegeRing.RING_0
    assert gate.requires_elevation(req) is True

    # Blocked without user confirmation
    assert gate.check_privilege(req, user_confirmed=False) is False
    with pytest.raises(PrivilegeViolation):
        gate.assert_privilege(req, user_confirmed=False)

    # Allowed with user confirmation
    assert gate.check_privilege(req, user_confirmed=True) is True
    # Should not raise
    gate.assert_privilege(req, user_confirmed=True)


def test_ring0_auto_allowed_when_prompt_disabled():
    """Verify that Ring 0 operations are permitted automatically when prompt is disabled."""
    gate = PrivilegeGate(enable_ring0_prompt=False)
    req = SyscallRequest(syscall=SyscallType.PROC_SPAWN, params={"cmd": ["python", "app.py"]})
    assert gate.requires_elevation(req) is False
    assert gate.check_privilege(req, user_confirmed=False) is True
    gate.assert_privilege(req, user_confirmed=False)


def test_interactive_confirm_callback():
    """Verify that confirm_callback is consulted when user_confirmed is False."""
    approved_calls = []

    def mock_ui_confirm(req: SyscallRequest) -> bool:
        approved_calls.append(req.syscall)
        return True

    gate = PrivilegeGate(enable_ring0_prompt=True, confirm_callback=mock_ui_confirm)
    req = SyscallRequest(syscall=SyscallType.FILE_WRITE, params={"path": "a.txt", "content": "hi"})

    assert gate.check_privilege(req, user_confirmed=False) is True
    assert SyscallType.FILE_WRITE in approved_calls
