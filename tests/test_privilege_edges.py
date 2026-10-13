"""Comprehensive edge-case tests for security/privilege.py: PrivilegeGate and PrivilegeViolation."""

import os
import pytest

from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallType
from security.privilege import PrivilegeGate, PrivilegeViolation


# --- 1. App Whitelist Normalization Edge Cases ---

@pytest.mark.parametrize("app_input, expected_normalized", [
    ("calculator", "calculator"),
    ("CALCULATOR", "calculator"),
    ("  calculator  ", "calculator"),
    ("google-chrome", "googlechrome"),
    ("Google Chrome", "google_chrome"),
    ("Visual-Studio-Code", "visualstudiocode"),
    ("notepad_plus_plus", "notepad_plus_plus"),
])
def test_privilege_gate_whitelist_normalization(app_input: str, expected_normalized: str):
    """Verify app whitelisting normalizes casing, spaces, and hyphens."""
    gate = PrivilegeGate()
    gate.whitelist_app(app_input)
    assert gate.is_app_whitelisted(app_input) is True
    # Verify normalized form matches internal representation
    assert expected_normalized in gate.whitelisted_apps


def test_privilege_gate_non_whitelisted_app():
    """Verify non-whitelisted apps return False."""
    gate = PrivilegeGate()
    assert gate.is_app_whitelisted("malicious_tool") is False
    assert gate.is_app_whitelisted("") is False


# --- 2. Prompt Toggling and Elevation Requirements ---

@pytest.mark.parametrize("env_val, expected_flag", [
    ("true", True),
    ("True", True),
    ("1", True),
    ("yes", True),
    ("on", True),
    ("false", False),
    ("False", False),
    ("0", False),
    ("no", False),
    ("off", False),
])
def test_privilege_gate_env_flag_parsing(monkeypatch: pytest.MonkeyPatch, env_val: str, expected_flag: bool):
    """Verify environment variable ENABLE_RING0_PROMPT is accurately parsed."""
    monkeypatch.setenv("ENABLE_RING0_PROMPT", env_val)
    gate = PrivilegeGate(enable_ring0_prompt=None)
    assert gate.enable_ring0_prompt is expected_flag


def test_privilege_gate_prompt_disabled_bypasses_all_elevation():
    """When enable_ring0_prompt=False, all Ring 0 calls bypass confirmation."""
    gate = PrivilegeGate(enable_ring0_prompt=False)
    req = SyscallRequest(syscall=SyscallType.PROC_KILL, ring=PrivilegeRing.RING_0)

    assert gate.requires_elevation(req) is False
    assert gate.check_privilege(req, user_confirmed=False) is True
    # assert_privilege does not raise
    gate.assert_privilege(req, user_confirmed=False)


def test_privilege_gate_ring3_never_requires_elevation():
    """Ring 3 operations must never require elevation regardless of prompt setting."""
    gate = PrivilegeGate(enable_ring0_prompt=True)
    req = SyscallRequest(syscall=SyscallType.CALCULATE, ring=PrivilegeRing.RING_3)

    assert gate.requires_elevation(req) is False
    assert gate.check_privilege(req, user_confirmed=False) is True
    gate.assert_privilege(req, user_confirmed=False)


def test_privilege_gate_app_open_whitelisted_bypasses_elevation():
    """APP_OPEN for a whitelisted application bypasses Ring 0 prompt."""
    gate = PrivilegeGate(enable_ring0_prompt=True)
    gate.whitelist_app("calculator")

    req = SyscallRequest(syscall=SyscallType.APP_OPEN, params={"app": "calculator"})
    assert gate.requires_elevation(req) is False
    assert gate.check_privilege(req, user_confirmed=False) is True


def test_privilege_gate_app_open_non_whitelisted_requires_elevation():
    """APP_OPEN for an unknown app requires elevation when prompt enabled."""
    gate = PrivilegeGate(enable_ring0_prompt=True)
    req = SyscallRequest(syscall=SyscallType.APP_OPEN, params={"app": "unknown_app"})
    assert gate.requires_elevation(req) is True
    assert gate.check_privilege(req, user_confirmed=False) is False


# --- 3. Confirmation Callbacks & Assertion Violations ---

def test_privilege_gate_callback_approval():
    """Callback returning True allows execution without explicit user_confirmed parameter."""
    gate = PrivilegeGate(enable_ring0_prompt=True, confirm_callback=lambda req: True)
    req = SyscallRequest(syscall=SyscallType.FILE_DELETE, ring=PrivilegeRing.RING_0)

    assert gate.check_privilege(req, user_confirmed=False) is True
    gate.assert_privilege(req, user_confirmed=False)


def test_privilege_gate_callback_rejection():
    """Callback returning False rejects execution."""
    gate = PrivilegeGate(enable_ring0_prompt=True, confirm_callback=lambda req: False)
    req = SyscallRequest(syscall=SyscallType.FILE_DELETE, ring=PrivilegeRing.RING_0)

    assert gate.check_privilege(req, user_confirmed=False) is False
    with pytest.raises(PrivilegeViolation, match="requires Ring 0 privilege elevation"):
        gate.assert_privilege(req, user_confirmed=False)


def test_privilege_gate_user_confirmed_precedence():
    """Explicit user_confirmed=True takes precedence even without callback."""
    gate = PrivilegeGate(enable_ring0_prompt=True, confirm_callback=None)
    req = SyscallRequest(syscall=SyscallType.FILE_WRITE, ring=PrivilegeRing.RING_0)

    assert gate.check_privilege(req, user_confirmed=True) is True
    gate.assert_privilege(req, user_confirmed=True)
