"""Verification test suite for APP_CLOSE system call with pre-existence checks."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import psutil
import pytest
from unittest.mock import MagicMock, patch

from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import ProcessManager
from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)
from security.privilege import PrivilegeGate
from ui.elevation_dialog import ElevationDialog


def test_app_close_enum_and_ring():
    """Verifies that APP_CLOSE is properly defined as a Ring 0 system call."""
    assert SyscallType.APP_CLOSE.value == "APP_CLOSE"
    assert DEFAULT_SYSCALL_RINGS[SyscallType.APP_CLOSE] == PrivilegeRing.RING_0

    gate = PrivilegeGate(enable_ring0_prompt=True)
    assert gate.classify(SyscallType.APP_CLOSE) == PrivilegeRing.RING_0


def test_app_close_validation_errors():
    """Verifies input validation on app name parameter."""
    pm = ProcessManager()

    # Empty name
    res = pm.close_application("")
    assert not res.success
    assert "cannot be empty" in res.error

    res_spaces = pm.close_application("   ")
    assert not res_spaces.success
    assert "cannot be empty" in res_spaces.error

    # Prohibited shell
    res_shell = pm.close_application("cmd.exe")
    assert not res_shell.success
    assert res_shell.exit_code == 126
    assert "not permitted" in res_shell.error

    # Path traversal attempt
    res_traversal = pm.close_application("../notepad")
    assert not res_traversal.success
    assert res_traversal.exit_code == 126


def test_app_close_nonexistent_process_pre_check():
    """Verifies that attempting to close a non-running app fails gracefully without modifying state."""
    pm = ProcessManager()

    fake_app = "definitely_not_running_dummy_app_xyz_123"
    res = pm.close_application(fake_app)

    assert not res.success
    assert res.exit_code == 1
    assert f"Application '{fake_app}' is not currently running" in res.error
    assert "Cannot close a non-existent process" in res.error


def test_app_close_running_process_successful_termination():
    """Verifies that APP_CLOSE identifies a running process and terminates it cleanly."""
    pm = ProcessManager()

    mock_proc = MagicMock()
    mock_proc.pid = 99999
    mock_proc.name.return_value = "dummyapp.exe"
    mock_proc.info = {"name": "dummyapp.exe", "pid": 99999}

    with patch("psutil.process_iter", return_value=[mock_proc]), \
         patch("psutil.pid_exists", return_value=True), \
         patch.object(pm, "kill_process_tree") as mock_kill:
        res = pm.close_application("dummyapp")
        assert res.success
        assert res.data["closed"] is True
        assert 99999 in res.data["pids"]
        assert "PID 99999" in res.output
        mock_kill.assert_called_once_with(99999)


def test_dispatcher_app_close_missing_parameter():
    """Verifies SyscallDispatcher rejects APP_CLOSE when 'app' parameter is missing."""
    dispatcher = SyscallDispatcher()
    req = SyscallRequest(
        syscall=SyscallType.APP_CLOSE,
        params={},
        ring=PrivilegeRing.RING_0,
    )

    res = dispatcher.dispatch(req, user_confirmed=True)
    assert not res.success
    assert "Missing required parameter 'app'" in res.error


def test_dispatcher_app_close_routing_and_elevation():
    """Verifies SyscallDispatcher routes APP_CLOSE with Ring 0 elevation gating."""
    dispatcher = SyscallDispatcher()

    # Blocked without elevation confirmation
    req = SyscallRequest(
        syscall=SyscallType.APP_CLOSE,
        params={"app": "vlc"},
        ring=PrivilegeRing.RING_0,
    )

    denied = dispatcher.dispatch(req, user_confirmed=False)
    assert not denied.success
    assert denied.exit_code == 126
    assert "Ring 0 privilege elevation approval" in denied.error

    # Elevation granted but VLC is not running -> fails gracefully with pre-check
    approved = dispatcher.dispatch(req, user_confirmed=True)
    assert not approved.success
    assert approved.exit_code == 1
    assert "is not currently running" in approved.error


def test_elevation_dialog_app_close_highlight():
    """Verifies ElevationDialog renders human-readable highlight for APP_CLOSE."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])

    req = SyscallRequest(
        syscall=SyscallType.APP_CLOSE,
        params={"app": "vlc"},
        ring=PrivilegeRing.RING_0,
    )
    dialog = ElevationDialog(request=req)
    highlight = dialog._build_highlight_text()
    assert "Close Application" in highlight
    assert "vlc" in highlight
