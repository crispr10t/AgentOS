"""Comprehensive tests for Edge window/tab closing, URL keyword extraction, and Edge aliases."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from kernel.process_manager import (
    ProcessManager,
    resolve_application_executable,
)
from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallResult, SyscallType


@pytest.fixture
def pm() -> ProcessManager:
    return ProcessManager(default_timeout=5, default_memory_limit_mb=256)


# --- 1. URL Keyword Extraction ---

def test_extract_url_keywords():
    """Verify keyword extraction identifies query and domain keywords."""
    url = "https://www.bing.com/search?q=java"
    kw = ProcessManager._extract_url_keywords(url)
    assert "bing" in kw
    assert "java" in kw

    url2 = "https://google.com/search?q=agentos+kernel&hl=en"
    kw2 = ProcessManager._extract_url_keywords(url2)
    assert "google" in kw2
    assert "agentos kernel" in kw2 or "agentos" in [k.split()[0] for k in kw2] or "agentos" in kw2


# --- 2. Graceful Edge Tab Closing With Live PID ---

def test_close_edge_tab_live_pid(pm: ProcessManager):
    """Verify close_edge_tab terminates live PID and removes tracking entry."""
    pm._edge_windows.append({"pid": 99912, "url": "https://www.bing.com/search?q=java"})

    with patch("kernel.process_manager.psutil.pid_exists", return_value=True), \
         patch.object(pm, "kill_process_tree", return_value=True) as mock_kill, \
         patch.object(pm, "_close_edge_window", return_value=False):
        res = pm.close_edge_tab(url="https://www.bing.com/search?q=java")

    assert res.success is True
    assert "Closed Edge tab/window" in res.output
    mock_kill.assert_called_once_with(99912)
    assert len(pm._edge_windows) == 0


# --- 3. Edge Tab Closing When Spawned PID Exited (Window Still Open) ---

def test_close_edge_tab_transient_pid_closed_via_wm_close(pm: ProcessManager):
    """Verify that when the spawned launcher PID has already exited, WM_CLOSE closes the window."""
    pm._edge_windows.append({"pid": 24108, "url": "https://www.bing.com/search?q=java"})

    with patch("kernel.process_manager.psutil.pid_exists", return_value=False), \
         patch.object(pm, "_close_edge_window", return_value=True) as mock_win_close:
        res = pm.close_edge_tab()

    assert res.success is True
    assert "Closed Edge tab/window" in res.output
    assert "PID 24108" in res.output
    assert len(pm._edge_windows) == 0
    mock_win_close.assert_called_once()


# --- 4. Honest Failure Reporting (Never Lie on Failed Close) ---

def test_close_edge_tab_fails_honestly_when_nothing_closed(pm: ProcessManager):
    """Verify close_edge_tab returns failure and preserves tracking when neither window nor process can be closed."""
    pm._edge_windows.append({"pid": 24108, "url": "https://www.bing.com/search?q=java"})

    with patch("kernel.process_manager.psutil.pid_exists", return_value=False), \
         patch("kernel.process_manager.psutil.process_iter", return_value=[]), \
         patch.object(pm, "_close_edge_window", return_value=False):
        res = pm.close_edge_tab()

    assert res.success is False
    assert res.exit_code == 1
    assert "Could not close Edge window" in (res.error or "")
    # Entry must be preserved in tracking state so retry or inspection is possible
    assert len(pm._edge_windows) == 1


# --- 5. Empty Tracking Fallback to Running Edge Window/Process ---

def test_close_edge_tab_fallback_when_tracking_empty_and_edge_running(pm: ProcessManager):
    """Verify that if _edge_windows is empty but Edge is running, active window is closed."""
    assert len(pm._edge_windows) == 0

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 11220, "name": "msedge.exe"}

    with patch("kernel.process_manager.psutil.process_iter", return_value=[mock_proc]), \
         patch.object(pm, "_close_edge_window", return_value=True):
        res = pm.close_edge_tab()

    assert res.success is True
    assert "Closed active Microsoft Edge window" in res.output


def test_close_edge_tab_fallback_to_close_app_when_no_window(pm: ProcessManager):
    """Verify that if _edge_windows is empty and window close fails, it falls back to terminating Edge."""
    assert len(pm._edge_windows) == 0

    mock_proc = MagicMock()
    mock_proc.info = {"pid": 11220, "name": "msedge.exe"}

    ok_res = SyscallResult.ok(
        request=SyscallRequest(syscall=SyscallType.APP_CLOSE),
        output="Closed edge (PID 11220).",
    )

    with patch("kernel.process_manager.psutil.process_iter", return_value=[mock_proc]), \
         patch.object(pm, "_close_edge_window", return_value=False), \
         patch.object(pm, "close_app", return_value=ok_res) as mock_close_app:
        res = pm.close_edge_tab()

    assert res.success is True
    mock_close_app.assert_called_once()
    assert mock_close_app.call_args.args[0] == "edge"


def test_close_edge_tab_fails_when_tracking_empty_and_edge_not_running(pm: ProcessManager):
    """Verify that if _edge_windows is empty and Edge is not running at all, it reports clear failure."""
    assert len(pm._edge_windows) == 0

    with patch("kernel.process_manager.psutil.process_iter", return_value=[]):
        res = pm.close_edge_tab()

    assert res.success is False
    assert "No active Microsoft Edge windows or tabs found to close" in (res.error or "")


# --- 6. Edge Aliases in close_app and resolve_application_executable ---

@pytest.mark.parametrize("alias", [
    "ms edge",
    "ms_edge",
    "microsoft edge",
    "microsoft_edge",
    "msedge",
    "edge",
])
def test_close_app_identifies_edge_process_under_all_aliases(pm: ProcessManager, alias: str):
    """Verify that close_app matches msedge.exe running processes for all Edge naming variations."""
    mock_edge = MagicMock()
    mock_edge.info = {"pid": 5555, "name": "msedge.exe"}

    with patch("kernel.process_manager.psutil.process_iter", return_value=[mock_edge]), \
         patch("kernel.process_manager.psutil.pid_exists", return_value=True), \
         patch.object(pm, "kill_process_tree", return_value=True) as mock_kill:
        res = pm.close_app(alias)

    assert res.success is True
    assert "5555" in res.output
    mock_kill.assert_called_once_with(5555)


def test_resolve_application_executable_edge_aliases():
    """Verify resolve_application_executable resolves all Edge alias names to msedge.exe."""
    with patch("kernel.process_manager.shutil.which", return_value=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"):
        assert resolve_application_executable("ms edge") is not None
        assert resolve_application_executable("microsoft edge") is not None
        assert resolve_application_executable("ms_edge") is not None
        assert resolve_application_executable("edge") is not None


# --- 7. Planner Prompts and Few-Shot Invariants ---

def test_few_shot_examples_edge_close_and_tab_close():
    """Verify few-shot examples distinguish between closing Edge application vs Edge tab."""
    from agent.prompts import FEW_SHOT_EXAMPLES
    from agent.planner import SyscallPlan

    examples_map = {ex["user_request"]: ex["plan"] for ex in FEW_SHOT_EXAMPLES}

    # Verify "close ms edge" maps to APP_CLOSE with "edge"
    assert "close ms edge" in examples_map
    edge_close_plan = examples_map["close ms edge"]
    assert edge_close_plan["steps"][0]["syscall"] == "APP_CLOSE"
    assert edge_close_plan["steps"][0]["params"]["app"] == "edge"

    # Verify "close the edge tab" maps to APP_CLOSE_TAB
    assert "close the edge tab" in examples_map
    tab_close_plan = examples_map["close the edge tab"]
    assert tab_close_plan["steps"][0]["syscall"] == "APP_CLOSE_TAB"

    # Verify all few-shot plans pass DAG validation
    for ex in FEW_SHOT_EXAMPLES:
        plan = SyscallPlan(user_prompt=ex["user_request"], **ex["plan"])
        plan.validate_dag()

