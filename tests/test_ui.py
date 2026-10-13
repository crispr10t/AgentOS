"""Automated Verification Suite for PyQt6 Graphical Shell (Phase 5).

Runs headlessly under offscreen platform mode to verify UI widgets,
live PCB table rendering, streaming terminal, telemetry meters,
Ring 0 elevation dialogs, and non-blocking worker threads.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

import pytest

# Ensure offscreen QPA platform for headless testing
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt6.QtWidgets import QApplication

from agent.llm_client import LLMClient, LLMConfig, LLMProvider
from agent.planner import AgentPlanner, PlanStep, SyscallPlan
from kernel.pcb import ProcessState, TaskPCB
from kernel.scheduler import SchedulingPolicy, TaskScheduler
from kernel.sync import PCBTable
from kernel.syscalls import (
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)
from kernel.telemetry import TelemetryDaemon
from ui.elevation_dialog import ElevationDialog
from ui.main_window import ElevationBridge, MainWindow, SupervisorWorker
from ui.pcb_table_widget import PcbTableWidget
from ui.telemetry_widget import TelemetryWidget
from ui.terminal_widget import TerminalWidget


@pytest.fixture(scope="session")
def qapp():
    """Session-level QApplication instance running in offscreen mode."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    yield app


# =====================================================================
# Telemetry Daemon Tests
# =====================================================================


def test_telemetry_daemon_sampling():
    """Verifies that TelemetryDaemon samples hardware metrics accurately."""
    daemon = TelemetryDaemon(interval_sec=0.2)
    sample = daemon.sample()

    assert "cpu_total" in sample
    assert "cpu_per_core" in sample
    assert "ram_percent" in sample
    assert "ram_used_gb" in sample
    assert "ram_total_gb" in sample
    assert isinstance(sample["cpu_per_core"], list)
    assert len(sample["cpu_per_core"]) > 0
    assert sample["ram_total_gb"] > 0

    # Test subscribe & daemon background thread
    received = []
    daemon.subscribe(lambda data: received.append(data))

    daemon.start()
    assert daemon.is_running
    time.sleep(0.5)
    daemon.stop()

    assert not daemon.is_running
    assert len(received) >= 1


# =====================================================================
# Elevation Dialog Tests
# =====================================================================


def test_elevation_dialog_rendering(qapp):
    """Verifies ElevationDialog layout, parameters, and syscall details."""
    req = SyscallRequest(
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": ["python", "-c", "print('hello')"], "timeout": 5},
        ring=PrivilegeRing.RING_0,
    )
    dialog = ElevationDialog(request=req)

    assert "Ring 0" in dialog.windowTitle()
    assert dialog.isModal()
    assert "python -c print('hello')" in dialog._build_highlight_text()
    assert "PROC_SPAWN" in dialog.params_view.toPlainText() or "cmd" in dialog.params_view.toPlainText()


def test_elevation_dialog_accept_reject(qapp):
    """Verifies user approve and reject responses on ElevationDialog."""
    req = SyscallRequest(
        syscall=SyscallType.FILE_DELETE,
        params={"path": "quarantine.txt", "quarantine": True},
        ring=PrivilegeRing.RING_0,
    )
    dialog = ElevationDialog(request=req)

    # Test accept
    dialog.approve_btn.click()
    assert dialog.result() == ElevationDialog.DialogCode.Accepted

    # Test reject
    dialog2 = ElevationDialog(request=req)
    dialog2.reject_btn.click()
    assert dialog2.result() == ElevationDialog.DialogCode.Rejected


# =====================================================================
# PCB Table Widget Tests
# =====================================================================


def test_pcb_table_widget_lifecycle(qapp):
    """Verifies row insertion, state transitions, and counter badges in PcbTableWidget."""
    widget = PcbTableWidget()
    assert widget.table.rowCount() == 0

    pcb = TaskPCB(pid=101, name="Compile Task", priority=5, estimated_duration=2.5)
    widget.update_pcb(pcb)

    assert widget.table.rowCount() == 1
    assert widget.table.item(0, 0).text() == "#101"
    assert widget.table.item(0, 1).text() == "Compile Task"
    assert widget.table.item(0, 3).text() == "5"
    assert "Tasks: 1" in widget.count_badge.text()

    # Transition to RUNNING
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)
    widget.update_pcb(pcb)
    assert widget.table.rowCount() == 1
    assert "Running: 1" in widget.count_badge.text()

    # Transition to TERMINATED with metrics
    pcb.record_metrics(cpu_time=0.125, peak_memory_mb=42.0, exit_code=0)
    pcb.transition_to(ProcessState.TERMINATED)
    widget.update_pcb(pcb)

    assert widget.table.rowCount() == 1
    assert widget.table.item(0, 5).text() == "0.125s"
    assert widget.table.item(0, 6).text() == "42.0 MB"
    assert widget.table.item(0, 7).text() == "0 (OK)"
    assert "Terminated: 1" in widget.count_badge.text()

    # Test clear
    widget.clear()
    assert widget.table.rowCount() == 0
    assert "Tasks: 0" in widget.count_badge.text()


def test_pcb_table_widget_error_exit_code(qapp):
    """Verifies that non-zero exit codes format with error styling."""
    widget = PcbTableWidget()
    pcb = TaskPCB(pid=102, name="Failed Task")
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)
    pcb.record_metrics(exit_code=1, error_msg="Segmentation fault")
    pcb.transition_to(ProcessState.TERMINATED)

    widget.update_pcb(pcb)
    exit_item = widget.table.item(0, 7)
    assert exit_item.text() == "1 (ERR)"


# =====================================================================
# Terminal Widget Tests
# =====================================================================


def test_terminal_widget_streaming_and_controls(qapp):
    """Verifies streaming text channels, auto-scroll, and clear controls in TerminalWidget."""
    terminal = TerminalWidget()
    assert terminal.editor.toPlainText() == ""

    terminal.append_stream("Output line 1\n", channel="stdout")
    terminal.append_line("Kernel status notice", channel="system")
    terminal.append_line("Execution failed", channel="stderr")

    content = terminal.editor.toPlainText()
    assert "Output line 1" in content
    assert "Kernel status notice" in content
    assert "Execution failed" in content

    # Test Clear
    terminal.clear_console()
    assert terminal.editor.toPlainText() == ""


# =====================================================================
# Telemetry Widget Tests
# =====================================================================


def test_telemetry_widget_update(qapp):
    """Verifies gauge and per-core meter updates in TelemetryWidget."""
    widget = TelemetryWidget()

    test_data = {
        "cpu_total": 45.5,
        "cpu_per_core": [30.0, 60.0, 75.0, 20.0],
        "ram_percent": 68.2,
        "ram_used_gb": 10.9,
        "ram_total_gb": 16.0,
    }

    widget.update_telemetry(test_data)

    assert "CPU: 45.5%" in widget.cpu_label.text()
    assert widget.cpu_bar.value() == 45
    assert len(widget._core_bars) == 4
    assert widget._core_bars[1].value() == 60
    assert "RAM: 68.2%" in widget.ram_label.text()
    assert "10.9 / 16.0 GB" in widget.ram_label.text()
    assert widget.ram_bar.value() == 68


# =====================================================================
# Main Window & Supervisor Worker Tests
# =====================================================================


class DummyPlanner(AgentPlanner):
    """Mock planner returning a pre-determined 2-step plan."""

    def compile(self, user_instruction: str, context: Any = None) -> SyscallPlan:
        return SyscallPlan(
            user_prompt=user_instruction,
            plan_description="Mock System Verification Plan",
            steps=[
                PlanStep(
                    step_id=1,
                    syscall=SyscallType.SYS_INFO,
                    params={},
                    ring=PrivilegeRing.RING_3,
                    description="Gather host system telemetry",
                ),
                PlanStep(
                    step_id=2,
                    syscall=SyscallType.FILE_SEARCH,
                    params={"pattern": "*.py", "max_results": 5},
                    ring=PrivilegeRing.RING_3,
                    description="Search for python files",
                ),
            ],
        )


def test_main_window_initialization(qapp):
    """Verifies MainWindow components, defaults, and child hierarchy."""
    planner = DummyPlanner()
    window = MainWindow(planner=planner)

    assert window.windowTitle().startswith("AgentOS")
    assert window.prompt_input is not None
    assert window.execute_btn.isEnabled()
    assert not window.execute_btn.isHidden()
    assert not window.stop_btn.isEnabled()
    assert window.stop_btn.isHidden()
    assert window.undo_btn.isHidden()
    assert window.policy_combo.currentText() == "FCFS"
    assert window.pcb_table is not None
    assert window.terminal is not None
    assert window.telemetry_widget is not None

    window.close()


def test_main_window_dynamic_button_visibility(qapp):
    """Verifies that Stop and Execute buttons swap visibility during execution lifecycle."""
    planner = DummyPlanner()
    dispatcher = SyscallDispatcher()
    window = MainWindow(planner=planner, dispatcher=dispatcher)

    # Initial state: only Execute is visible, Stop & Undo are hidden
    assert not window.execute_btn.isHidden()
    assert window.stop_btn.isHidden()
    assert window.undo_btn.isHidden()

    window.prompt_input.setText("Inspect system info")
    window.on_execute_clicked()

    # While running: Stop is shown, Execute & Undo are hidden
    assert window.execute_btn.isHidden()
    assert not window.stop_btn.isHidden()
    assert window.undo_btn.isHidden()

    if window._worker is not None:
        window._worker.wait(3000)
    qapp.processEvents()

    # Finished state: Execute is restored, Stop is hidden
    assert not window.execute_btn.isHidden()
    assert window.stop_btn.isHidden()

    window.close()


def test_supervisor_worker_execution(qapp):
    """Verifies non-blocking execution of the SupervisorWorker thread."""
    planner = DummyPlanner()
    dispatcher = SyscallDispatcher()
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    pcb_table = PCBTable()

    worker = SupervisorWorker(
        prompt="Inspect system information",
        policy=SchedulingPolicy.FCFS,
        planner=planner,
        dispatcher=dispatcher,
        scheduler=scheduler,
        pcb_table=pcb_table,
    )

    plans_compiled = []
    pcb_updates = []
    streams = []
    finished = []

    worker.sig_plan_compiled.connect(lambda p: plans_compiled.append(p))
    worker.sig_pcb_updated.connect(lambda pcb: pcb_updates.append(pcb))
    worker.sig_console_stream.connect(lambda text, ch: streams.append(text))
    worker.sig_execution_finished.connect(lambda ok, msg: finished.append((ok, msg)))

    worker.start()
    worker.wait(5000)
    qapp.processEvents()

    assert len(plans_compiled) == 1
    assert len(pcb_updates) >= 2
    assert len(finished) == 1
    assert finished[0][0] is True  # Success
    assert "succeeded" in finished[0][1]


def test_supervisor_worker_cancellation(qapp):
    """Verifies that user cancel request aborts worker execution."""
    planner = DummyPlanner()
    dispatcher = SyscallDispatcher()
    worker = SupervisorWorker(
        prompt="Long running plan",
        policy=SchedulingPolicy.FCFS,
        planner=planner,
        dispatcher=dispatcher,
    )

    worker.cancel()
    assert worker.is_cancelled

    finished = []
    worker.sig_execution_finished.connect(lambda ok, msg: finished.append((ok, msg)))

    worker.start()
    worker.wait(3000)
    qapp.processEvents()

    assert len(finished) == 1
    assert finished[0][0] is False
    assert "Aborted" in finished[0][1]
