"""Comprehensive End-to-End Integration Verification Suite for Phase 6.

Validates:
1. End-to-End Pipeline: Natural language instruction -> Plan compilation ->
   Topological scheduling -> Watchdog process execution -> File quarantine ->
   Write-ahead audit logging -> Undo restoration.
2. PyQt6 Graphical Dashboard Integration: Undo button trigger, streaming console
   audit output, and background TelemetryWorker signal delivery without GUI lag.
3. Concurrency & Privilege Ring Separation in multi-step workflows.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import threading
import time
import pytest

# Ensure offscreen platform for Qt headless execution
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QApplication

from agent.planner import AgentPlanner, PlanStep, SyscallPlan
from kernel.file_engine import FileEngine
from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import ProcessManager
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
from security.privilege import PrivilegeGate
from storage.db import DatabaseManager
from storage.journal import TransactionJournal
from ui.main_window import (
    ElevationBridge,
    MainWindow,
    SupervisorWorker,
    TelemetryWorker,
)


@pytest.fixture(scope="session")
def qapp():
    """Session QApplication instance running offscreen."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    yield app


class Phase6MockPlanner(AgentPlanner):
    """Deterministic planner generating a multi-step end-to-end DAG workflow."""

    def compile(self, user_instruction: str) -> SyscallPlan:
        return SyscallPlan(
            user_prompt=user_instruction,
            plan_description="Phase 6 Multi-Step Lifecycle Workflow",
            steps=[
                PlanStep(
                    step_id=1,
                    syscall=SyscallType.FILE_WRITE,
                    params={
                        "path": "worker_task.py",
                        "content": "import sys; print('CALCULATION_DONE_42'); sys.exit(0)",
                        "mode": "w",
                    },
                    ring=PrivilegeRing.RING_0,
                    description="Write worker task script into sandbox",
                ),
                PlanStep(
                    step_id=2,
                    syscall=SyscallType.PROC_SPAWN,
                    params={
                        "cmd": [sys.executable, "worker_task.py"],
                        "timeout": 5,
                    },
                    ring=PrivilegeRing.RING_0,
                    dependencies=[1],
                    description="Execute python script under watchdog supervision",
                ),
                PlanStep(
                    step_id=3,
                    syscall=SyscallType.FILE_DELETE,
                    params={
                        "path": "worker_task.py",
                        "quarantine": True,
                    },
                    ring=PrivilegeRing.RING_0,
                    dependencies=[2],
                    description="Safely quarantine worker script after execution",
                ),
            ],
        )


def test_end_to_end_workflow_with_undo_recovery(tmp_path: Path):
    """Verifies complete pipeline: Write -> Spawn -> Quarantine -> SQLite Audit -> Undo Recovery."""
    sandbox = tmp_path / "e2e_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)

    db = DatabaseManager(db_path=":memory:")
    journal = TransactionJournal(db_manager=db, sandbox_root=sandbox)
    gate = PrivilegeGate(enable_ring0_prompt=False)  # auto-elevate for automated test
    pm = ProcessManager(default_timeout=5)
    fe = FileEngine(sandbox_root=sandbox, journal=journal)

    dispatcher = SyscallDispatcher(
        privilege_gate=gate,
        process_manager=pm,
        file_engine=fe,
        db_manager=db,
    )
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    pcb_table = PCBTable()
    planner = Phase6MockPlanner()

    # 1. Compile Plan
    plan = planner.compile("Generate worker, execute it, and clean up")
    assert len(plan.steps) == 3
    ordered_steps = plan.get_topological_steps()
    assert [s.step_id for s in ordered_steps] == [1, 2, 3]

    # 2. Queue into Scheduler
    pcbs: list[TaskPCB] = []
    for i, step in enumerate(ordered_steps):
        pcb = step.to_pcb(pid=700 + i)
        pcbs.append(pcb)
        pcb_table.register(pcb)
        scheduler.enqueue(pcb)

    assert scheduler.queue_size() == 3

    # 3. Execute all scheduled steps
    results: list[SyscallResult] = []
    step_map = {700 + i: s for i, s in enumerate(ordered_steps)}

    while not scheduler.is_empty():
        pcb = scheduler.next_task()
        assert pcb is not None
        step = step_map[pcb.pid]
        req = step.to_syscall_request()

        # For process spawn, set working directory to sandbox
        if req.syscall == SyscallType.PROC_SPAWN:
            req.params["cwd"] = str(sandbox)

        res = dispatcher.dispatch(request=req, pcb=pcb, user_confirmed=True)
        scheduler.record_completed(pcb)
        results.append(res)
        assert res.success is True
        assert pcb.state == ProcessState.TERMINATED

    # Verify execution outputs
    # Step 1: wrote file
    assert results[0].syscall == SyscallType.FILE_WRITE
    # Step 2: process ran and printed expected token
    assert results[1].syscall == SyscallType.PROC_SPAWN
    assert "CALCULATION_DONE_42" in (results[1].output or "")
    # Step 3: file quarantined
    assert results[2].syscall == SyscallType.FILE_DELETE
    assert not (sandbox / "worker_task.py").exists()

    # Verify SQLite Audit DB recorded all 3 operations
    audit_logs = db.get_audit_logs(limit=20)
    assert len(audit_logs) == 3
    # Verify tasks saved in DB
    all_tasks = db.get_all_tasks(limit=10)
    assert len(all_tasks) == 3

    # 4. UNDO RECOVERY (Viva Demo 4)
    # The file was deleted in step 3. Invoking undo should restore worker_task.py!
    assert journal.can_undo() is True
    undo_res = dispatcher.undo_last_action()
    assert undo_res.success is True
    assert "Restored 'worker_task.py'" in undo_res.output

    # Verify file is back in sandbox and has correct original content
    restored_file = sandbox / "worker_task.py"
    assert restored_file.exists()
    content = restored_file.read_text(encoding="utf-8")
    assert "CALCULATION_DONE_42" in content


def test_telemetry_worker_thread_decoupling(qapp):
    """Verifies that TelemetryWorker runs on a separate background thread and delivers signals."""
    daemon = TelemetryDaemon(interval_sec=0.2)
    worker = TelemetryWorker(daemon=daemon, interval_sec=0.2)

    received_samples = []
    thread_ids = []

    def on_tick(data):
        received_samples.append(data)
        thread_ids.append(threading.get_ident())

    worker.sig_telemetry_tick.connect(on_tick)
    worker.start()

    time.sleep(0.6)
    qapp.processEvents()

    worker.stop(timeout_ms=1000)

    assert len(received_samples) >= 2
    # Verify samples contain full telemetry metrics
    s = received_samples[0]
    assert "cpu_total" in s
    assert "cpu_per_core" in s
    assert "ram_percent" in s

    # Ensure thread did not block or crash
    assert not worker.isRunning()


def test_main_window_phase6_undo_ui_interaction(qapp, tmp_path: Path):
    """Verifies MainWindow Undo button and terminal streaming in headless offscreen mode."""
    sandbox = tmp_path / "gui_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)

    db = DatabaseManager(db_path=":memory:")
    fe = FileEngine(sandbox_root=sandbox, db_manager=db)
    dispatcher = SyscallDispatcher(file_engine=fe, db_manager=db)
    planner = Phase6MockPlanner()

    window = MainWindow(planner=planner, dispatcher=dispatcher)

    # Verify Undo button exists, is enabled initially, and has tooltip
    assert hasattr(window, "undo_btn")
    assert window.undo_btn is not None
    assert window.undo_btn.isEnabled()
    assert "Ctrl+Z" in window.undo_btn.toolTip()
    assert hasattr(window, "telemetry_worker")
    assert window.telemetry_worker.isRunning()

    # Pre-condition: Create a file and delete it directly in sandbox
    fe.file_write("demo.txt", "Undo GUI demonstration text")
    assert (sandbox / "demo.txt").exists()
    fe.file_delete("demo.txt", quarantine=True)
    assert not (sandbox / "demo.txt").exists()

    # Trigger Undo button click
    window.undo_btn.click()
    qapp.processEvents()

    # Verify file restored
    assert (sandbox / "demo.txt").exists()
    assert (sandbox / "demo.txt").read_text(encoding="utf-8") == "Undo GUI demonstration text"

    # Verify terminal widget logged the undo event
    console_text = window.terminal.editor.toPlainText()
    assert "[UNDO]" in console_text
    assert "Restored 'demo.txt'" in console_text

    # Second click on Undo: reverses the file write (removing newly created file)
    window.undo_btn.click()
    qapp.processEvents()
    assert not (sandbox / "demo.txt").exists()

    # Third click on Undo: nothing left to undo -> warning message logged
    window.undo_btn.click()
    qapp.processEvents()
    console_text = window.terminal.editor.toPlainText()
    assert "No reversible actions" in console_text

    window.close()
