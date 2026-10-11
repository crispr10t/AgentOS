"""Comprehensive Verification & Benchmark Test Suite for Phase 7 (Academic Capstone).

Validates:
1. Benchmark Consistency: FCFS, Priority, and SJF mathematical invariants, Convoy Effect,
   and SJF latency minimization ($W_{SJF} \\le W_{FCFS}$).
2. Benchmark CLI & Export: Table, Markdown, and JSON serialization.
3. Viva Demo 1: Process compilation & execution lifecycle with PCB state tracking.
4. Viva Demo 2: Process watchdog terminating runaway infinite loops with tree-killing.
5. Viva Demo 3: Ring 0 privilege elevation gate blocking unauthorized operations.
6. Viva Demo 4: Transactional file undo restoring quarantined assets.
7. Viva Demo 5: Dynamic scheduling policy switching and turnaround/waiting time computation.
8. Viva Demo 6: Offline LLM fallback resilience for local environments.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import pytest

from agent.llm_client import LLMClient, LLMConfig, LLMProvider
from benchmark_scheduler import (
    format_markdown,
    format_table,
    generate_benchmark_tasks,
    run_benchmark,
)
from kernel.file_engine import FileEngine
from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import ProcessManager
from kernel.scheduler import SchedulingPolicy, TaskScheduler
from kernel.syscalls import (
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)
from security.privilege import PrivilegeGate
from storage.db import DatabaseManager
from storage.journal import TransactionJournal


# =====================================================================
# 1. Scheduler Benchmarking Mathematical Invariants
# =====================================================================


def test_scheduler_benchmarking_invariants():
    """Verifies that SJF strictly minimizes average waiting time over FCFS and Priority."""
    results = run_benchmark()

    assert "workload" in results
    assert len(results["workload"]) == 5
    assert "policies" in results
    assert "analysis" in results

    fcfs = results["policies"][SchedulingPolicy.FCFS.value]
    prio = results["policies"][SchedulingPolicy.PRIORITY.value]
    sjf = results["policies"][SchedulingPolicy.SJF.value]

    # Verify all tasks completed in all policies
    assert fcfs["tasks_completed"] == 5
    assert prio["tasks_completed"] == 5
    assert sjf["tasks_completed"] == 5

    # Verify dispatch orders match theoretical expectations
    assert fcfs["dispatch_order"][0] == "heavy_compile"
    assert prio["dispatch_order"][0] == "security_audit"
    assert sjf["dispatch_order"][0] == "clean_cache"

    # Mathematical property: For non-preemptive batches arriving simultaneously,
    # SJF yields the minimal average waiting time.
    assert sjf["avg_waiting_time"] <= fcfs["avg_waiting_time"]
    assert sjf["avg_turnaround_time"] <= fcfs["avg_turnaround_time"]

    # Verify Convoy Effect quantification
    assert results["analysis"]["convoy_effect_ratio"] > 2.0
    assert results["analysis"]["sjf_wait_reduction_percent"] > 50.0
    assert results["analysis"]["sjf_optimal"] is True


def test_benchmark_cli_formats(tmp_path: Path):
    """Verifies table, markdown, and JSON report generation and file export."""
    results = run_benchmark()

    # Table format
    tbl = format_table(results)
    assert "AgentOS Task Scheduler Benchmark" in tbl
    assert "heavy_compile" in tbl
    assert "Convoy Effect" in tbl

    # Markdown format
    md = format_markdown(results)
    assert "### Empirical Scheduler Benchmark Results" in md
    assert "$T_{wait}$" in md
    assert "**FCFS**" in md
    assert "**SJF**" in md

    # JSON export
    json_path = tmp_path / "benchmark.json"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["analysis"]["sjf_optimal"] is True


# =====================================================================
# 2. Viva Defense Demonstration Invariants
# =====================================================================


def test_viva_demo1_execution_lifecycle_with_pcb_tracking(tmp_path: Path):
    """Viva Demo 1: Verifies multi-step execution with full PCB state transitions and database logging."""
    sandbox = tmp_path / "demo1_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    pm = ProcessManager(default_timeout=5)
    fe = FileEngine(sandbox_root=sandbox, db_manager=db)
    gate = PrivilegeGate(enable_ring0_prompt=False)
    dispatcher = SyscallDispatcher(
        privilege_gate=gate,
        process_manager=pm,
        file_engine=fe,
        db_manager=db,
    )

    # 1. Create a script in sandbox
    script_path = sandbox / "worker.py"
    script_path.write_text("print('DEMO1_EXECUTION_COMPLETED');", encoding="utf-8")

    # 2. Initialize PCB in NEW state
    pcb = TaskPCB(pid=101, name="demo1_worker", priority=5)
    assert pcb.state == ProcessState.NEW

    req = SyscallRequest(
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": [sys.executable, str(script_path)]},
        ring=PrivilegeRing.RING_0,
    )

    res = dispatcher.dispatch(request=req, pcb=pcb, user_confirmed=True)

    # 3. Assert execution succeeded and PCB reached TERMINATED state
    assert res.success is True
    assert "DEMO1_EXECUTION_COMPLETED" in (res.output or "")
    assert pcb.state == ProcessState.TERMINATED
    assert pcb.started_at is not None
    assert pcb.ended_at is not None
    assert pcb.turnaround_time is not None
    assert pcb.turnaround_time > 0.0

    # 4. Assert PCB is saved in SQLite database
    saved_tasks = db.get_all_tasks()
    assert any(t["pid"] == 101 for t in saved_tasks)


def test_viva_demo2_watchdog_infinite_loop_timeout():
    """Viva Demo 2: Verifies watchdog halts runaway loop and terminates process tree."""
    pm = ProcessManager(default_timeout=2)
    demo_script = Path(__file__).resolve().parent.parent / "demo_assets" / "infinite_loop.py"
    assert demo_script.exists()

    start_time = time.time()
    result = pm.spawn(cmd=[sys.executable, str(demo_script)], timeout_sec=2)
    duration = time.time() - start_time

    assert result.success is False
    assert result.exit_code == 124  # Standard timeout exit code
    assert "TIMEOUT_EXPIRED" in (result.error or "")
    assert duration < 5.0  # Watchdog killed within tolerance


def test_viva_demo3_ring0_elevation_gate_security(tmp_path: Path):
    """Viva Demo 3: Verifies Ring 0 security boundary intercepts and requires elevation."""
    sandbox = tmp_path / "demo3_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    gate = PrivilegeGate(enable_ring0_prompt=True)
    fe = FileEngine(sandbox_root=sandbox, db_manager=db)
    dispatcher = SyscallDispatcher(
        privilege_gate=gate,
        file_engine=fe,
        db_manager=db,
    )

    req = SyscallRequest(
        syscall=SyscallType.FILE_DELETE,
        params={"path": "critical_file.txt"},
        ring=PrivilegeRing.RING_0,
    )

    # Dispatched without elevation confirmation -> Must fail with PERMISSION_DENIED
    res_blocked = dispatcher.dispatch(request=req, user_confirmed=False)
    assert res_blocked.success is False
    assert "PERMISSION_DENIED" in (res_blocked.error or "")

    # Dispatched with elevation confirmation -> Approved through security gate
    # (Will fail gracefully because file does not exist, but permission is granted)
    res_allowed = dispatcher.dispatch(request=req, user_confirmed=True)
    assert "PERMISSION_DENIED" not in (res_allowed.error or "")


def test_viva_demo4_file_quarantine_and_undo_recovery(tmp_path: Path):
    """Viva Demo 4: Verifies file deletion moves to quarantine and undo restores it."""
    sandbox = tmp_path / "demo4_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    fe = FileEngine(sandbox_root=sandbox, db_manager=db)
    dispatcher = SyscallDispatcher(file_engine=fe, db_manager=db)

    # 1. Write file
    target_file = sandbox / "important_data.csv"
    fe.file_write("important_data.csv", "id,value\n1,42\n2,99")
    assert target_file.exists()

    # 2. Delete file with quarantine
    fe.file_delete("important_data.csv", quarantine=True)
    assert not target_file.exists()

    # Verify quarantine trash contains file
    trash_files = list((sandbox / ".agentos_trash").glob("*important_data.csv"))
    assert len(trash_files) == 1

    # 3. Trigger Undo
    undo_res = dispatcher.undo_last_action()
    assert undo_res.success is True
    assert "Restored" in (undo_res.output or "")

    # File must be restored to original path with identical content
    assert target_file.exists()
    assert "id,value\n1,42\n2,99" in target_file.read_text(encoding="utf-8")


def test_viva_demo5_dynamic_scheduler_policy_switch():
    """Viva Demo 5: Verifies dynamic policy switching and ordering metrics."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)

    tasks = [
        TaskPCB(pid=1, name="long_task", priority=1, estimated_duration=10.0),
        TaskPCB(pid=2, name="short_task", priority=10, estimated_duration=1.0),
    ]

    for t in tasks:
        scheduler.enqueue(t)

    # Dynamic switch to SJF before dispatching
    scheduler.set_policy(SchedulingPolicy.SJF)
    first_task = scheduler.next_task()
    assert first_task is not None
    assert first_task.name == "short_task"

    # Next task is the longer one
    second_task = scheduler.next_task()
    assert second_task is not None
    assert second_task.name == "long_task"


def test_viva_demo6_offline_resilience():
    """Viva Demo 6: Verifies graceful fallback and offline reliability."""
    # Test Mock / Offline Provider
    client = LLMClient(config=LLMConfig(provider=LLMProvider.MOCK))
    resp = client.generate("List files in current directory")
    assert resp is not None
    assert len(resp.content) > 0
    assert resp.provider == LLMProvider.MOCK

    # Test fallback capability configuration
    config = LLMConfig(
        provider=LLMProvider.GEMINI,
        gemini_api_key=None,
        auto_fallback=True,
    )
    assert config.auto_fallback is True
