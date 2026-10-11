"""Tests for storage/db.py: DatabaseManager, Task persistence, and Syscall audit logging."""

import json
from pathlib import Path

from kernel.pcb import ProcessState, TaskPCB
from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallResult, SyscallType
from storage.db import DatabaseManager


def test_in_memory_db_initialization():
    """Verify that in-memory database initializes required tables."""
    db = DatabaseManager(db_path=":memory:")
    conn = db.get_connection()
    cursor = conn.cursor()

    # Verify tasks table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'"
    )
    assert cursor.fetchone() is not None

    # Verify syscall_audit_log table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='syscall_audit_log'"
    )
    assert cursor.fetchone() is not None


def test_task_save_and_retrieve():
    """Verify storing, retrieving, and updating a TaskPCB."""
    db = DatabaseManager(db_path=":memory:")
    pcb = TaskPCB(pid=2001, name="unit_test_process", priority=2)

    # Save new task
    db.save_task(pcb)
    saved = db.get_task(2001)
    assert saved is not None
    assert saved["pid"] == 2001
    assert saved["name"] == "unit_test_process"
    assert saved["state"] == "NEW"
    assert saved["priority"] == 2
    assert saved["exit_code"] is None

    # Update task state and record metrics
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)
    pcb.record_metrics(cpu_time=0.45, peak_memory_mb=128.5)
    pcb.transition_to(ProcessState.TERMINATED)
    pcb.record_metrics(exit_code=0)

    # Upsert updated task
    db.save_task(pcb)
    updated = db.get_task(2001)
    assert updated is not None
    assert updated["state"] == "TERMINATED"
    assert updated["cpu_time"] == 0.45
    assert updated["peak_memory_mb"] == 128.5
    assert updated["exit_code"] == 0
    assert updated["turnaround_time"] is not None
    assert updated["waiting_time"] is not None


def test_get_all_tasks():
    """Verify batch retrieval with limits."""
    db = DatabaseManager(db_path=":memory:")
    for i in range(5):
        pcb = TaskPCB(pid=3000 + i, name=f"batch_task_{i}")
        db.save_task(pcb)

    tasks = db.get_all_tasks(limit=3)
    assert len(tasks) == 3


def test_log_syscall_and_retrieve_audit_logs():
    """Verify appending and querying system call audit log entries."""
    db = DatabaseManager(db_path=":memory:")

    req = SyscallRequest(
        syscall=SyscallType.FILE_SEARCH,
        params={"pattern": "*.py", "root": "/app"},
        ring=PrivilegeRing.RING_3,
    )
    res = SyscallResult.ok(
        request=req,
        output="main.py\nkernel.py",
        duration_sec=0.012,
    )

    row_id = db.log_syscall(request=req, result=res, pid=5001)
    assert row_id > 0

    logs = db.get_audit_logs(limit=10)
    assert len(logs) == 1
    log = logs[0]
    assert log["call_id"] == req.call_id
    assert log["pid"] == 5001
    assert log["syscall"] == "FILE_SEARCH"
    assert log["ring"] == 3
    assert log["success"] == 1
    assert log["output"] == "main.py\nkernel.py"
    assert log["error"] is None
    assert log["duration_sec"] == 0.012

    # Verify JSON params parsed back
    params = json.loads(log["params_json"])
    assert params["pattern"] == "*.py"


def test_file_based_db(tmp_path: Path):
    """Verify file-based SQLite database creation in temporary directory."""
    test_db_file = tmp_path / "subdir" / "test_agentos.db"
    db = DatabaseManager(db_path=test_db_file)

    pcb = TaskPCB(pid=9999, name="file_db_task")
    db.save_task(pcb)

    assert test_db_file.exists()
    retrieved = db.get_task(9999)
    assert retrieved is not None
    assert retrieved["name"] == "file_db_task"
