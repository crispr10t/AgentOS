"""Comprehensive edge-case tests for storage/db.py: DatabaseManager persistence and audit trails."""

from pathlib import Path
import pytest

from kernel.pcb import ProcessState, TaskPCB
from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallResult, SyscallType
from storage.db import DatabaseManager


@pytest.fixture
def memory_db():
    """Fixture providing an in-memory DatabaseManager."""
    db = DatabaseManager(db_path=":memory:")
    yield db
    db.close()


@pytest.fixture
def file_db(tmp_path: Path):
    """Fixture providing a file-backed DatabaseManager."""
    db_file = tmp_path / "sqlite_test.db"
    db = DatabaseManager(db_path=db_file)
    yield db
    db.close()


# --- 1. Task Persistence Edge Cases ---

@pytest.mark.parametrize("state", list(ProcessState))
def test_db_save_and_get_task_all_states(memory_db: DatabaseManager, state: ProcessState):
    """Verify persisting and reading tasks across every lifecycle state."""
    pcb = TaskPCB(pid=1000 + list(ProcessState).index(state), name=f"task_{state.value}", state=state)
    memory_db.save_task(pcb)

    row = memory_db.get_task(pcb.pid)
    assert row is not None
    assert row["pid"] == pcb.pid
    assert row["name"] == pcb.name
    assert row["state"] == state.value


def test_db_get_nonexistent_task(memory_db: DatabaseManager):
    """Querying an unknown PID returns None."""
    assert memory_db.get_task(99999) is None


def test_db_upsert_task_updates_in_place(memory_db: DatabaseManager):
    """Verify saving a task with the same PID updates all fields via ON CONFLICT."""
    pcb = TaskPCB(pid=2000, name="original", priority=1)
    memory_db.save_task(pcb)

    # Modify PCB
    pcb.name = "updated_name"
    pcb.priority = 10
    pcb.record_metrics(cpu_time=5.5, peak_memory_mb=64.0, exit_code=0, error_msg="Success")
    memory_db.save_task(pcb)

    row = memory_db.get_task(2000)
    assert row is not None
    assert row["name"] == "updated_name"
    assert row["priority"] == 10
    assert row["cpu_time"] == 5.5
    assert row["peak_memory_mb"] == 64.0
    assert row["exit_code"] == 0
    assert row["error_msg"] == "Success"


def test_db_get_all_tasks_limit(memory_db: DatabaseManager):
    """Verify get_all_tasks respects limit and order."""
    for i in range(10):
        pcb = TaskPCB(pid=3000 + i, name=f"task_{i}")
        memory_db.save_task(pcb)

    all_tasks = memory_db.get_all_tasks(limit=4)
    assert len(all_tasks) == 4


# --- 2. Syscall Audit Log Edge Cases ---

def test_db_log_syscall_success(memory_db: DatabaseManager):
    """Verify successful syscall logging with JSON parameter serialization."""
    req = SyscallRequest(
        syscall=SyscallType.FILE_READ,
        params={"path": "config.json", "max_bytes": 1024},
        ring=PrivilegeRing.RING_3,
    )
    res = SyscallResult.ok(request=req, output='{"key": "val"}', duration_sec=0.02)

    log_id = memory_db.log_syscall(request=req, result=res, pid=501)
    assert log_id > 0

    logs = memory_db.get_audit_logs(limit=10)
    assert len(logs) >= 1
    log_entry = logs[0]
    assert log_entry["call_id"] == req.call_id
    assert log_entry["pid"] == 501
    assert log_entry["syscall"] == "FILE_READ"
    assert log_entry["ring"] == 3
    assert log_entry["success"] == 1
    assert log_entry["duration_sec"] == 0.02


def test_db_log_syscall_failure(memory_db: DatabaseManager):
    """Verify failed syscall logging with error messages and exit codes."""
    req = SyscallRequest(
        syscall=SyscallType.PROC_KILL,
        params={"pid": 999},
        ring=PrivilegeRing.RING_0,
    )
    res = SyscallResult.fail(request=req, error="Process not found", exit_code=127)

    log_id = memory_db.log_syscall(request=req, result=res, pid=None)
    assert log_id > 0

    logs = memory_db.get_audit_logs(limit=1)
    entry = logs[0]
    assert entry["success"] == 0
    assert entry["exit_code"] == 127
    assert entry["error"] == "Process not found"
    assert entry["pid"] is None


# --- 3. File-Backed Persistence Integrity ---

def test_file_db_persistence_across_instances(tmp_path: Path):
    """Verify data persists on disk when closing and reopening a database file."""
    db_file = tmp_path / "persistent.db"

    # Write in first instance
    db1 = DatabaseManager(db_path=db_file)
    pcb = TaskPCB(pid=8888, name="persistent_task")
    db1.save_task(pcb)
    db1.close()

    # Read from new instance
    db2 = DatabaseManager(db_path=db_file)
    row = db2.get_task(8888)
    assert row is not None
    assert row["name"] == "persistent_task"
    db2.close()
