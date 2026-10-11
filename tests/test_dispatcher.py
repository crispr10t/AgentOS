"""Tests for kernel/syscalls.py: SyscallDispatcher integration."""

from pathlib import Path
import sys
import pytest

from kernel.file_engine import FileEngine
from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import ProcessManager
from kernel.syscalls import (
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallType,
)
from security.privilege import PrivilegeGate
from storage.db import DatabaseManager


@pytest.fixture
def dispatcher_suite(tmp_path: Path):
    """Fixture providing an isolated SyscallDispatcher and test database."""
    sandbox = tmp_path / "dispatcher_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)

    db = DatabaseManager(db_path=":memory:")
    gate = PrivilegeGate(enable_ring0_prompt=True)
    pm = ProcessManager(default_timeout=5, default_memory_limit_mb=512)
    fe = FileEngine(sandbox_root=sandbox)

    dispatcher = SyscallDispatcher(
        privilege_gate=gate,
        process_manager=pm,
        file_engine=fe,
        db_manager=db,
    )

    return {
        "dispatcher": dispatcher,
        "db": db,
        "sandbox": sandbox,
        "gate": gate,
    }


def test_dispatcher_ring3_file_search_auto_approved(dispatcher_suite: dict):
    """Verify that Ring 3 syscalls are dispatched and executed without confirmation."""
    dispatcher: SyscallDispatcher = dispatcher_suite["dispatcher"]
    req = SyscallRequest(
        syscall=SyscallType.FILE_SEARCH,
        params={"pattern": "*.py"},
    )
    assert req.ring == PrivilegeRing.RING_3

    res = dispatcher.dispatch(req, user_confirmed=False)
    assert res.success is True
    assert res.syscall == SyscallType.FILE_SEARCH


def test_dispatcher_ring0_blocked_without_confirmation(dispatcher_suite: dict):
    """Verify that unconfirmed Ring 0 syscalls are rejected by the dispatcher."""
    dispatcher: SyscallDispatcher = dispatcher_suite["dispatcher"]
    req = SyscallRequest(
        syscall=SyscallType.FILE_WRITE,
        params={"path": "test.txt", "content": "blocked"},
    )
    assert req.ring == PrivilegeRing.RING_0

    res = dispatcher.dispatch(req, user_confirmed=False)
    assert res.success is False
    assert res.exit_code == 126
    assert "PERMISSION_DENIED" in (res.error or "")


def test_dispatcher_ring0_allowed_with_confirmation(dispatcher_suite: dict):
    """Verify that confirmed Ring 0 syscalls execute successfully."""
    dispatcher: SyscallDispatcher = dispatcher_suite["dispatcher"]
    req = SyscallRequest(
        syscall=SyscallType.FILE_WRITE,
        params={"path": "test.txt", "content": "approved content"},
    )

    res = dispatcher.dispatch(req, user_confirmed=True)
    assert res.success is True
    assert res.exit_code == 0

    # Read back to verify
    req_read = SyscallRequest(
        syscall=SyscallType.FILE_READ,
        params={"path": "test.txt"},
    )
    read_res = dispatcher.dispatch(req_read)
    assert read_res.success is True
    assert read_res.output == "approved content"


def test_dispatcher_process_spawn_with_pcb(dispatcher_suite: dict):
    """Verify process spawn transitions PCB states and records execution metrics."""
    dispatcher: SyscallDispatcher = dispatcher_suite["dispatcher"]
    pcb = TaskPCB(pid=5001, name="eval_script", priority=1)
    assert pcb.state == ProcessState.NEW

    req = SyscallRequest(
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": [sys.executable, "-c", "print('hello from pcb task')"]},
    )

    res = dispatcher.dispatch(req, pcb=pcb, user_confirmed=True)
    assert res.success is True
    assert "hello from pcb task" in (res.output or "")

    # Verify PCB state transitions and metrics
    assert pcb.state == ProcessState.TERMINATED
    assert pcb.started_at is not None
    assert pcb.ended_at is not None
    assert pcb.exit_code == 0
    assert pcb.turnaround_time is not None
    assert pcb.waiting_time is not None


def test_dispatcher_audit_log_persisted(dispatcher_suite: dict):
    """Verify that dispatched syscalls are recorded in SQLite audit table."""
    dispatcher: SyscallDispatcher = dispatcher_suite["dispatcher"]
    db: DatabaseManager = dispatcher_suite["db"]

    req = SyscallRequest(
        syscall=SyscallType.SYS_INFO,
        params={},
    )
    res = dispatcher.dispatch(req)
    assert res.success is True

    logs = db.get_audit_logs(limit=10)
    assert len(logs) >= 1
    recent = logs[0]
    assert recent["syscall"] == "SYS_INFO"
    assert recent["success"] == 1
    assert recent["call_id"] == req.call_id
