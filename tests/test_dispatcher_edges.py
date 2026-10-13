"""Comprehensive edge-case tests for kernel/syscalls.py: SyscallDispatcher routing, missing parameters, and PCB integration."""

from pathlib import Path
import pytest

from kernel.file_engine import FileEngine
from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import ProcessManager
from kernel.syscalls import (
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)
from security.privilege import PrivilegeGate
from storage.db import DatabaseManager


@pytest.fixture
def dispatcher_fixture(tmp_path: Path):
    """Fixture providing isolated SyscallDispatcher and dependencies."""
    sandbox = tmp_path / "disp_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    gate = PrivilegeGate(enable_ring0_prompt=False)  # Auto-permit for dispatcher tests
    pm = ProcessManager()
    fe = FileEngine(sandbox_root=sandbox, db_manager=db)

    dispatcher = SyscallDispatcher(
        privilege_gate=gate,
        process_manager=pm,
        file_engine=fe,
        db_manager=db,
    )
    return dispatcher, sandbox, db


# --- 1. Missing Required Parameters for Each Syscall ---

@pytest.mark.parametrize("syscall_type, empty_params, expected_missing", [
    (SyscallType.APP_OPEN, {}, "Missing required parameter 'app'"),
    (SyscallType.APP_OPEN_URL, {}, "Missing required parameter 'url'"),
    (SyscallType.CALCULATE, {}, "Missing required parameter 'expression'"),
    (SyscallType.PROC_SPAWN, {}, "Missing required parameter 'cmd'"),
    (SyscallType.PROC_KILL, {}, "Missing required parameter 'pid'"),
    (SyscallType.FILE_READ, {}, "Missing required parameter 'path'"),
    (SyscallType.FILE_WRITE, {}, "Missing required parameter 'path'"),
    (SyscallType.FILE_MOVE, {"src": "a.txt"}, "Missing required parameters 'src' and 'dest'"),
    (SyscallType.FILE_MOVE, {"dest": "b.txt"}, "Missing required parameters 'src' and 'dest'"),
    (SyscallType.FILE_DELETE, {}, "Missing required parameter 'path'"),
])
def test_dispatcher_missing_parameters_rejected(dispatcher_fixture, syscall_type: SyscallType, empty_params: dict, expected_missing: str):
    """Verify dispatcher returns fail when required parameters are omitted."""
    dispatcher, _, _ = dispatcher_fixture
    req = SyscallRequest(syscall=syscall_type, params=empty_params)

    res = dispatcher.dispatch(req, user_confirmed=True)
    assert res.success is False
    assert res.exit_code == 1
    assert expected_missing in (res.error or "")


# --- 2. PCB Lifecycle Progression During Dispatch ---

def test_dispatcher_transitions_pcb_from_new_to_running_and_terminated(dispatcher_fixture):
    """Verify PCB transitions through lifecycle and records timestamps."""
    dispatcher, _, _ = dispatcher_fixture
    pcb = TaskPCB(pid=900, name="calc_pcb")
    assert pcb.state == ProcessState.NEW

    req = SyscallRequest(syscall=SyscallType.CALCULATE, params={"expression": "5 * 5"})
    res = dispatcher.dispatch(req, pcb=pcb)

    assert res.success is True
    assert pcb.state == ProcessState.TERMINATED
    assert pcb.started_at is not None
    assert pcb.ended_at is not None
    assert pcb.exit_code == 0
    assert pcb.turnaround_time is not None


def test_dispatcher_pcb_records_error_exit_code_on_failure(dispatcher_fixture):
    """Verify PCB records non-zero exit code and error message on failed syscall."""
    dispatcher, _, _ = dispatcher_fixture
    pcb = TaskPCB(pid=901, name="failing_pcb")

    req = SyscallRequest(syscall=SyscallType.FILE_READ, params={"path": "nonexistent.txt"})
    res = dispatcher.dispatch(req, pcb=pcb)

    assert res.success is False
    assert pcb.state == ProcessState.TERMINATED
    assert pcb.exit_code == 1
    assert pcb.error_msg is not None


# --- 3. Audit Logging on Dispatch ---

def test_dispatcher_audit_log_persists_for_both_success_and_fail(dispatcher_fixture):
    """Verify every dispatch logs an entry to the database."""
    dispatcher, _, db = dispatcher_fixture

    # 1. Successful SYS_INFO
    req1 = SyscallRequest(syscall=SyscallType.SYS_INFO)
    dispatcher.dispatch(req1)

    # 2. Failed FILE_READ
    req2 = SyscallRequest(syscall=SyscallType.FILE_READ, params={})
    dispatcher.dispatch(req2)

    logs = db.get_audit_logs(limit=10)
    assert len(logs) >= 2
    # Verify both calls are recorded
    call_ids = [l["call_id"] for l in logs]
    assert req1.call_id in call_ids
    assert req2.call_id in call_ids
