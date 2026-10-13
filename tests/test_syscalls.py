"""Tests for kernel/syscalls.py: SyscallRequest, SyscallResult, and PrivilegeRing."""

import json
from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)


def test_syscall_types_and_rings():
    """Verify standard syscall types and their security ring classification."""
    assert SyscallType.PROC_SPAWN.value == "PROC_SPAWN"
    assert SyscallType.FILE_SEARCH.value == "FILE_SEARCH"
    assert SyscallType.FILE_DELETE.value == "FILE_DELETE"
    assert SyscallType.APP_OPEN.value == "APP_OPEN"

    # Verify default rings
    assert DEFAULT_SYSCALL_RINGS[SyscallType.FILE_SEARCH] == PrivilegeRing.RING_3
    assert DEFAULT_SYSCALL_RINGS[SyscallType.SYS_INFO] == PrivilegeRing.RING_3
    assert DEFAULT_SYSCALL_RINGS[SyscallType.PROC_SPAWN] == PrivilegeRing.RING_0
    assert DEFAULT_SYSCALL_RINGS[SyscallType.FILE_DELETE] == PrivilegeRing.RING_0
    assert DEFAULT_SYSCALL_RINGS[SyscallType.APP_OPEN] == PrivilegeRing.RING_0


def test_syscall_request_automatic_ring_assignment():
    """Verify that SyscallRequest auto-assigns the correct default ring."""
    # FILE_SEARCH should default to Ring 3
    req_search = SyscallRequest(
        syscall=SyscallType.FILE_SEARCH,
        params={"pattern": "*.py"},
    )
    assert req_search.ring == PrivilegeRing.RING_3
    assert req_search.call_id is not None
    assert req_search.params["pattern"] == "*.py"

    # PROC_SPAWN should default to Ring 0
    req_spawn = SyscallRequest(
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": ["python", "app.py"]},
    )
    assert req_spawn.ring == PrivilegeRing.RING_0


def test_syscall_request_explicit_ring_override():
    """Verify explicit ring override takes precedence."""
    req = SyscallRequest(
        syscall=SyscallType.FILE_READ,
        params={"path": "sensitive.txt"},
        ring=PrivilegeRing.RING_0,
    )
    assert req.ring == PrivilegeRing.RING_0


def test_syscall_result_ok_factory():
    """Verify SyscallResult.ok() factory."""
    req = SyscallRequest(
        syscall=SyscallType.FILE_SEARCH,
        params={"pattern": "*.java"},
    )
    res = SyscallResult.ok(
        request=req,
        output="Main.java\nTest.java",
        data=["Main.java", "Test.java"],
        duration_sec=0.045,
    )

    assert res.call_id == req.call_id
    assert res.syscall == SyscallType.FILE_SEARCH
    assert res.success is True
    assert res.output == "Main.java\nTest.java"
    assert res.data == ["Main.java", "Test.java"]
    assert res.error is None
    assert res.exit_code == 0
    assert res.duration_sec == 0.045


def test_syscall_result_fail_factory():
    """Verify SyscallResult.fail() factory."""
    req = SyscallRequest(
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": ["javac", "NotFound.java"]},
    )
    res = SyscallResult.fail(
        request=req,
        error="File not found: NotFound.java",
        exit_code=2,
        duration_sec=0.12,
    )

    assert res.call_id == req.call_id
    assert res.syscall == SyscallType.PROC_SPAWN
    assert res.success is False
    assert res.error == "File not found: NotFound.java"
    assert res.exit_code == 2
    assert res.duration_sec == 0.12


def test_syscall_serialization():
    """Verify JSON serialization and reconstruction roundtrip."""
    req = SyscallRequest(
        syscall=SyscallType.FILE_WRITE,
        params={"path": "test.txt", "content": "hello world"},
    )
    json_str = req.model_dump_json()
    data = json.loads(json_str)
    assert data["syscall"] == "FILE_WRITE"
    assert data["ring"] == 0

    reconstructed = SyscallRequest.model_validate(data)
    assert reconstructed.call_id == req.call_id
    assert reconstructed.syscall == req.syscall
    assert reconstructed.ring == req.ring
