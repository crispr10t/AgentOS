"""Comprehensive edge-case tests for kernel/syscalls.py: SyscallRequest, SyscallResult, and PrivilegeRing."""

import json
import uuid
import pytest
from pydantic import ValidationError

from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)


# --- 1. Exhaustive SyscallType and Ring Mapping ---

@pytest.mark.parametrize("syscall_type, expected_ring", [
    (SyscallType.PROC_SPAWN, PrivilegeRing.RING_0),
    (SyscallType.PROC_KILL, PrivilegeRing.RING_0),
    (SyscallType.APP_OPEN, PrivilegeRing.RING_0),
    (SyscallType.APP_OPEN_URL, PrivilegeRing.RING_0),
    (SyscallType.APP_CLOSE_TAB, PrivilegeRing.RING_0),
    (SyscallType.FILE_WRITE, PrivilegeRing.RING_0),
    (SyscallType.FILE_MOVE, PrivilegeRing.RING_0),
    (SyscallType.FILE_DELETE, PrivilegeRing.RING_0),
    (SyscallType.CALCULATE, PrivilegeRing.RING_3),
    (SyscallType.FILE_SEARCH, PrivilegeRing.RING_3),
    (SyscallType.FILE_READ, PrivilegeRing.RING_3),
    (SyscallType.SYS_INFO, PrivilegeRing.RING_3),
])
def test_all_syscall_types_default_rings(syscall_type: SyscallType, expected_ring: PrivilegeRing):
    """Verify that every single SyscallType is accurately classified by default."""
    assert DEFAULT_SYSCALL_RINGS[syscall_type] == expected_ring

    # Also verify request auto-assigns the ring when omitted
    req = SyscallRequest(syscall=syscall_type)
    assert req.ring == expected_ring


@pytest.mark.parametrize("syscall_type", list(SyscallType))
def test_explicit_ring_override_all_syscalls(syscall_type: SyscallType):
    """Explicitly specified rings must override default classification."""
    default = DEFAULT_SYSCALL_RINGS[syscall_type]
    inverted = PrivilegeRing.RING_3 if default == PrivilegeRing.RING_0 else PrivilegeRing.RING_0

    req = SyscallRequest(syscall=syscall_type, ring=inverted)
    assert req.ring == inverted


# --- 2. SyscallRequest Validation and Edge Cases ---

def test_syscall_request_string_syscall_type():
    """String syscall names should be accepted and converted to SyscallType enum."""
    req = SyscallRequest(syscall="CALCULATE")
    assert req.syscall == SyscallType.CALCULATE
    assert req.ring == PrivilegeRing.RING_3


def test_syscall_request_custom_call_id():
    """Explicit call_id should be preserved."""
    custom_id = "test-call-id-999"
    req = SyscallRequest(syscall=SyscallType.SYS_INFO, call_id=custom_id)
    assert req.call_id == custom_id


def test_syscall_request_uuid_uniqueness():
    """Generated call_ids must be unique across requests."""
    req1 = SyscallRequest(syscall=SyscallType.SYS_INFO)
    req2 = SyscallRequest(syscall=SyscallType.SYS_INFO)
    assert req1.call_id != req2.call_id


def test_syscall_request_missing_syscall_raises():
    """Omitting the required syscall argument must raise ValidationError."""
    with pytest.raises(ValidationError):
        SyscallRequest()  # type: ignore


@pytest.mark.parametrize("nested_params", [
    {},
    {"nested": {"a": [1, 2, 3], "b": {"c": "deep"}}},
    {"unicode_key": "🚀", "empty_str": ""},
    {"null_val": None, "bool_val": False},
])
def test_syscall_request_arbitrary_params(nested_params: dict):
    """Verify params dictionary accepts complex and nested datatypes."""
    req = SyscallRequest(syscall=SyscallType.FILE_SEARCH, params=nested_params)
    assert req.params == nested_params


# --- 3. SyscallResult Factory Edge Cases ---

@pytest.mark.parametrize("data_payload", [
    None,
    "plain text",
    {"status": "ok", "items": [1, 2, 3]},
    [{"id": 1}, {"id": 2}],
    42,
    3.14159,
    True,
])
def test_syscall_result_ok_various_payloads(data_payload):
    """Verify SyscallResult.ok handles various data payload types correctly."""
    req = SyscallRequest(syscall=SyscallType.CALCULATE)
    res = SyscallResult.ok(request=req, output="done", data=data_payload, duration_sec=0.05)
    assert res.success is True
    assert res.exit_code == 0
    assert res.output == "done"
    assert res.data == data_payload
    assert res.duration_sec == 0.05
    assert res.error is None
    assert res.call_id == req.call_id
    assert res.syscall == req.syscall


@pytest.mark.parametrize("exit_code, error_msg", [
    (1, "Generic error"),
    (126, "Permission denied"),
    (127, "Command not found"),
    (-1, "Process terminated by signal"),
])
def test_syscall_result_fail_factories(exit_code: int, error_msg: str):
    """Verify SyscallResult.fail accurately structures error metadata and return codes."""
    req = SyscallRequest(syscall=SyscallType.PROC_SPAWN)
    res = SyscallResult.fail(request=req, error=error_msg, exit_code=exit_code, duration_sec=0.1)
    assert res.success is False
    assert res.exit_code == exit_code
    assert res.error == error_msg
    assert res.duration_sec == 0.1
    assert res.call_id == req.call_id


# --- 4. Serialization Roundtrip ---

def test_syscall_request_and_result_json_serialization():
    """Verify JSON dumping and reconstruction of SyscallRequest and SyscallResult."""
    req = SyscallRequest(
        syscall=SyscallType.FILE_WRITE,
        params={"path": "demo.txt", "content": "hello world"},
        ring=PrivilegeRing.RING_0,
    )
    req_json = req.model_dump_json()
    req_loaded = SyscallRequest.model_validate_json(req_json)
    assert req_loaded.call_id == req.call_id
    assert req_loaded.syscall == req.syscall
    assert req_loaded.ring == req.ring
    assert req_loaded.params == req.params

    res = SyscallResult.ok(request=req, output="Written 11 bytes", data={"bytes": 11})
    res_json = res.model_dump_json()
    res_loaded = SyscallResult.model_validate_json(res_json)
    assert res_loaded.call_id == req.call_id
    assert res_loaded.success is True
    assert res_loaded.data == {"bytes": 11}
