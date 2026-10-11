"""System Call Data Models and Privilege Classification.

Defines the typed boundary between the user-space Cognitive Shell
and the Micro-Supervisor Kernel.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Any, Optional
import uuid

from pydantic import BaseModel, Field


class PrivilegeRing(IntEnum):
    """Privilege rings separating unprivileged and privileged supervisor calls."""

    RING_0 = 0  # Privileged / Destructive: Requires explicit confirmation if guarded
    RING_3 = 3  # Unprivileged / Safe: Executed automatically


class SyscallType(str, Enum):
    """Supported System Call primitives dispatched by the Micro-Supervisor."""

    PROC_SPAWN = "PROC_SPAWN"
    PROC_KILL = "PROC_KILL"
    FILE_SEARCH = "FILE_SEARCH"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_MOVE = "FILE_MOVE"
    FILE_DELETE = "FILE_DELETE"
    SYS_INFO = "SYS_INFO"


# Mapping of default privilege rings for each syscall
DEFAULT_SYSCALL_RINGS: dict[SyscallType, PrivilegeRing] = {
    SyscallType.PROC_SPAWN: PrivilegeRing.RING_0,
    SyscallType.PROC_KILL: PrivilegeRing.RING_0,
    SyscallType.FILE_SEARCH: PrivilegeRing.RING_3,
    SyscallType.FILE_READ: PrivilegeRing.RING_3,
    SyscallType.FILE_WRITE: PrivilegeRing.RING_0,
    SyscallType.FILE_MOVE: PrivilegeRing.RING_0,
    SyscallType.FILE_DELETE: PrivilegeRing.RING_0,
    SyscallType.SYS_INFO: PrivilegeRing.RING_3,
}


class SyscallRequest(BaseModel):
    """Structured request packet invoking a Micro-Supervisor system call."""

    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    syscall: SyscallType
    params: dict[str, Any] = Field(default_factory=dict)
    ring: PrivilegeRing = PrivilegeRing.RING_3

    def __init__(self, **data: Any):
        # Automatically assign default ring if not explicitly provided
        if "ring" not in data and "syscall" in data:
            sc_val = data["syscall"]
            if isinstance(sc_val, str):
                try:
                    sc_val = SyscallType(sc_val)
                except ValueError:
                    pass
            if isinstance(sc_val, SyscallType):
                data["ring"] = DEFAULT_SYSCALL_RINGS.get(sc_val, PrivilegeRing.RING_3)
        super().__init__(**data)


class SyscallResult(BaseModel):
    """Result packet returned following system call execution by the kernel."""

    call_id: str
    syscall: SyscallType
    success: bool
    output: Optional[str] = None
    data: Optional[Any] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    duration_sec: float = 0.0

    @classmethod
    def ok(
        cls,
        request: SyscallRequest,
        output: Optional[str] = None,
        data: Optional[Any] = None,
        duration_sec: float = 0.0,
        exit_code: int = 0,
    ) -> SyscallResult:
        """Helper to create a successful SyscallResult from a request."""
        return cls(
            call_id=request.call_id,
            syscall=request.syscall,
            success=True,
            output=output,
            data=data,
            exit_code=exit_code,
            duration_sec=max(0.0, float(duration_sec)),
        )

    @classmethod
    def fail(
        cls,
        request: SyscallRequest,
        error: str,
        output: Optional[str] = None,
        exit_code: int = 1,
        duration_sec: float = 0.0,
    ) -> SyscallResult:
        """Helper to create a failed SyscallResult from a request."""
        return cls(
            call_id=request.call_id,
            syscall=request.syscall,
            success=False,
            output=output,
            error=error,
            exit_code=exit_code,
            duration_sec=max(0.0, float(duration_sec)),
        )
