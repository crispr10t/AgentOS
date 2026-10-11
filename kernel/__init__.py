"""AgentOS Kernel Layer.

Exposes core OS abstractions:
- Process Control Block (TaskPCB) and lifecycle states (ProcessState)
- System Call definitions (SyscallType, PrivilegeRing, SyscallRequest, SyscallResult)
- Syscall Dispatcher (SyscallDispatcher)
- Process Execution Engine and Watchdog (ProcessManager, ProcessSecurityError)
- Sandboxed Filesystem Engine (FileEngine)
"""

from kernel.file_engine import FileEngine
from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import ProcessManager, ProcessSecurityError
from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)

__all__ = [
    "ProcessState",
    "TaskPCB",
    "SyscallType",
    "PrivilegeRing",
    "DEFAULT_SYSCALL_RINGS",
    "SyscallRequest",
    "SyscallResult",
    "SyscallDispatcher",
    "ProcessManager",
    "ProcessSecurityError",
    "FileEngine",
]
