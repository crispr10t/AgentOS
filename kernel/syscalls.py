"""System Call Data Models and Privilege Classification.

Defines the typed boundary between the user-space Cognitive Shell
and the Micro-Supervisor Kernel.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from pathlib import Path
import time
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
    APP_OPEN = "APP_OPEN"
    APP_CLOSE = "APP_CLOSE"
    APP_OPEN_URL = "APP_OPEN_URL"
    APP_CLOSE_TAB = "APP_CLOSE_TAB"
    CALCULATE = "CALCULATE"
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
    SyscallType.APP_OPEN: PrivilegeRing.RING_0,
    SyscallType.APP_CLOSE: PrivilegeRing.RING_0,
    SyscallType.APP_OPEN_URL: PrivilegeRing.RING_0,
    SyscallType.APP_CLOSE_TAB: PrivilegeRing.RING_0,
    SyscallType.CALCULATE: PrivilegeRing.RING_3,
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
        data: Optional[Any] = None,
        exit_code: int = 1,
        duration_sec: float = 0.0,
    ) -> SyscallResult:
        """Helper to create a failed SyscallResult from a request."""
        return cls(
            call_id=request.call_id,
            syscall=request.syscall,
            success=False,
            output=output,
            data=data,
            error=error,
            exit_code=exit_code,
            duration_sec=max(0.0, float(duration_sec)),
        )


class SyscallDispatcher:
    """Dispatches validated system calls to underlying OS and filesystem subsystems.

    Enforces privilege separation, updates PCB state and performance metrics,
    and logs actions to the SQLite audit database.
    """

    def __init__(
        self,
        privilege_gate: Optional[Any] = None,
        process_manager: Optional[Any] = None,
        file_engine: Optional[Any] = None,
        db_manager: Optional[Any] = None,
    ):
        """Initializes the SyscallDispatcher with required subsystems.

        Subsystems will be dynamically imported and instantiated with default
        settings if not explicitly provided.
        """
        if privilege_gate is None:
            from security.privilege import PrivilegeGate

            self.privilege_gate = PrivilegeGate()
        else:
            self.privilege_gate = privilege_gate

        if process_manager is None:
            from kernel.process_manager import ProcessManager

            self.process_manager = ProcessManager()
        else:
            self.process_manager = process_manager

        if db_manager is None:
            from storage.db import DatabaseManager

            self.db_manager = DatabaseManager()
        else:
            self.db_manager = db_manager

        if file_engine is None:
            from kernel.file_engine import FileEngine
            from storage.journal import TransactionJournal

            journal = TransactionJournal(db_manager=self.db_manager)
            self.file_engine = FileEngine(journal=journal, db_manager=self.db_manager)
        else:
            self.file_engine = file_engine
            if (
                hasattr(self.file_engine, "journal")
                and self.file_engine.journal is not None
                and db_manager is not None
                and self.file_engine.journal.db_manager != self.db_manager
            ):
                self.file_engine.journal.db_manager = self.db_manager
                self.file_engine.journal._ensure_journal_schema()

    def dispatch(
        self,
        request: SyscallRequest,
        pcb: Optional[Any] = None,
        user_confirmed: bool = False,
    ) -> SyscallResult:
        """Executes a system call through the appropriate kernel subsystem.

        Args:
            request: The SyscallRequest to execute.
            pcb: Optional TaskPCB to transition and record metrics for.
            user_confirmed: True if Ring 0 elevation has been granted by user.

        Returns:
            SyscallResult with execution output, exit code, and runtime metrics.
        """
        # 1. Update PCB lifecycle to READY -> RUNNING
        if pcb is not None:
            from kernel.pcb import ProcessState

            if pcb.state == ProcessState.NEW:
                pcb.transition_to(ProcessState.READY)
            if pcb.state == ProcessState.READY:
                pcb.transition_to(ProcessState.RUNNING)

        # 2. Check privilege ring permission
        if not self.privilege_gate.check_privilege(request, user_confirmed=user_confirmed):
            result = SyscallResult.fail(
                request=request,
                error=(
                    f"PERMISSION_DENIED: System call '{request.syscall.value}' requires "
                    f"Ring 0 privilege elevation approval."
                ),
                exit_code=126,
                duration_sec=0.0,
            )
            self._finalize(request, result, pcb)
            return result

        # 3. Route to subsystem
        params = request.params or {}
        try:
            if request.syscall == SyscallType.APP_OPEN:
                app_name = params.get("app")
                if not app_name:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'app'.",
                        exit_code=1,
                    )
                else:
                    result = self.process_manager.open_application(
                        app_name=app_name,
                        request=request,
                    )
            elif request.syscall == SyscallType.APP_CLOSE:
                app_name = params.get("app")
                if not app_name:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'app'.",
                        exit_code=1,
                    )
                else:
                    result = self.process_manager.close_application(
                        app_name=app_name,
                        request=request,
                    )
            elif request.syscall == SyscallType.APP_OPEN_URL:
                url = params.get("url")
                if not url:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'url'.",
                        exit_code=1,
                    )
                else:
                    result = self.process_manager.open_edge_url(
                        url=url,
                        request=request,
                    )
            elif request.syscall == SyscallType.APP_CLOSE_TAB:
                result = self.process_manager.close_edge_tab(
                    url=params.get("url"),
                    pid=params.get("pid"),
                    request=request,
                )
            elif request.syscall == SyscallType.CALCULATE:
                expression = params.get("expression")
                if not expression:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'expression'.",
                        exit_code=1,
                    )
                else:
                    result = self.process_manager.calculate_expression(
                        expression=expression,
                        request=request,
                    )
            elif request.syscall == SyscallType.PROC_SPAWN:
                cmd = params.get("cmd")
                if not cmd:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'cmd'.",
                        exit_code=1,
                    )
                else:
                    exec_cwd = params.get("cwd")
                    s_root = getattr(self.file_engine, "sandbox_root", None)

                    # Determine target script from command tokens
                    target_script = ""
                    if isinstance(cmd, list) and len(cmd) > 1 and not str(cmd[1]).startswith("-"):
                        target_script = str(cmd[1])
                    elif isinstance(cmd, list) and len(cmd) > 0 and not str(cmd[0]).startswith("-"):
                        target_script = str(cmd[0])
                    elif isinstance(cmd, str):
                        tokens_tmp = cmd.split()
                        if len(tokens_tmp) > 1 and not tokens_tmp[1].startswith("-"):
                            target_script = tokens_tmp[1]
                        elif len(tokens_tmp) > 0 and not tokens_tmp[0].startswith("-"):
                            target_script = tokens_tmp[0]

                    # Determine working directory: prefer specified cwd if script exists there, otherwise check sandbox
                    if target_script and s_root:
                        script_in_cwd = (Path(exec_cwd or ".") / target_script).exists()
                        script_in_sandbox = (Path(s_root) / target_script).exists()
                        if script_in_cwd:
                            pass
                        elif script_in_sandbox:
                            exec_cwd = s_root
                    elif exec_cwd is None and s_root:
                        exec_cwd = s_root

                    result = self.process_manager.spawn(
                        cmd=cmd,
                        timeout_sec=params.get("timeout") or params.get("timeout_sec"),
                        memory_limit_mb=params.get("memory_limit_mb"),
                        cwd=exec_cwd,
                        env=params.get("env"),
                        stdin_data=params.get("stdin_data"),
                        request=request,
                    )
            elif request.syscall == SyscallType.PROC_KILL:
                pid = params.get("pid")
                if pid is None:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'pid'.",
                        exit_code=1,
                    )
                else:
                    result = self.process_manager.kill_process(
                        pid=int(pid), request=request
                    )
            elif request.syscall == SyscallType.FILE_SEARCH:
                result = self.file_engine.file_search(
                    pattern=params.get("pattern", "*"),
                    relative_to=params.get("relative_to"),
                    max_results=params.get("max_results", 100),
                    request=request,
                )
            elif request.syscall == SyscallType.FILE_READ:
                path = params.get("path")
                if not path:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'path'.",
                        exit_code=1,
                    )
                else:
                    result = self.file_engine.file_read(
                        file_path=path,
                        max_bytes=params.get("max_bytes", 1024 * 1024),
                        encoding=params.get("encoding", "utf-8"),
                        request=request,
                    )
            elif request.syscall == SyscallType.FILE_WRITE:
                path = params.get("path")
                if not path:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'path'.",
                        exit_code=1,
                    )
                else:
                    result = self.file_engine.file_write(
                        file_path=path,
                        content=params.get("content", ""),
                        mode=params.get("mode", "w"),
                        encoding=params.get("encoding", "utf-8"),
                        request=request,
                    )
            elif request.syscall == SyscallType.FILE_MOVE:
                src = params.get("src")
                dest = params.get("dest")
                if not src or not dest:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameters 'src' and 'dest'.",
                        exit_code=1,
                    )
                else:
                    result = self.file_engine.file_move(
                        src_path=src, dest_path=dest, request=request
                    )
            elif request.syscall == SyscallType.FILE_DELETE:
                path = params.get("path")
                if not path:
                    result = SyscallResult.fail(
                        request=request,
                        error="Missing required parameter 'path'.",
                        exit_code=1,
                    )
                else:
                    result = self.file_engine.file_delete(
                        file_path=path,
                        quarantine=params.get("quarantine", True),
                        request=request,
                    )
            elif request.syscall == SyscallType.SYS_INFO:
                result = self.file_engine.get_sys_info(request=request)
            else:
                result = SyscallResult.fail(
                    request=request,
                    error=f"Unsupported system call type: '{request.syscall}'",
                    exit_code=38,
                )
        except Exception as exc:
            result = SyscallResult.fail(
                request=request,
                error=f"Unhandled kernel exception during '{request.syscall.value}': {exc}",
                exit_code=1,
            )

        # 4. Finalize PCB & audit log
        self._finalize(request, result, pcb)
        return result

    def _finalize(
        self,
        request: SyscallRequest,
        result: SyscallResult,
        pcb: Optional[Any] = None,
    ) -> None:
        """Updates PCB metrics/lifecycle and logs syscall audit records."""
        if pcb is not None:
            from kernel.pcb import ProcessState

            cpu_time = 0.0
            peak_mem = 0.0
            if result.data and isinstance(result.data, dict):
                cpu_time = float(result.data.get("cpu_time", 0.0))
                peak_mem = float(result.data.get("peak_memory_mb", 0.0))

            pcb.record_metrics(
                cpu_time=cpu_time,
                peak_memory_mb=peak_mem,
                exit_code=result.exit_code,
                error_msg=result.error,
            )
            if pcb.state != ProcessState.TERMINATED:
                pcb.transition_to(ProcessState.TERMINATED)

            if self.db_manager is not None:
                self.db_manager.save_task(pcb)

        if self.db_manager is not None:
            self.db_manager.log_syscall(
                request=request,
                result=result,
                pid=pcb.pid if pcb is not None else None,
            )

    def undo_last_action(self) -> SyscallResult:
        """Rolls back the most recent un-reverted sandboxed file modification.

        Returns:
            SyscallResult containing status, output, and transaction details.
        """
        start_time = time.time()
        undo_req = SyscallRequest(
            syscall=SyscallType.FILE_DELETE,
            params={"action": "UNDO_LAST"},
            ring=PrivilegeRing.RING_0,
        )
        if self.file_engine is None:
            return SyscallResult.fail(
                request=undo_req,
                error="FileEngine not initialized in dispatcher.",
                duration_sec=0.0,
            )

        res = self.file_engine.undo_last_action()
        duration = time.time() - start_time

        if res.success:
            entry_data = res.entry.model_dump() if res.entry else None
            result = SyscallResult.ok(
                request=undo_req,
                output=res.message,
                data=entry_data,
                duration_sec=duration,
            )
        else:
            entry_data = res.entry.model_dump() if res.entry else None
            result = SyscallResult.fail(
                request=undo_req,
                error=res.message,
                data=entry_data,
                duration_sec=duration,
            )

        if self.db_manager is not None:
            self.db_manager.log_syscall(request=undo_req, result=result)

        return result
