"""Process Execution Engine, Watchdog, and Process Tree Manager.

Implements supervised process lifecycle execution with recursive tree termination,
watchdog timeout enforcement, peak resident memory monitoring, and command sanitization.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
from typing import Optional

from dotenv import load_dotenv
import psutil

from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallResult, SyscallType

load_dotenv()

# Pre-approved binary base names for sandbox execution
DEFAULT_ALLOWED_EXECUTABLES: set[str] = {
    "python",
    "python3",
    "py",
    "javac",
    "java",
    "gcc",
    "g++",
    "node",
    "git",
    "echo",
    "cat",
    "dir",
    "ls",
    "pytest",
}

# Forbidden shell wrapper prefixes that bypass structured execution
PROHIBITED_SHELL_PREFIXES: list[list[str]] = [
    ["cmd.exe", "/c"],
    ["cmd", "/c"],
    ["powershell.exe", "-command"],
    ["powershell", "-command"],
    ["sh", "-c"],
    ["bash", "-c"],
    ["zsh", "-c"],
]


class ProcessSecurityError(ValueError):
    """Raised when an unapproved or unsafe command invocation is attempted."""

    pass


class ProcessManager:
    """Supervises child process lifecycle, watchdog timing, and resource caps."""

    def __init__(
        self,
        default_timeout: Optional[int] = None,
        default_memory_limit_mb: Optional[int] = None,
        allowed_executables: Optional[set[str]] = None,
        enforce_whitelist: bool = True,
    ):
        """Initializes the ProcessManager.

        Args:
            default_timeout: Watchdog timeout in seconds (defaults to SUBPROCESS_TIMEOUT_SECONDS or 10).
            default_memory_limit_mb: Memory ceiling in MB (defaults to MAX_PROCESS_MEMORY_MB or 512).
            allowed_executables: Custom set of approved executable names.
            enforce_whitelist: Whether to reject binaries outside the approved whitelist.
        """
        if default_timeout is None:
            self.default_timeout = int(os.getenv("SUBPROCESS_TIMEOUT_SECONDS", "10"))
        else:
            self.default_timeout = int(default_timeout)

        if default_memory_limit_mb is None:
            self.default_memory_limit_mb = int(os.getenv("MAX_PROCESS_MEMORY_MB", "512"))
        else:
            self.default_memory_limit_mb = int(default_memory_limit_mb)

        self.enforce_whitelist = enforce_whitelist
        self.allowed_executables = set(
            allowed_executables if allowed_executables is not None else DEFAULT_ALLOWED_EXECUTABLES
        )
        # Always allow current Python interpreter
        current_py_stem = Path(sys.executable).stem.lower()
        self.allowed_executables.add(current_py_stem)
        self.allowed_executables.add(sys.executable.lower())

    def validate_command(self, cmd: list[str] | str) -> list[str]:
        """Validates command structure and ensures no shell escape wrappers are present.

        Args:
            cmd: Command argument list or command string.

        Returns:
            Sanitized list of string command tokens.

        Raises:
            ProcessSecurityError: If the command is malformed, uses prohibited wrappers,
                or uses an unauthorized binary.
        """
        if isinstance(cmd, str):
            tokens = shlex.split(cmd, posix=(sys.platform != "win32"))
        elif isinstance(cmd, (list, tuple)):
            tokens = [str(arg) for arg in cmd]
        else:
            raise ProcessSecurityError(f"Command must be a list of strings or string, got {type(cmd).__name__}")

        if not tokens:
            raise ProcessSecurityError("Command cannot be empty.")

        # Check for prohibited shell wrappers
        lower_tokens = [t.lower() for t in tokens[:2]]
        for prohibited in PROHIBITED_SHELL_PREFIXES:
            if len(lower_tokens) >= len(prohibited):
                if lower_tokens[: len(prohibited)] == [p.lower() for p in prohibited]:
                    raise ProcessSecurityError(
                        f"Prohibited shell wrapper invocation detected: '{' '.join(tokens[:2])}'"
                    )

        # Validate executable against whitelist
        if self.enforce_whitelist:
            raw_binary = tokens[0]
            bin_path = Path(raw_binary)
            bin_name = bin_path.stem.lower()
            bin_full = str(bin_path.resolve()).lower() if bin_path.is_absolute() else ""

            is_allowed = (
                bin_name in self.allowed_executables
                or raw_binary.lower() in self.allowed_executables
                or (bin_full and bin_full in self.allowed_executables)
            )

            if not is_allowed:
                raise ProcessSecurityError(
                    f"Executable '{raw_binary}' is not in the approved whitelist: "
                    f"{sorted(self.allowed_executables)}"
                )

        return tokens

    @staticmethod
    def kill_process_tree(pid: int) -> bool:
        """Recursively terminates a process and all of its descendants.

        Args:
            pid: Process ID to terminate.

        Returns:
            True if process tree was found and killed, False if already exited or not found.
        """
        try:
            parent = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

        try:
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.kill()
            psutil.wait_procs(children + [parent], timeout=1.0)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True

    def spawn(
        self,
        cmd: list[str] | str,
        timeout_sec: Optional[int] = None,
        memory_limit_mb: Optional[int] = None,
        cwd: Optional[Path | str] = None,
        env: Optional[dict[str, str]] = None,
        stdin_data: Optional[str] = None,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Spawns and supervises a child process with watchdog timeout and memory caps.

        Args:
            cmd: Command argument list or command string.
            timeout_sec: Watchdog timeout limit in seconds.
            memory_limit_mb: Resident memory ceiling in MB.
            cwd: Working directory for process execution.
            env: Custom environment dictionary.
            stdin_data: Optional standard input string to pipe.
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult containing stdout/stderr, exit code, execution metrics, and status.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.PROC_SPAWN,
            params={"cmd": cmd},
            ring=PrivilegeRing.RING_0,
        )

        timeout = self.default_timeout if timeout_sec is None else max(1, int(timeout_sec))
        mem_limit = (
            self.default_memory_limit_mb
            if memory_limit_mb is None
            else max(10, int(memory_limit_mb))
        )

        start_time = time.time()

        try:
            tokens = self.validate_command(cmd)
        except ProcessSecurityError as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        exec_cwd = str(Path(cwd).resolve()) if cwd is not None else None
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        try:
            proc = subprocess.Popen(
                tokens,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                cwd=exec_cwd,
                env=merged_env,
            )
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Failed to spawn process '{tokens[0]}': {exc}",
                exit_code=127,
                duration_sec=time.time() - start_time,
            )

        stop_watchdog = threading.Event()
        timed_out = threading.Event()
        mem_exceeded = threading.Event()
        peak_memory_mb = [0.0]
        total_cpu_time = [0.0]

        def watchdog_loop() -> None:
            """Background thread monitoring elapsed execution time and memory consumption."""
            try:
                p = psutil.Process(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return

            while not stop_watchdog.is_set():
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    timed_out.set()
                    self.kill_process_tree(proc.pid)
                    return

                try:
                    if not p.is_running():
                        return

                    # Sample resident memory
                    rss = p.memory_info().rss / (1024 * 1024)
                    cpu_t = p.cpu_times().user + p.cpu_times().system
                    for child in p.children(recursive=True):
                        try:
                            rss += child.memory_info().rss / (1024 * 1024)
                            child_cpu = child.cpu_times()
                            cpu_t += child_cpu.user + child_cpu.system
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    if rss > peak_memory_mb[0]:
                        peak_memory_mb[0] = rss
                    if cpu_t > total_cpu_time[0]:
                        total_cpu_time[0] = cpu_t

                    if rss > mem_limit:
                        mem_exceeded.set()
                        self.kill_process_tree(proc.pid)
                        return
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return

                time.sleep(0.05)

        watchdog_thread = threading.Thread(target=watchdog_loop, daemon=True)
        watchdog_thread.start()

        stdout_data = ""
        stderr_data = ""
        try:
            stdout_data, stderr_data = proc.communicate(input=stdin_data)
        except Exception as exc:
            self.kill_process_tree(proc.pid)
            stderr_data = f"Communication error: {exc}"
        finally:
            stop_watchdog.set()
            watchdog_thread.join(timeout=1.0)

        duration = time.time() - start_time
        combined_output = stdout_data or ""
        if stderr_data:
            combined_output = (
                f"{combined_output}\n[STDERR]\n{stderr_data}"
                if combined_output
                else stderr_data
            )

        metrics = {
            "pid": proc.pid,
            "peak_memory_mb": round(peak_memory_mb[0], 2),
            "cpu_time": round(total_cpu_time[0], 3),
            "duration_sec": round(duration, 3),
            "stdout": stdout_data,
            "stderr": stderr_data,
        }

        if timed_out.is_set():
            return SyscallResult.fail(
                request=req,
                error=f"TIMEOUT_EXPIRED: Process exceeded timeout of {timeout} seconds",
                output=combined_output,
                exit_code=124,
                duration_sec=duration,
            )

        if mem_exceeded.is_set():
            return SyscallResult.fail(
                request=req,
                error=f"MEMORY_LIMIT_EXCEEDED: Process exceeded memory cap of {mem_limit} MB",
                output=combined_output,
                exit_code=137,
                duration_sec=duration,
            )

        exit_code = proc.returncode if proc.returncode is not None else 0
        if exit_code == 0:
            return SyscallResult.ok(
                request=req,
                output=combined_output,
                data=metrics,
                exit_code=exit_code,
                duration_sec=duration,
            )
        else:
            return SyscallResult.fail(
                request=req,
                error=stderr_data or f"Process exited with non-zero status {exit_code}",
                output=combined_output,
                exit_code=exit_code,
                duration_sec=duration,
            )

    def kill_process(
        self,
        pid: int,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Kills a target process and all descendants by PID.

        Args:
            pid: Target PID.
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult indicating whether the process was terminated.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.PROC_KILL,
            params={"pid": pid},
            ring=PrivilegeRing.RING_0,
        )

        start_time = time.time()
        success = self.kill_process_tree(pid)
        duration = time.time() - start_time

        if success:
            return SyscallResult.ok(
                request=req,
                output=f"Process {pid} and its children terminated.",
                data={"pid": pid, "killed": True},
                duration_sec=duration,
            )
        else:
            return SyscallResult.fail(
                request=req,
                error=f"Process {pid} not found or already terminated.",
                exit_code=1,
                duration_sec=duration,
            )
