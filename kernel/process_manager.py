"""Process Execution Engine, Watchdog, and Process Tree Manager.

Implements supervised process lifecycle execution with recursive tree termination,
watchdog timeout enforcement, peak resident memory monitoring, and command sanitization.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import threading
import time
from typing import Any, Optional

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

APPROVED_APPLICATIONS: dict[str, str] = {
    "calculator": "calc.exe",
    "notepad": "notepad.exe",
    "task_manager": "taskmgr.exe",
    "edge": "msedge.exe",
}

EDGE_TAB_TRACKER: dict[str, list[str]] = {}


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
        current_py_stem = Path(sys.executable).stem.lower()
        self.allowed_executables.add(current_py_stem)
        self.allowed_executables.add(sys.executable.lower())
        self._edge_windows: list[dict[str, Any]] = []

    @staticmethod
    def _validate_app_name(app_name: str) -> str:
        """Validate that an application name is approved for launch."""
        normalized = app_name.strip().lower()
        if not normalized:
            raise ProcessSecurityError("Application name cannot be empty.")
        if normalized not in APPROVED_APPLICATIONS:
            raise ProcessSecurityError(f"Application '{app_name}' is not in the approved allowlist.")
        return APPROVED_APPLICATIONS[normalized]

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate a URL before opening it in Edge."""
        candidate = (url or "").strip()
        if not candidate:
            raise ProcessSecurityError("URL cannot be empty.")
        lowered = candidate.lower()
        if lowered.startswith(("http://", "https://")):
            return candidate
        if lowered.startswith("www."):
            return f"https://{candidate}"
        raise ProcessSecurityError(
            "Only http://, https://, or www. URLs are allowed for Edge navigation."
        )

    @staticmethod
    def _validate_calculation(expression: str) -> str:
        """Validate calculator expressions before evaluation."""
        candidate = (expression or "").strip()
        if not candidate:
            raise ProcessSecurityError("Calculation expression cannot be empty.")
        try:
            parsed = ast.parse(candidate, mode="eval")
        except SyntaxError as exc:
            raise ProcessSecurityError(f"Invalid calculation expression: {exc.msg}") from exc
        allowed_nodes = (
            ast.Expression,
            ast.BinOp,
            ast.UnaryOp,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.FloorDiv,
            ast.Mod,
            ast.Pow,
            ast.USub,
            ast.UAdd,
            ast.Constant,
            ast.Num,
        )
        for subnode in ast.walk(parsed):
            if not isinstance(subnode, allowed_nodes):
                raise ProcessSecurityError("Calculation expression contains unsupported operations.")
        if not isinstance(parsed.body, (ast.Constant, ast.Num, ast.BinOp, ast.UnaryOp)):
            raise ProcessSecurityError("Calculation expression is not a valid numeric expression.")
        return candidate

    @staticmethod
    def _evaluate_numeric_ast(node: ast.AST) -> float | int:
        """Safely evaluate a numeric AST fragment."""
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                return node.value
            raise ProcessSecurityError("Calculation constants must be numeric.")
        if isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.UnaryOp):
            operand = ProcessManager._evaluate_numeric_ast(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand
            raise ProcessSecurityError("Unsupported unary operation in calculation.")
        if isinstance(node, ast.BinOp):
            left = ProcessManager._evaluate_numeric_ast(node.left)
            right = ProcessManager._evaluate_numeric_ast(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.FloorDiv):
                return left // right
            if isinstance(node.op, ast.Mod):
                return left % right
            if isinstance(node.op, ast.Pow):
                return left ** right
            raise ProcessSecurityError("Unsupported binary operation in calculation.")
        raise ProcessSecurityError("Calculation expression contains unsupported syntax.")

    def open_application(
        self,
        app_name: str,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Opens one explicitly approved Windows application without shell commands."""
        req = request or SyscallRequest(
            syscall=SyscallType.APP_OPEN,
            params={"app": app_name},
            ring=PrivilegeRing.RING_0,
        )
        start_time = time.time()

        if os.name != "nt":
            return SyscallResult.fail(
                request=req,
                error="Opening desktop applications is supported only on Windows.",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        app_key = app_name.strip().lower().replace(" ", "_")
        executable = APPROVED_APPLICATIONS.get(app_key)
        if executable is None:
            return SyscallResult.fail(
                request=req,
                error=(
                    f"Application '{app_name}' is not approved. "
                    f"Choose one of: {', '.join(APPROVED_APPLICATIONS)}."
                ),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        resolved_executable = shutil.which(executable)
        if app_key == "edge" and resolved_executable is None:
            install_roots = (
                os.environ.get("PROGRAMFILES(X86)"),
                os.environ.get("PROGRAMFILES"),
                os.environ.get("LOCALAPPDATA"),
            )
            for root in install_roots:
                if root:
                    candidate = Path(root) / "Microsoft" / "Edge" / "Application" / executable
                    if candidate.is_file():
                        resolved_executable = str(candidate)
                        break
        launch_target = resolved_executable or executable

        try:
            process = subprocess.Popen(
                [launch_target],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except OSError as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Could not open {app_key.replace('_', ' ')}: {exc}",
                exit_code=127,
                duration_sec=time.time() - start_time,
            )

        return SyscallResult.ok(
            request=req,
            output=f"Opened {app_key.replace('_', ' ')} (PID {process.pid}).",
            data={"app": app_key, "pid": process.pid},
            duration_sec=time.time() - start_time,
        )

    def open_edge_url(
        self,
        url: str,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Open a single validated URL in a dedicated Edge window."""
        req = request or SyscallRequest(
            syscall=SyscallType.APP_OPEN_URL,
            params={"url": url},
            ring=PrivilegeRing.RING_0,
        )
        start_time = time.time()

        if os.name != "nt":
            return SyscallResult.fail(
                request=req,
                error="Opening URLs in Edge is supported only on Windows.",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        try:
            normalized_url = self._validate_url(url)
        except ProcessSecurityError as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        resolved_executable = shutil.which("msedge.exe")
        if resolved_executable is None:
            install_roots = (
                os.environ.get("PROGRAMFILES(X86)"),
                os.environ.get("PROGRAMFILES"),
                os.environ.get("LOCALAPPDATA"),
            )
            for root in install_roots:
                if root:
                    candidate = Path(root) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
                    if candidate.is_file():
                        resolved_executable = str(candidate)
                        break

        if resolved_executable is None:
            return SyscallResult.fail(
                request=req,
                error="Microsoft Edge is not installed or not found on PATH.",
                exit_code=127,
                duration_sec=time.time() - start_time,
            )

        try:
            process = subprocess.Popen(
                [resolved_executable, "--new-window", normalized_url],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except OSError as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Could not open Edge URL '{normalized_url}': {exc}",
                exit_code=127,
                duration_sec=time.time() - start_time,
            )

        self._edge_windows.append({"pid": process.pid, "url": normalized_url})
        return SyscallResult.ok(
            request=req,
            output=f"Opened Edge to {normalized_url} (PID {process.pid}).",
            data={"url": normalized_url, "pid": process.pid},
            duration_sec=time.time() - start_time,
        )

    def close_edge_tab(
        self,
        url: Optional[str] = None,
        pid: Optional[int] = None,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Close the most recently opened Edge tab/window tracked by AgentOS."""
        req = request or SyscallRequest(
            syscall=SyscallType.APP_CLOSE_TAB,
            params={"url": url, "pid": pid},
            ring=PrivilegeRing.RING_0,
        )
        start_time = time.time()

        if not self._edge_windows:
            return SyscallResult.fail(
                request=req,
                error="No Edge tabs/windows have been opened by AgentOS that can be closed.",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        target = None
        if pid is not None:
            for entry in self._edge_windows:
                if entry["pid"] == int(pid):
                    target = entry
                    break
        elif url is not None:
            normalized = self._validate_url(url)
            for entry in self._edge_windows:
                if entry["url"] == normalized:
                    target = entry
                    break
        else:
            target = self._edge_windows.pop()

        if target is None:
            return SyscallResult.fail(
                request=req,
                error="The requested Edge tab/window was not found in AgentOS tracking.",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        if pid is not None and target["pid"] == int(pid):
            self._edge_windows = [entry for entry in self._edge_windows if entry["pid"] != int(pid)]
        elif url is not None:
            self._edge_windows = [entry for entry in self._edge_windows if entry["url"] != target["url"]]
        else:
            if self._edge_windows and self._edge_windows[-1]["pid"] == target["pid"]:
                self._edge_windows.pop()

        target_pid = int(target["pid"])
        try:
            if psutil.pid_exists(target_pid):
                proc = psutil.Process(target_pid)
                proc.terminate()
                proc.wait(timeout=3)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return SyscallResult.ok(
            request=req,
            output=f"Closed Edge tab/window for {target['url']} (PID {target_pid}).",
            data={"pid": target_pid, "url": target["url"]},
            duration_sec=time.time() - start_time,
        )

    def calculate_expression(
        self,
        expression: str,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Safely evaluate a numeric arithmetic expression."""
        req = request or SyscallRequest(
            syscall=SyscallType.CALCULATE,
            params={"expression": expression},
            ring=PrivilegeRing.RING_0,
        )
        start_time = time.time()

        try:
            candidate = self._validate_calculation(expression)
            value = self._evaluate_numeric_ast(ast.parse(candidate, mode="eval").body)
        except (ProcessSecurityError, ZeroDivisionError, OverflowError, ValueError) as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        return SyscallResult.ok(
            request=req,
            output=f"Result: {value}",
            data={"expression": candidate, "result": value},
            duration_sec=time.time() - start_time,
        )

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


class _LegacyProcessSecurityError(ValueError):
    """Raised when an unapproved or unsafe command invocation is attempted."""

    pass


class _LegacyProcessManager:
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

    def open_application(
        self,
        app_name: str,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Opens one explicitly approved Windows application without shell commands."""
        req = request or SyscallRequest(
            syscall=SyscallType.APP_OPEN,
            params={"app": app_name},
            ring=PrivilegeRing.RING_0,
        )
        start_time = time.time()

        if os.name != "nt":
            return SyscallResult.fail(
                request=req,
                error="Opening desktop applications is supported only on Windows.",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        app_key = app_name.strip().lower().replace(" ", "_")
        executable = APPROVED_APPLICATIONS.get(app_key)
        if executable is None:
            return SyscallResult.fail(
                request=req,
                error=(
                    f"Application '{app_name}' is not approved. "
                    f"Choose one of: {', '.join(APPROVED_APPLICATIONS)}."
                ),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        resolved_executable = shutil.which(executable)
        if app_key == "edge" and resolved_executable is None:
            install_roots = (
                os.environ.get("PROGRAMFILES(X86)"),
                os.environ.get("PROGRAMFILES"),
                os.environ.get("LOCALAPPDATA"),
            )
            for root in install_roots:
                if root:
                    candidate = Path(root) / "Microsoft" / "Edge" / "Application" / executable
                    if candidate.is_file():
                        resolved_executable = str(candidate)
                        break
        launch_target = resolved_executable or executable

        try:
            process = subprocess.Popen(
                [launch_target],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except OSError as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Could not open {app_key.replace('_', ' ')}: {exc}",
                exit_code=127,
                duration_sec=time.time() - start_time,
            )

        return SyscallResult.ok(
            request=req,
            output=f"Opened {app_key.replace('_', ' ')} (PID {process.pid}).",
            data={"app": app_key, "pid": process.pid},
            duration_sec=time.time() - start_time,
        )

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
