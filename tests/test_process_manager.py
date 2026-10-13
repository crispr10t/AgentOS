"""Tests for kernel/process_manager.py: Process Execution, Watchdog & Tree Killer."""

from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch
import pytest

from kernel.process_manager import (
    ProcessManager,
    ProcessSecurityError,
)
from kernel.syscalls import SyscallType


@pytest.fixture
def pm() -> ProcessManager:
    """Fixture providing a ProcessManager instance with 5s timeout."""
    return ProcessManager(default_timeout=5, default_memory_limit_mb=512)


def test_process_spawn_success(pm: ProcessManager):
    """Verify standard child process execution captures stdout and exit code 0."""
    res = pm.spawn([sys.executable, "-c", "print('AgentOS Process Manager OK')"])
    assert res.success is True
    assert res.exit_code == 0
    assert "AgentOS Process Manager OK" in (res.output or "")
    assert res.data is not None
    assert "peak_memory_mb" in res.data
    assert "cpu_time" in res.data
    assert res.duration_sec >= 0.0


def test_process_spawn_stderr_and_nonzero_exit(pm: ProcessManager):
    """Verify stderr capture and non-zero exit code reporting."""
    res = pm.spawn(
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('custom_error_message'); sys.exit(7)",
        ]
    )
    assert res.success is False
    assert res.exit_code == 7
    assert "custom_error_message" in (res.error or "")


def test_watchdog_timeout_kills_infinite_loop(pm: ProcessManager):
    """Verify that watchdog terminates a hanging process and reports TIMEOUT_EXPIRED."""
    # Spawn a process that sleeps for 10 seconds, but set timeout to 1 second
    start = time.time()
    res = pm.spawn(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_sec=1,
    )
    elapsed = time.time() - start

    assert res.success is False
    assert res.exit_code == 124
    assert "TIMEOUT_EXPIRED" in (res.error or "")
    # Should have terminated close to 1-2 seconds, well before 10 seconds
    assert elapsed < 5.0


def test_prohibited_shell_wrapper_rejected(pm: ProcessManager):
    """Verify that shell escape wrappers like cmd /c or sh -c are blocked."""
    res = pm.spawn(["cmd.exe", "/c", "echo", "hacked"])
    assert res.success is False
    assert res.exit_code == 126
    assert "Prohibited shell wrapper invocation detected" in (res.error or "")


def test_unauthorized_binary_rejected(pm: ProcessManager):
    """Verify that binaries not in the whitelist are rejected when enforced."""
    res = pm.spawn(["unauthorized_crypto_miner", "--start"])
    assert res.success is False
    assert res.exit_code == 126
    assert "not in the approved whitelist" in (res.error or "")


def test_open_approved_application_uses_fixed_target(pm: ProcessManager):
    """Verify app launching only starts a fixed allowlisted executable."""
    mock_process = MagicMock(pid=2468)
    with patch("kernel.process_manager.os.name", "nt"), patch(
        "kernel.process_manager.shutil.which", return_value=r"C:\Windows\System32\notepad.exe"
    ), patch("kernel.process_manager.subprocess.Popen", return_value=mock_process) as popen:
        result = pm.open_application("notepad")

    assert result.success is True
    assert result.data == {"app": "notepad", "pid": 2468}
    assert popen.call_args.args[0] == [r"C:\Windows\System32\notepad.exe"]
    assert popen.call_args.kwargs["stdin"] == subprocess.DEVNULL


def test_open_application_rejects_arbitrary_names(pm: ProcessManager):
    """Verify app names cannot supply arbitrary executable paths or commands."""
    result = pm.open_application(r"C:\Windows\System32\cmd.exe")

    assert result.success is False
    assert result.exit_code == 126


def test_custom_cwd_and_stdin(pm: ProcessManager, tmp_path: Path):
    """Verify that cwd and stdin piping work as expected."""
    test_script = (
        "import sys, os\n"
        "data = sys.stdin.read().strip()\n"
        "print(f'READ:{data}|CWD:{os.path.basename(os.getcwd())}')\n"
    )
    res = pm.spawn(
        [sys.executable, "-c", test_script],
        cwd=tmp_path,
        stdin_data="OS_SUPERVISOR_INPUT",
    )
    assert res.success is True
    assert f"READ:OS_SUPERVISOR_INPUT|CWD:{tmp_path.name}" in (res.output or "")


def test_kill_process_by_pid(pm: ProcessManager):
    """Verify killing an invalid PID returns handled fail result."""
    res = pm.kill_process(pid=99999999)
    assert res.success is False
    assert res.exit_code == 1
