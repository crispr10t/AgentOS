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
    resolve_application_executable,
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


def test_open_brave_launches_with_new_window(pm: ProcessManager):
    """Verify brave launches with --new-window and proper GUI creation flags."""
    mock_process = MagicMock(pid=7788)
    mock_process.poll.return_value = None
    with patch("kernel.process_manager.os.name", "nt"), patch(
        "kernel.process_manager.resolve_application_executable",
        return_value=r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    ), patch("kernel.process_manager.subprocess.Popen", return_value=mock_process) as popen:
        result = pm.open_application("brave")

    assert result.success is True
    assert result.data == {"app": "brave", "pid": 7788}
    assert popen.call_args.args[0] == [
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        "--new-window",
    ]
    assert popen.call_args.kwargs["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP
    assert "startupinfo" in popen.call_args.kwargs
    assert popen.call_args.kwargs["startupinfo"] is not None


def test_open_application_detects_immediate_failure(pm: ProcessManager):
    """Verify open_application returns failure when the process exits immediately with an error."""
    mock_process = MagicMock(pid=9999)
    mock_process.poll.return_value = 1
    with patch("kernel.process_manager.os.name", "nt"), patch(
        "kernel.process_manager.resolve_application_executable",
        return_value=r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    ), patch("kernel.process_manager.subprocess.Popen", return_value=mock_process):
        result = pm.open_application("brave")

    assert result.success is False
    assert result.exit_code == 1
    assert "failed to launch" in result.error


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


def test_process_spawn_python_script_direct(pm: ProcessManager, tmp_path: Path):
    """Verify that passing a .py script directly auto-invokes Python."""
    script_file = tmp_path / "hello_script.py"
    script_file.write_text("print('HELLO FROM PYTHON SCRIPT')")

    res = pm.spawn([str(script_file)], cwd=tmp_path)
    assert res.success is True
    assert "HELLO FROM PYTHON SCRIPT" in (res.output or "")


def test_process_spawn_workspace_file_allowed(pm: ProcessManager, tmp_path: Path):
    """Verify that local files inside cwd/workspace pass validation."""
    custom_script = tmp_path / "custom_worker.py"
    custom_script.write_text("print('WORKER RUNNING')")

    tokens = pm.validate_command(["custom_worker.py"], cwd=tmp_path)
    assert tokens == ["custom_worker.py"]


def test_process_spawn_shell_builtin_dir(pm: ProcessManager, tmp_path: Path):
    """Verify that Windows shell built-in 'dir' executes properly."""
    if sys.platform != "win32":
        pytest.skip("Windows only test for dir built-in")
    res = pm.spawn(["dir"], cwd=tmp_path)
    assert res.success is True
    assert res.exit_code == 0


def test_resolve_application_executable_aliases():
    """Verify that file manager and desktop app aliases resolve correctly."""
    with patch("kernel.process_manager.shutil.which", return_value=r"C:\Windows\explorer.exe"):
        assert resolve_application_executable("file manager") == r"C:\Windows\explorer.exe"
        assert resolve_application_executable("file explorer") == r"C:\Windows\explorer.exe"
        assert resolve_application_executable("files") == r"C:\Windows\explorer.exe"
        assert resolve_application_executable("my computer") == r"C:\Windows\explorer.exe"


def test_open_file_manager_success(pm: ProcessManager):
    """Verify open_application launches file manager without false failure."""
    mock_process = MagicMock(pid=1234)
    mock_process.poll.return_value = 0
    with patch("kernel.process_manager.os.name", "nt"), patch(
        "kernel.process_manager.resolve_application_executable",
        return_value=r"C:\Windows\explorer.exe",
    ), patch("kernel.process_manager.subprocess.Popen", return_value=mock_process):
        result = pm.open_application("file manager")

    assert result.success is True
    assert result.data["app"] == "file_manager"


def test_open_shell_target_uses_startfile(pm: ProcessManager):
    """Verify packaged UWP / Windows Store apps are launched via os.startfile."""
    target = r"shell:AppsFolder\TelegramMessengerLLP.TelegramDesktop_t4vj0pshhgkwm!Telegram.TelegramDesktop.Store"
    with patch("kernel.process_manager.os.name", "nt"), patch(
        "kernel.process_manager.resolve_application_executable",
        return_value=target,
    ), patch("kernel.process_manager.os.startfile") as mock_startfile:
        result = pm.open_application("telegram")

    assert result.success is True
    assert result.data["app"] == "telegram"
    mock_startfile.assert_called_once_with(target)


def test_open_obsidian_custom_drive(pm: ProcessManager):
    """Verify apps on secondary drives (e.g. D:) launch successfully."""
    mock_process = MagicMock(pid=5678)
    mock_process.poll.return_value = None
    with patch("kernel.process_manager.os.name", "nt"), patch(
        "kernel.process_manager.resolve_application_executable",
        return_value=r"D:\obsidian\Obsidian.exe",
    ), patch("kernel.process_manager.subprocess.Popen", return_value=mock_process) as popen:
        result = pm.open_application("obsidian")

    assert result.success is True
    assert result.data == {"app": "obsidian", "pid": 5678}
    assert popen.call_args.args[0] == [r"D:\obsidian\Obsidian.exe"]


def test_validate_app_name_dynamic(pm: ProcessManager):
    """Verify _validate_app_name accepts aliases and dynamic desktop apps."""
    assert pm._validate_app_name("file manager") == "explorer.exe"
    assert pm._validate_app_name("file explorer") == "explorer.exe"
    assert pm._validate_app_name("telegram") == "Telegram.exe"
    assert pm._validate_app_name("obsidian") == "Obsidian.exe"

