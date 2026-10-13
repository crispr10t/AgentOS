"""Comprehensive edge-case tests for kernel/process_manager.py: Process Execution, Security Checks, and Safe AST Calculator."""

import sys
import pytest

from kernel.process_manager import (
    DEFAULT_ALLOWED_EXECUTABLES,
    PROHIBITED_SHELL_PREFIXES,
    ProcessManager,
    ProcessSecurityError,
    resolve_application_executable,
)
from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallType


@pytest.fixture
def pm():
    """Fixture providing a ProcessManager instance."""
    return ProcessManager(default_timeout=5, default_memory_limit_mb=256)


# --- 1. Safe AST Numeric Calculator Edge Cases ---

@pytest.mark.parametrize("expr, expected_result", [
    ("2 + 2", 4),
    ("10 - 3.5", 6.5),
    ("4 * 5", 20),
    ("10 / 2", 5.0),
    ("15 // 4", 3),
    ("17 % 5", 2),
    ("2 ** 10", 1024),
    ("-5 + 10", 5),
    ("+42", 42),
    ("((2 + 3) * 4) - 5", 15),
])
def test_process_manager_calculate_valid_expressions(pm: ProcessManager, expr: str, expected_result: float | int):
    """Verify safe AST calculation handles all supported arithmetic operators and precedence."""
    res = pm.calculate_expression(expr)
    assert res.success is True
    assert res.data["result"] == expected_result
    assert str(expected_result) in res.output


@pytest.mark.parametrize("malicious_or_invalid_expr", [
    "__import__('os').system('dir')",
    "open('secret.txt').read()",
    "x + 5",
    "print('hello')",
    "lambda x: x",
    "[1, 2, 3]",
    "{'a': 1}",
    "1 / 0",  # ZeroDivisionError handled gracefully
    "",
    "   ",
    "2 +* 3",
])
def test_process_manager_calculate_malicious_and_invalid_rejected(pm: ProcessManager, malicious_or_invalid_expr: str):
    """Verify execution of code injection, functions, variables, and syntax errors is blocked."""
    res = pm.calculate_expression(malicious_or_invalid_expr)
    assert res.success is False
    assert res.exit_code != 0


# --- 2. URL Validation Edge Cases ---

@pytest.mark.parametrize("valid_url, expected_normalized", [
    ("https://github.com", "https://github.com"),
    ("http://localhost:8080", "http://localhost:8080"),
    ("www.python.org", "https://www.python.org"),
    ("  https://google.com/search?q=os  ", "https://google.com/search?q=os"),
])
def test_process_manager_url_validation_success(pm: ProcessManager, valid_url: str, expected_normalized: str):
    """Verify valid URLs are normalized correctly."""
    assert pm._validate_url(valid_url) == expected_normalized


@pytest.mark.parametrize("forbidden_url", [
    "file:///C:/Windows/System32",
    "javascript:alert('xss')",
    "data:text/html,<h1>PWNED</h1>",
    "ftp://ftp.is.co.za",
    "",
    "   ",
    "not_a_url",
])
def test_process_manager_url_validation_blocked(pm: ProcessManager, forbidden_url: str):
    """Verify non-web schemas and invalid URLs raise ProcessSecurityError."""
    with pytest.raises(ProcessSecurityError):
        pm._validate_url(forbidden_url)


# --- 3. Prohibited Shell Prefixes and Whitelist ---

@pytest.mark.parametrize("prefix", PROHIBITED_SHELL_PREFIXES)
def test_prohibited_shell_prefixes_blocked(pm: ProcessManager, prefix: list[str]):
    """Verify every prohibited shell prefix in PROHIBITED_SHELL_PREFIXES is blocked."""
    bad_cmd = list(prefix) + ["echo exploit"]
    req = SyscallRequest(syscall=SyscallType.PROC_SPAWN, params={"cmd": bad_cmd})
    res = pm.spawn(bad_cmd, request=req)
    assert res.success is False
    assert res.exit_code == 126
    assert "prohibited shell wrapper" in (res.error or "").lower()


@pytest.mark.parametrize("allowed_binary", [
    "python",
    "git",
    "node",
    "cargo",
    "pytest",
    "whoami",
    "echo",
])
def test_allowed_executables_whitelist_membership(allowed_binary: str):
    """Verify standard developer and diagnostic tools belong to DEFAULT_ALLOWED_EXECUTABLES."""
    assert allowed_binary in DEFAULT_ALLOWED_EXECUTABLES


def test_unauthorized_binary_blocked(pm: ProcessManager):
    """Verify binaries not in whitelist fail validation."""
    cmd = ["netcat_fake_binary", "-l", "8080"]
    res = pm.spawn(cmd)
    assert res.success is False
    assert res.exit_code == 126
    assert "not in the approved whitelist" in (res.error or "")


# --- 4. Process Tree Killer & Kill by PID ---

def test_kill_process_invalid_pid(pm: ProcessManager):
    """Verify killing a non-existent PID returns handled fail result."""
    res = pm.kill_process(pid=999999)
    assert res.success is False
    assert "not found" in (res.error or "").lower() or res.exit_code == 1


# --- 5. App Launch Sanitization ---

@pytest.mark.parametrize("disallowed_app", [
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "bash",
    "../malware.exe",
    "C:\\Windows\\System32\\calc.exe",
])
def test_open_application_disallowed_names_rejected(pm: ProcessManager, disallowed_app: str):
    """Raw paths and shell interpreters must be rejected by open_application."""
    res = pm.open_application(disallowed_app)
    assert res.success is False
    assert res.exit_code == 126
    assert "not permitted" in (res.error or "")
