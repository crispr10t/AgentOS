"""Process Execution Engine, Watchdog, and Process Tree Manager.

Implements supervised process lifecycle execution with recursive tree termination,
watchdog timeout enforcement, peak resident memory monitoring, and command sanitization.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
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
    # Interpreters, Compilers & Runtimes
    "python",
    "python3",
    "py",
    "javac",
    "java",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "node",
    "deno",
    "bun",
    "go",
    "cargo",
    "rustc",
    "dotnet",
    # Build & Package Managers
    "pip",
    "pip3",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "pytest",
    "make",
    "cmake",
    "mvn",
    "gradle",
    "git",
    # Shells & Runtimes
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "bash",
    "sh",
    "wsl",
    # Shell Utilities & Command Line Tools
    "dir",
    "ls",
    "echo",
    "cat",
    "type",
    "find",
    "findstr",
    "grep",
    "tree",
    "tasklist",
    "taskkill",
    "whoami",
    "hostname",
    "curl",
    "wget",
    "tar",
    "zip",
    "unzip",
    "where",
    "which",
    "explorer",
    "attrib",
    "sort",
    "more",
    "cls",
    "clear",
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
    "calc": "calc.exe",
    "notepad": "notepad.exe",
    "task_manager": "taskmgr.exe",
    "taskmgr": "taskmgr.exe",
    "edge": "msedge.exe",
    "msedge": "msedge.exe",
    "chrome": "chrome.exe",
    "google_chrome": "chrome.exe",
    "zen": "zen.exe",
    "zen_browser": "zen.exe",
    "brave": "brave.exe",
    "brave_browser": "brave.exe",
    "brave-browser": "brave.exe",
    "vs_code": "Code.exe",
    "vscode": "Code.exe",
    "code": "Code.exe",
    "explorer": "explorer.exe",
    "file_manager": "explorer.exe",
    "filemanager": "explorer.exe",
    "file_explorer": "explorer.exe",
    "fileexplorer": "explorer.exe",
    "files": "explorer.exe",
    "my_computer": "explorer.exe",
    "this_pc": "explorer.exe",
    "obsidian": "Obsidian.exe",
    "telegram": "Telegram.exe",
    "telegram_desktop": "Telegram.exe",
    "vlc": "vlc.exe",
    "steam": "Steam.exe",
    "spotify": "Spotify.exe",
    "discord": "Discord.exe",
}

_SHORTCUT_CACHE: Optional[dict[str, str]] = None
_START_APPS_CACHE: Optional[dict[str, str]] = None


def _extract_target_from_lnk(lnk_path: str) -> Optional[str]:
    """Extract executable target path from a Windows .lnk shortcut file."""
    try:
        with open(lnk_path, "rb") as f:
            data = f.read()
        matches = re.findall(
            rb'[a-zA-Z]:\\(?:[^<>:"|?*\x00-\x1f\r\n\t]+\\)*[^<>:"|?*\x00-\x1f\r\n\t]+\.exe',
            data,
            re.IGNORECASE,
        )
        for m in matches:
            cand = m.decode("latin1", errors="ignore")
            if os.path.isfile(cand):
                return cand
        if matches:
            return matches[0].decode("latin1", errors="ignore")
    except Exception:
        pass
    return None


def _get_shortcut_applications() -> dict[str, str]:
    """Scan Start Menu and Desktop folders for .lnk shortcuts, mapping app names to targets."""
    global _SHORTCUT_CACHE
    if _SHORTCUT_CACHE is not None:
        return _SHORTCUT_CACHE

    shortcuts: dict[str, str] = {}
    if os.name != "nt":
        _SHORTCUT_CACHE = shortcuts
        return shortcuts

    search_dirs = [
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
        os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.environ.get("PUBLIC", ""), "Desktop"),
        os.path.join(os.environ.get("USERPROFILE", ""), r"OneDrive\Desktop"),
    ]

    for s_dir in search_dirs:
        if not s_dir or not os.path.isdir(s_dir):
            continue
        try:
            for root, _, files in os.walk(s_dir):
                for f in files:
                    if f.lower().endswith(".lnk"):
                        full_lnk = os.path.join(root, f)
                        stem = Path(f).stem
                        target = _extract_target_from_lnk(full_lnk) or full_lnk

                        clean_stem = stem.lower().strip()
                        key_stem = clean_stem.replace(" ", "_").replace("-", "")
                        nodash_stem = clean_stem.replace(" ", "").replace("-", "")

                        shortcuts[clean_stem] = target
                        shortcuts[key_stem] = target
                        shortcuts[nodash_stem] = target

                        words = [w.lower() for w in re.split(r"[\s\-_]+", stem) if len(w) > 2]
                        for w in words:
                            if w not in ("desktop", "shortcut", "app", "application", "windows"):
                                if w not in shortcuts:
                                    shortcuts[w] = target
        except Exception:
            pass

    _SHORTCUT_CACHE = shortcuts
    return shortcuts


def _get_start_apps() -> dict[str, str]:
    """Query Windows Get-StartApps to resolve UWP / Store apps and system packages."""
    global _START_APPS_CACHE
    if _START_APPS_CACHE is not None:
        return _START_APPS_CACHE

    start_apps: dict[str, str] = {}
    if os.name != "nt":
        _START_APPS_CACHE = start_apps
        return start_apps

    try:
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-StartApps | ConvertTo-Json -Compress"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8.0)
        if res.returncode == 0 and res.stdout.strip():
            raw = json.loads(res.stdout)
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                name = item.get("Name", "")
                app_id = item.get("AppID", "")
                if not name or not app_id:
                    continue

                if os.path.isfile(app_id):
                    target = app_id
                elif app_id.startswith("shell:") or app_id.startswith("::{"):
                    target = app_id
                else:
                    target = f"shell:AppsFolder\\{app_id}"

                c_name = name.lower().strip()
                k_name = c_name.replace(" ", "_").replace("-", "")
                no_name = c_name.replace(" ", "").replace("-", "")

                start_apps[c_name] = target
                start_apps[k_name] = target
                start_apps[no_name] = target

                words = [w.lower() for w in re.split(r"[\s\-_]+", name) if len(w) > 2]
                for w in words:
                    if w not in ("desktop", "shortcut", "app", "application", "windows", "microsoft"):
                        if w not in start_apps:
                            start_apps[w] = target
    except Exception:
        pass

    _START_APPS_CACHE = start_apps
    return start_apps


def resolve_application_executable(app_name: str) -> Optional[str]:
    """Dynamically resolves a desktop application name to an executable path.

    Searches aliases, system PATH, Windows App Paths registry, Start Menu/Desktop
    shortcuts, standard Program Files / LocalAppData install directories, and
    Windows Start Apps (UWP / Shell AppsFolder).
    """
    if not app_name:
        return None

    # Block path traversal attempts
    if any(sep in app_name for sep in ("/", "\\", "..")):
        return None

    app_clean = app_name.strip()
    app_key = app_clean.lower().replace(" ", "_").replace("-", "")
    app_key_nodash = app_clean.lower().replace(" ", "").replace("-", "")

    alias_map: dict[str, str] = {
        "vs_code": "Code.exe",
        "vscode": "Code.exe",
        "code": "Code.exe",
        "visual_studio_code": "Code.exe",
        "zen": "zen.exe",
        "zen_browser": "zen.exe",
        "zenbrowser": "zen.exe",
        "chrome": "chrome.exe",
        "google_chrome": "chrome.exe",
        "googlechrome": "chrome.exe",
        "brave": "brave.exe",
        "brave_browser": "brave.exe",
        "bravebrowser": "brave.exe",
        "edge": "msedge.exe",
        "msedge": "msedge.exe",
        "firefox": "firefox.exe",
        "mozilla_firefox": "firefox.exe",
        "calculator": "calc.exe",
        "calc": "calc.exe",
        "notepad": "notepad.exe",
        "task_manager": "taskmgr.exe",
        "taskmgr": "taskmgr.exe",
        "paint": "mspaint.exe",
        "mspaint": "mspaint.exe",
        "explorer": "explorer.exe",
        "file_manager": "explorer.exe",
        "filemanager": "explorer.exe",
        "file_explorer": "explorer.exe",
        "fileexplorer": "explorer.exe",
        "files": "explorer.exe",
        "my_computer": "explorer.exe",
        "this_pc": "explorer.exe",
        "obsidian": "Obsidian.exe",
        "telegram": "Telegram.exe",
        "telegram_desktop": "Telegram.exe",
        "vlc": "vlc.exe",
        "vlc_media_player": "vlc.exe",
        "spotify": "Spotify.exe",
        "discord": "Discord.exe",
        "steam": "Steam.exe",
        "terminal": "wt.exe",
        "windows_terminal": "wt.exe",
    }

    target_exe = alias_map.get(
        app_key,
        alias_map.get(
            app_key_nodash,
            f"{app_clean}.exe" if not app_clean.lower().endswith(".exe") else app_clean,
        ),
    )

    # 1. PATH search via shutil.which
    which_path = (
        shutil.which(target_exe)
        or shutil.which(app_clean)
        or shutil.which(f"{app_clean}.exe")
        or shutil.which(f"{app_key}.exe")
    )
    if which_path and os.path.isfile(which_path):
        return which_path

    # 2. Windows Registry App Paths
    if os.name == "nt":
        try:
            import winreg

            for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(
                        root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
                    ) as k:
                        num_subkeys = winreg.QueryInfoKey(k)[0]
                        for i in range(num_subkeys):
                            sk_name = winreg.EnumKey(k, i)
                            if sk_name.lower() in (
                                target_exe.lower(),
                                f"{app_clean}.exe".lower(),
                                f"{app_key}.exe".lower(),
                            ):
                                with winreg.OpenKey(k, sk_name) as ak:
                                    val, _ = winreg.QueryValueEx(ak, "")
                                    if val and os.path.isfile(val):
                                        return str(val)
                except Exception:
                    pass
        except ImportError:
            pass

    # 3. Start Menu & Desktop Shortcuts (captures apps across any drive)
    shortcuts = _get_shortcut_applications()
    for cand_key in (app_key, app_key_nodash, app_clean.lower(), Path(target_exe).stem.lower()):
        if cand_key in shortcuts:
            return shortcuts[cand_key]

    # 4. Known standard install locations
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    prog_files = os.environ.get("PROGRAMFILES", "")
    prog_files_x86 = os.environ.get("PROGRAMFILES(X86)", "")

    specific_candidates: list[str] = [
        os.path.join(local_app_data, "Programs", "Microsoft VS Code", "Code.exe"),
        os.path.join(prog_files, "Microsoft VS Code", "Code.exe"),
        os.path.join(prog_files_x86, "Microsoft VS Code", "Code.exe"),
        os.path.join(prog_files, "Zen Browser", "zen.exe"),
        os.path.join(prog_files_x86, "Zen Browser", "zen.exe"),
        os.path.join(local_app_data, "Zen Browser", "zen.exe"),
        os.path.join(prog_files, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        os.path.join(prog_files_x86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        os.path.join(local_app_data, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        os.path.join(prog_files, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(prog_files_x86, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(local_app_data, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(prog_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(prog_files, "Microsoft", "Edge", "Application", "msedge.exe"),
    ]

    for cand in specific_candidates:
        if cand and os.path.isfile(cand):
            if Path(cand).name.lower() == target_exe.lower():
                return cand

    # 5. Search within Program Files and LocalAppData subdirectories (up to 3 levels)
    search_roots = [
        prog_files,
        prog_files_x86,
        local_app_data,
        os.path.join(local_app_data, "Programs"),
    ]
    for base in search_roots:
        if not base or not os.path.isdir(base):
            continue
        direct = os.path.join(base, target_exe)
        if os.path.isfile(direct):
            return direct
        try:
            for root, dirs, files in os.walk(base):
                depth = len(Path(root).relative_to(Path(base)).parts)
                if depth > 3:
                    dirs.clear()
                    continue
                for f in files:
                    if f.lower() == target_exe.lower():
                        return os.path.join(root, f)
        except Exception:
            pass

    # 6. Windows Start Apps (UWP / Shell AppsFolder)
    start_apps = _get_start_apps()
    for cand_key in (app_key, app_key_nodash, app_clean.lower(), Path(target_exe).stem.lower()):
        if cand_key in start_apps:
            return start_apps[cand_key]

    return None

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
        self.whitelisted_apps: set[str] = {
            "calculator", "calc", "notepad", "task_manager", "taskmgr", "edge", "msedge"
        }

    def is_app_whitelisted(self, app_name: str) -> bool:
        """Checks if an application has already been whitelisted or elevated."""
        norm = str(app_name).strip().lower().replace(" ", "_").replace("-", "")
        return norm in self.whitelisted_apps

    def whitelist_app(self, app_name: str) -> None:
        """Dynamically adds an application to the approved whitelist."""
        norm = str(app_name).strip().lower().replace(" ", "_").replace("-", "")
        self.whitelisted_apps.add(norm)

    @staticmethod
    def _validate_app_name(app_name: str) -> str:
        """Validate that an application name is approved for launch."""
        normalized = app_name.strip().lower()
        if not normalized:
            raise ProcessSecurityError("Application name cannot be empty.")
        norm_key = normalized.replace(" ", "_").replace("-", "")
        if normalized in APPROVED_APPLICATIONS:
            return APPROVED_APPLICATIONS[normalized]
        if norm_key in APPROVED_APPLICATIONS:
            return APPROVED_APPLICATIONS[norm_key]
        resolved = resolve_application_executable(app_name)
        if resolved:
            return Path(resolved).name
        raise ProcessSecurityError(f"Application '{app_name}' is not in the approved allowlist.")

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
        prohibited_shells = {
            "cmd", "cmd.exe", "powershell", "powershell.exe",
            "pwsh", "pwsh.exe", "bash", "bash.exe", "sh", "sh.exe", "wscript", "cscript",
        }

        # Block path traversal, raw paths, or prohibited shell commands
        if any(sep in app_name for sep in ("/", "\\", "..")) or app_key in prohibited_shells:
            return SyscallResult.fail(
                request=req,
                error=(
                    f"Application '{app_name}' is not permitted. "
                    f"Only desktop GUI applications can be launched."
                ),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        launch_target = resolve_application_executable(app_name)
        if launch_target is None:
            return SyscallResult.fail(
                request=req,
                error=(
                    f"Application '{app_name}' could not be located on this system. "
                    f"Ensure it is installed and added to PATH or standard directories."
                ),
                exit_code=126,
                duration_sec=time.time() - start_time,
            )

        is_shell_target = (
            launch_target.startswith("shell:")
            or launch_target.lower().endswith(".lnk")
            or launch_target.startswith("::{")
        )

        if is_shell_target:
            try:
                os.startfile(launch_target)
            except OSError as exc:
                return SyscallResult.fail(
                    request=req,
                    error=f"Could not open {app_key.replace('_', ' ')}: {exc}",
                    exit_code=127,
                    duration_sec=time.time() - start_time,
                )

            time.sleep(0.25)
            active_pid = None
            stem = Path(launch_target).stem.lower()
            try:
                for proc in psutil.process_iter(["pid", "name"]):
                    pname = (proc.info.get("name") or "").lower()
                    if (
                        app_key in pname
                        or stem in pname
                        or app_clean.lower() in pname
                    ):
                        active_pid = proc.info["pid"]
                        break
            except Exception:
                pass

            self.whitelist_app(app_key)
            return SyscallResult.ok(
                request=req,
                output=f"Opened {app_name}" + (f" (PID {active_pid})." if active_pid else "."),
                data={"app": app_key, "pid": active_pid},
                duration_sec=time.time() - start_time,
            )

        # Determine launch command and arguments for standard executable
        launch_cmd = [launch_target]
        target_name = Path(launch_target).name.lower()
        browser_executables = {"brave.exe", "chrome.exe", "msedge.exe", "zen.exe", "firefox.exe"}
        if target_name in browser_executables:
            launch_cmd.append("--new-window")

        creationflags = 0
        startupinfo = None
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 1  # SW_SHOWNORMAL

        try:
            process = subprocess.Popen(
                launch_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except OSError as exc:
            # Fallback to os.startfile on Windows if Popen encounters binary execution issues
            if os.name == "nt":
                try:
                    os.startfile(launch_target)
                    self.whitelist_app(app_key)
                    return SyscallResult.ok(
                        request=req,
                        output=f"Opened {app_name}.",
                        data={"app": app_key, "pid": None},
                        duration_sec=time.time() - start_time,
                    )
                except OSError:
                    pass
            return SyscallResult.fail(
                request=req,
                error=f"Could not open {app_key.replace('_', ' ')}: {exc}",
                exit_code=127,
                duration_sec=time.time() - start_time,
            )

        # Brief post-spawn health check to avoid reporting false success
        time.sleep(0.15)
        poll_status = process.poll()
        if isinstance(poll_status, int) and poll_status != 0 and target_name != "explorer.exe":
            return SyscallResult.fail(
                request=req,
                error=f"Application '{app_name}' failed to launch (process exited immediately with code {poll_status}).",
                exit_code=poll_status,
                duration_sec=time.time() - start_time,
            )

        active_pid = getattr(process, "pid", None)
        if poll_status == 0 or target_name == "explorer.exe":
            # Process delegated to an existing instance
            matched_pid = None
            try:
                for proc in psutil.process_iter(["pid", "name"]):
                    if proc.info.get("name") and proc.info["name"].lower() == target_name:
                        matched_pid = proc.info["pid"]
                        break
            except Exception:
                pass
            if matched_pid is not None:
                active_pid = matched_pid
            elif active_pid is not None and not psutil.pid_exists(active_pid) and target_name != "explorer.exe":
                return SyscallResult.fail(
                    request=req,
                    error=f"Application '{app_name}' was launched but terminated unexpectedly.",
                    exit_code=1,
                    duration_sec=time.time() - start_time,
                )

        self.whitelist_app(app_key)
        return SyscallResult.ok(
            request=req,
            output=f"Opened {app_name} (PID {active_pid}).",
            data={"app": app_key, "pid": active_pid},
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

    def validate_command(
        self,
        cmd: list[str] | str,
        cwd: Optional[Path | str] = None,
    ) -> list[str]:
        """Validates command structure and ensures no shell escape wrappers are present.

        Args:
            cmd: Command argument list or command string.
            cwd: Optional execution working directory to resolve local binaries.

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

        # Check for prohibited shell wrappers unless shell commands are explicitly allowed
        allow_shell = os.getenv("ALLOW_SHELL_COMMANDS", "false").lower() in ("true", "1")
        if not allow_shell:
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

            # Check if binary or script exists within workspace or cwd
            is_workspace_file = False
            for base in (cwd, os.getenv("SANDBOX_ROOT", "./sandbox_workspace"), "."):
                if base:
                    base_p = Path(base)
                    if (base_p / raw_binary).exists() or (base_p / bin_path.name).exists():
                        is_workspace_file = True
                        break

            # Also allow any executable that exists in system PATH
            exists_in_path = shutil.which(raw_binary) is not None

            is_allowed = (
                is_workspace_file
                or exists_in_path
                or bin_name in self.allowed_executables
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
            tokens = self.validate_command(cmd, cwd=cwd)
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

        # 1. Native handling for shell built-ins (dir, ls, echo) for sandbox resilience
        candidate = tokens[0].lower()
        if candidate in ("dir", "ls"):
            target_dir = Path(exec_cwd or ".")
            if len(tokens) > 1 and not str(tokens[1]).startswith("-") and not str(tokens[1]).startswith("/"):
                sub = Path(tokens[1])
                target_dir = (Path(exec_cwd) / sub) if (exec_cwd and not sub.is_absolute()) else sub

            if not target_dir.exists():
                duration = time.time() - start_time
                return SyscallResult.fail(
                    request=req,
                    error=f"The system cannot find the path specified: {target_dir}",
                    exit_code=1,
                    duration_sec=duration,
                )

            lines = [f" Directory of {target_dir.resolve()}\n"]
            try:
                for entry in sorted(target_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                    mtime = time.strftime("%m/%d/%Y  %I:%M %p", time.localtime(entry.stat().st_mtime))
                    if entry.is_dir():
                        lines.append(f"{mtime}    <DIR>          {entry.name}")
                    else:
                        size = entry.stat().st_size
                        lines.append(f"{mtime}    {size:>12,} {entry.name}")
                output_text = "\n".join(lines)
                duration = time.time() - start_time
                return SyscallResult.ok(
                    request=req,
                    output=output_text,
                    data={"directory": str(target_dir.resolve()), "count": len(lines) - 1},
                    exit_code=0,
                    duration_sec=duration,
                )
            except Exception:
                pass

        if candidate == "echo":
            msg = " ".join(tokens[1:])
            duration = time.time() - start_time
            return SyscallResult.ok(
                request=req,
                output=msg,
                data={"message": msg},
                exit_code=0,
                duration_sec=duration,
            )

        # 2. If tokens[0] is a Python script, automatically prepend current Python interpreter
        if tokens[0].lower().endswith(".py"):
            tokens = [sys.executable] + tokens

        # 3. On Windows, wrap other shell scripts (.bat / .cmd) in cmd.exe /c if needed
        if sys.platform == "win32":
            if (candidate.endswith(".bat") or candidate.endswith(".cmd")) and shutil.which(tokens[0]) is None:
                tokens = ["cmd.exe", "/c"] + tokens

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
