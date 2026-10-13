"""Transactional and Sandboxed Filesystem Engine.

Enforces canonical sandbox jail containment, byte limits on reads, safe moves,
and quarantine deletion into '.agentos_trash' for non-destructive data handling.
"""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
import platform
import shutil
import time
from typing import Any, Optional

import psutil

from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallResult, SyscallType
from security.sandbox import (
    PathSecurityViolation,
    ensure_sandbox_root,
    get_sandbox_root,
    validate_safe_path,
)


class FileEngine:
    """Manages sandboxed filesystem operations and system hardware telemetry."""

    def __init__(
        self,
        sandbox_root: Optional[Path | str] = None,
        trash_dir_name: str = ".agentos_trash",
        journal: Optional[Any] = None,
        db_manager: Optional[Any] = None,
    ):
        """Initializes the FileEngine.

        Args:
            sandbox_root: Optional sandbox root path. If None, reads SANDBOX_ROOT env.
            trash_dir_name: Subdirectory name for quarantined files.
            journal: Optional TransactionJournal instance for write-ahead logging and undo.
            db_manager: Optional DatabaseManager instance to bind transaction logging to.
        """
        self.sandbox_root = ensure_sandbox_root(sandbox_root)
        self.trash_dir = self.sandbox_root / trash_dir_name
        self.trash_dir.mkdir(parents=True, exist_ok=True)

        if journal is None:
            from storage.journal import TransactionJournal

            self.journal = TransactionJournal(
                db_manager=db_manager,
                sandbox_root=self.sandbox_root,
                trash_dir_name=trash_dir_name,
            )
        else:
            self.journal = journal

    def file_search(
        self,
        pattern: str = "*",
        relative_to: Optional[str | Path] = None,
        max_results: int = 100,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Searches files inside the sandbox matching a glob pattern.

        Args:
            pattern: Glob search pattern (e.g., '*.py', '*.java').
            relative_to: Subdirectory within sandbox to anchor search.
            max_results: Maximum number of matches to return.
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult with matching relative file paths.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.FILE_SEARCH,
            params={"pattern": pattern, "relative_to": relative_to},
            ring=PrivilegeRing.RING_3,
        )

        start_time = time.time()
        try:
            base_dir = (
                validate_safe_path(relative_to, self.sandbox_root)
                if relative_to
                else self.sandbox_root
            )
        except PathSecurityViolation as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        if not base_dir.is_dir():
            # Typo-tolerant directory resolution for subdirectories within sandbox
            resolved_fuzzy: Optional[Path] = None
            if relative_to:
                target_name = Path(relative_to).name.lower()
                existing_dirs = [
                    d for d in self.sandbox_root.iterdir()
                    if d.is_dir() and d != self.trash_dir
                ]
                # 1. Exact case-insensitive match
                for d in existing_dirs:
                    if d.name.lower() == target_name:
                        resolved_fuzzy = d
                        break
                # 2. Close match via difflib (e.g. demo_assests -> demo_assets)
                if not resolved_fuzzy:
                    dir_names = [d.name for d in existing_dirs]
                    close_matches = difflib.get_close_matches(
                        Path(relative_to).name, dir_names, n=1, cutoff=0.5
                    )
                    if close_matches:
                        resolved_fuzzy = self.sandbox_root / close_matches[0]

            if resolved_fuzzy and resolved_fuzzy.is_dir():
                base_dir = resolved_fuzzy
            else:
                # If directory still cannot be resolved, return informative non-crashing result
                avail = ", ".join([d.name for d in self.sandbox_root.iterdir() if d.is_dir() and d != self.trash_dir]) or "none"
                return SyscallResult.ok(
                    request=req,
                    output=f"No directory named '{relative_to}' found in workspace. Available directories: {avail}",
                    data=[],
                    duration_sec=time.time() - start_time,
                )

        matches: list[str] = []
        try:
            # Recursively match pattern
            for item in sorted(base_dir.rglob(pattern)):
                # Skip quarantine trash items from regular search results
                try:
                    item.relative_to(self.trash_dir)
                    continue
                except ValueError:
                    pass

                rel = str(item.relative_to(self.sandbox_root)).replace("\\", "/")
                matches.append(rel)
                if len(matches) >= max_results:
                    break
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Error searching files: {exc}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        output_str = "\n".join(matches) if matches else "No files found matching pattern."
        return SyscallResult.ok(
            request=req,
            output=output_str,
            data=matches,
            duration_sec=time.time() - start_time,
        )

    def file_read(
        self,
        file_path: str | Path,
        max_bytes: int = 1024 * 1024,
        encoding: str = "utf-8",
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Safely reads file contents bounded by a byte limit.

        Args:
            file_path: Relative or absolute path within sandbox.
            max_bytes: Upper byte cap to prevent excessive memory consumption.
            encoding: Text encoding (default: utf-8).
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult with the file contents.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.FILE_READ,
            params={"path": str(file_path)},
            ring=PrivilegeRing.RING_3,
        )

        start_time = time.time()
        try:
            safe_path = validate_safe_path(file_path, self.sandbox_root)
        except PathSecurityViolation as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        if not safe_path.exists():
            return SyscallResult.fail(
                request=req,
                error=f"File not found: {file_path}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        if not safe_path.is_file():
            return SyscallResult.fail(
                request=req,
                error=f"Target path is a directory, not a file: {file_path}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        try:
            file_size = safe_path.stat().st_size
            with open(safe_path, "r", encoding=encoding, errors="replace") as f:
                content = f.read(max_bytes)

            truncated = file_size > max_bytes
            rel_path = str(safe_path.relative_to(self.sandbox_root)).replace("\\", "/")
            return SyscallResult.ok(
                request=req,
                output=content,
                data={
                    "path": rel_path,
                    "bytes_read": len(content.encode(encoding, errors="replace")),
                    "total_size": file_size,
                    "truncated": truncated,
                },
                duration_sec=time.time() - start_time,
            )
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Error reading file '{file_path}': {exc}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

    def file_write(
        self,
        file_path: str | Path,
        content: str,
        mode: str = "w",
        encoding: str = "utf-8",
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Safely writes or appends content to a file inside the sandbox.

        Args:
            file_path: Relative or absolute path within sandbox.
            content: String text content to write.
            mode: Write mode ('w' for overwrite, 'a' for append).
            encoding: Text encoding.
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult with write metadata.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.FILE_WRITE,
            params={"path": str(file_path), "mode": mode},
            ring=PrivilegeRing.RING_0,
        )

        start_time = time.time()
        try:
            safe_path = validate_safe_path(file_path, self.sandbox_root)
        except PathSecurityViolation as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        try:
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            is_new = not safe_path.exists()
            previous_content: Optional[str] = None
            if not is_new and safe_path.is_file():
                try:
                    with open(safe_path, "r", encoding=encoding, errors="replace") as f_prev:
                        previous_content = f_prev.read()
                except Exception:
                    pass

            with open(safe_path, mode, encoding=encoding) as f:
                bytes_written = f.write(content)

            rel_path = str(safe_path.relative_to(self.sandbox_root)).replace("\\", "/")

            if self.journal is not None:
                try:
                    self.journal.record_write(
                        file_path=rel_path,
                        previous_content=previous_content,
                        is_new=is_new,
                        details={"bytes_written": bytes_written, "mode": mode},
                    )
                except Exception:
                    pass

            return SyscallResult.ok(
                request=req,
                output=f"Wrote {bytes_written} characters to '{rel_path}'.",
                data={
                    "path": rel_path,
                    "bytes_written": bytes_written,
                    "mode": mode,
                },
                duration_sec=time.time() - start_time,
            )
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Error writing file '{file_path}': {exc}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

    def file_move(
        self,
        src_path: str | Path,
        dest_path: str | Path,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Safely moves or renames a file or directory within the sandbox.

        Args:
            src_path: Source path.
            dest_path: Destination path.
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult with relocation details.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.FILE_MOVE,
            params={"src": str(src_path), "dest": str(dest_path)},
            ring=PrivilegeRing.RING_0,
        )

        start_time = time.time()
        try:
            safe_src = validate_safe_path(src_path, self.sandbox_root)
            safe_dest = validate_safe_path(dest_path, self.sandbox_root)
        except PathSecurityViolation as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        if not safe_src.exists():
            return SyscallResult.fail(
                request=req,
                error=f"Source path not found: {src_path}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        try:
            safe_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(safe_src), str(safe_dest))

            rel_src = str(safe_src.relative_to(self.sandbox_root)).replace("\\", "/")
            rel_dest = str(safe_dest.relative_to(self.sandbox_root)).replace("\\", "/")

            if self.journal is not None:
                try:
                    self.journal.record_move(
                        src_path=rel_src,
                        dest_path=rel_dest,
                    )
                except Exception:
                    pass

            return SyscallResult.ok(
                request=req,
                output=f"Moved '{rel_src}' -> '{rel_dest}'.",
                data={"src": rel_src, "dest": rel_dest},
                duration_sec=time.time() - start_time,
            )
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Error moving '{src_path}' to '{dest_path}': {exc}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

    def file_delete(
        self,
        file_path: str | Path,
        quarantine: bool = True,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Deletes a file or folder, defaulting to safe quarantine in .agentos_trash.

        Args:
            file_path: Target path to delete.
            quarantine: If True, moves to quarantine with metadata rather than unlinking.
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult indicating outcome.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.FILE_DELETE,
            params={"path": str(file_path), "quarantine": quarantine},
            ring=PrivilegeRing.RING_0,
        )

        start_time = time.time()
        try:
            safe_path = validate_safe_path(file_path, self.sandbox_root)
        except PathSecurityViolation as exc:
            return SyscallResult.fail(
                request=req,
                error=str(exc),
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        if not safe_path.exists():
            return SyscallResult.fail(
                request=req,
                error=f"Target path not found: {file_path}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

        rel_path = str(safe_path.relative_to(self.sandbox_root)).replace("\\", "/")

        try:
            if quarantine:
                ts = int(time.time())
                trash_target_name = f"{ts}_{safe_path.name}"
                quarantined_dest = self.trash_dir / trash_target_name
                is_directory = safe_path.is_dir()

                shutil.move(str(safe_path), str(quarantined_dest))

                # Store recovery metadata
                meta_file = self.trash_dir / f"{trash_target_name}.meta.json"
                meta_data = {
                    "original_relative_path": rel_path,
                    "quarantined_target": trash_target_name,
                    "timestamp": time.time(),
                    "is_directory": is_directory,
                }
                with open(meta_file, "w", encoding="utf-8") as mf:
                    json.dump(meta_data, mf, indent=2)

                if self.journal is not None:
                    try:
                        self.journal.record_quarantine(
                            original_path=rel_path,
                            quarantined_target=trash_target_name,
                            is_directory=is_directory,
                            details=meta_data,
                        )
                    except Exception:
                        pass

                return SyscallResult.ok(
                    request=req,
                    output=f"Quarantined '{rel_path}' to '{trash_target_name}'.",
                    data=meta_data,
                    duration_sec=time.time() - start_time,
                )
            else:
                if safe_path.is_dir():
                    shutil.rmtree(str(safe_path))
                else:
                    safe_path.unlink()

                return SyscallResult.ok(
                    request=req,
                    output=f"Permanently deleted '{rel_path}'.",
                    data={"deleted_path": rel_path, "permanent": True},
                    duration_sec=time.time() - start_time,
                )
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Error deleting '{file_path}': {exc}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

    def get_sys_info(
        self,
        request: Optional[SyscallRequest] = None,
    ) -> SyscallResult:
        """Retrieves hardware metrics, host OS telemetry, and sandbox path.

        Args:
            request: Optional parent SyscallRequest context.

        Returns:
            SyscallResult with host hardware and environment stats.
        """
        req = request or SyscallRequest(
            syscall=SyscallType.SYS_INFO,
            params={},
            ring=PrivilegeRing.RING_3,
        )

        start_time = time.time()
        try:
            vmem = psutil.virtual_memory()
            disk = shutil.disk_usage(str(self.sandbox_root))

            stats: dict[str, Any] = {
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "cpu_count_physical": psutil.cpu_count(logical=False),
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_total_mb": round(vmem.total / (1024 * 1024), 2),
                "memory_available_mb": round(vmem.available / (1024 * 1024), 2),
                "memory_used_percent": vmem.percent,
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "sandbox_root": str(self.sandbox_root),
            }

            output_str = (
                f"OS: {stats['os']} {stats['os_release']} ({stats['architecture']})\n"
                f"CPU: {stats['cpu_count_logical']} Logical Cores (Usage: {stats['cpu_percent']}%)\n"
                f"RAM: {stats['memory_available_mb']} MB available / {stats['memory_total_mb']} MB total ({stats['memory_used_percent']}% used)\n"
                f"Sandbox: {stats['sandbox_root']}"
            )

            return SyscallResult.ok(
                request=req,
                output=output_str,
                data=stats,
                duration_sec=time.time() - start_time,
            )
        except Exception as exc:
            return SyscallResult.fail(
                request=req,
                error=f"Error collecting system info: {exc}",
                exit_code=1,
                duration_sec=time.time() - start_time,
            )

    def undo_last_action(self) -> Any:
        """Rolls back the most recent un-reverted transaction in the journal.

        Returns:
            UndoResult from the transaction journal.
        """
        if self.journal is None:
            from storage.journal import UndoResult

            return UndoResult(
                success=False,
                message="No transaction journal configured.",
                entry=None,
            )
        return self.journal.undo_last(sandbox_root=self.sandbox_root)

    def get_journal_history(self, limit: int = 50) -> list[Any]:
        """Retrieves recent transaction journal entries."""
        if self.journal is None:
            return []
        return self.journal.get_history(limit=limit)

