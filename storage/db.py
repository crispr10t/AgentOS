"""SQLite Persistence Layer for Task Histories and Audit Logs.

Provides a thread-safe DatabaseManager to log TaskPCB records
and track system call executions for auditing and viva demonstration.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Optional

from dotenv import load_dotenv

from kernel.pcb import TaskPCB
from kernel.syscalls import SyscallRequest, SyscallResult

load_dotenv()


class DatabaseManager:
    """Manages SQLite connection, schema creation, task history, and audit trails."""

    def __init__(self, db_path: Optional[str | Path] = None):
        """Initializes the database manager.

        Args:
            db_path: Path to SQLite DB file, ':memory:', or None to use DATABASE_PATH env.
        """
        if db_path is None:
            raw_path = os.getenv("DATABASE_PATH", "./data/agentos.db")
            self.db_path = raw_path
        else:
            self.db_path = str(db_path)

        self.is_memory = self.db_path == ":memory:"
        self._shared_memory_conn: Optional[sqlite3.Connection] = None

        if not self.is_memory:
            resolved_parent = Path(self.db_path).resolve().parent
            resolved_parent.mkdir(parents=True, exist_ok=True)
        else:
            # Maintain persistent connection for in-memory databases across calls
            self._shared_memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_memory_conn.row_factory = sqlite3.Row

        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a SQLite connection configured with sqlite3.Row."""
        if self.is_memory and self._shared_memory_conn is not None:
            return self._shared_memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Executes table and index creation statements."""
        conn = self.get_connection()
        try:
            with conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS tasks (
                        pid INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        state TEXT NOT NULL,
                        priority INTEGER NOT NULL DEFAULT 1,
                        created_at REAL NOT NULL,
                        started_at REAL,
                        ended_at REAL,
                        cpu_time REAL DEFAULT 0.0,
                        peak_memory_mb REAL DEFAULT 0.0,
                        exit_code INTEGER,
                        error_msg TEXT,
                        estimated_duration REAL DEFAULT 1.0,
                        turnaround_time REAL,
                        waiting_time REAL
                    );

                    CREATE TABLE IF NOT EXISTS syscall_audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        call_id TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        pid INTEGER,
                        syscall TEXT NOT NULL,
                        ring INTEGER NOT NULL,
                        params_json TEXT,
                        success INTEGER NOT NULL,
                        exit_code INTEGER,
                        duration_sec REAL DEFAULT 0.0,
                        output TEXT,
                        error TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
                    CREATE INDEX IF NOT EXISTS idx_audit_syscall ON syscall_audit_log(syscall);
                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON syscall_audit_log(timestamp);
                    """
                )
        finally:
            if not self.is_memory:
                conn.close()

    def save_task(self, pcb: TaskPCB) -> None:
        """Upserts a TaskPCB into the tasks table.

        Args:
            pcb: TaskPCB instance to persist.
        """
        conn = self.get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO tasks (
                        pid, name, state, priority, created_at, started_at, ended_at,
                        cpu_time, peak_memory_mb, exit_code, error_msg, estimated_duration,
                        turnaround_time, waiting_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(pid) DO UPDATE SET
                        name = excluded.name,
                        state = excluded.state,
                        priority = excluded.priority,
                        started_at = excluded.started_at,
                        ended_at = excluded.ended_at,
                        cpu_time = excluded.cpu_time,
                        peak_memory_mb = excluded.peak_memory_mb,
                        exit_code = excluded.exit_code,
                        error_msg = excluded.error_msg,
                        estimated_duration = excluded.estimated_duration,
                        turnaround_time = excluded.turnaround_time,
                        waiting_time = excluded.waiting_time;
                    """,
                    (
                        pcb.pid,
                        pcb.name,
                        pcb.state.value,
                        pcb.priority,
                        pcb.created_at,
                        pcb.started_at,
                        pcb.ended_at,
                        pcb.cpu_time,
                        pcb.peak_memory_mb,
                        pcb.exit_code,
                        pcb.error_msg,
                        pcb.estimated_duration,
                        pcb.turnaround_time,
                        pcb.waiting_time,
                    ),
                )
        finally:
            if not self.is_memory:
                conn.close()

    def get_task(self, pid: int) -> Optional[dict[str, Any]]:
        """Retrieves a single task record by PID.

        Args:
            pid: Process ID.

        Returns:
            Dictionary of task row fields or None if not found.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tasks WHERE pid = ?", (pid,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            if not self.is_memory:
                conn.close()

    def get_all_tasks(self, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieves recent task records ordered by creation timestamp descending.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of task row dictionaries.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            if not self.is_memory:
                conn.close()

    def log_syscall(
        self,
        request: SyscallRequest,
        result: SyscallResult,
        pid: Optional[int] = None,
    ) -> int:
        """Appends a system call audit log entry.

        Args:
            request: The dispatched SyscallRequest.
            result: The completed SyscallResult.
            pid: Optional associated process ID.

        Returns:
            Auto-incremented ID of the created audit log entry.
        """
        conn = self.get_connection()
        try:
            params_str = json.dumps(request.params, default=str)
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO syscall_audit_log (
                        call_id, timestamp, pid, syscall, ring, params_json,
                        success, exit_code, duration_sec, output, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.call_id,
                        time.time(),
                        pid,
                        request.syscall.value,
                        int(request.ring),
                        params_str,
                        1 if result.success else 0,
                        result.exit_code,
                        result.duration_sec,
                        result.output,
                        result.error,
                    ),
                )
                return cursor.lastrowid or 0
        finally:
            if not self.is_memory:
                conn.close()

    def get_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieves recent syscall audit logs ordered by timestamp descending.

        Args:
            limit: Maximum number of audit records to return.

        Returns:
            List of audit log dictionaries.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM syscall_audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            if not self.is_memory:
                conn.close()

    def close(self) -> None:
        """Closes any persistent in-memory connection."""
        if self._shared_memory_conn:
            self._shared_memory_conn.close()
            self._shared_memory_conn = None
