"""Write-Ahead Transaction Journal and Undo Engine for AgentOS.

Maintains an atomic audit of sandboxed filesystem modifications in SQLite,
enabling non-destructive rollback and restoration of quarantined files
from '.agentos_trash' directly back into the sandbox.
"""

from __future__ import annotations

from enum import Enum
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import threading
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from security.sandbox import ensure_sandbox_root, validate_safe_path
from storage.db import DatabaseManager

logger = logging.getLogger(__name__)


class JournalAction(str, Enum):
    """Types of journaled filesystem operations."""

    FILE_DELETE = "FILE_DELETE"  # Quarantined into trash
    FILE_MOVE = "FILE_MOVE"      # Moved or renamed
    FILE_WRITE = "FILE_WRITE"    # Written or overwritten


class JournalEntry(BaseModel):
    """Data record for a single journaled filesystem transaction."""

    id: int
    timestamp: float
    action_type: JournalAction
    original_path: str
    target_path: Optional[str] = None
    backup_data: Optional[str] = None
    is_directory: bool = False
    undone: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class UndoResult(BaseModel):
    """Result payload returned by an undo/restore operation."""

    success: bool
    message: str
    entry: Optional[JournalEntry] = None


class TransactionJournal:
    """Thread-safe write-ahead transaction log and rollback manager."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        sandbox_root: Optional[Path | str] = None,
        db_path: Optional[str | Path] = None,
        trash_dir_name: str = ".agentos_trash",
    ):
        """Initializes the TransactionJournal.

        Args:
            db_manager: Optional existing DatabaseManager instance.
            sandbox_root: Canonical sandbox root path.
            db_path: Optional SQLite database path if db_manager is omitted.
            trash_dir_name: Subdirectory name for quarantined files.
        """
        if db_manager is not None:
            self.db_manager = db_manager
        else:
            self.db_manager = DatabaseManager(db_path=db_path)

        self.sandbox_root = ensure_sandbox_root(sandbox_root)
        self.trash_dir = self.sandbox_root / trash_dir_name
        self.trash_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        self._ensure_journal_schema()

    def _ensure_journal_schema(self) -> None:
        """Verifies that the file_journal table exists."""
        conn = self.db_manager.get_connection()
        try:
            with conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS file_journal (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        action_type TEXT NOT NULL,
                        original_path TEXT NOT NULL,
                        target_path TEXT,
                        backup_data TEXT,
                        is_directory INTEGER NOT NULL DEFAULT 0,
                        undone INTEGER NOT NULL DEFAULT 0,
                        details_json TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_journal_undone ON file_journal(undone);
                    CREATE INDEX IF NOT EXISTS idx_journal_timestamp ON file_journal(timestamp);
                    """
                )
        finally:
            if not self.db_manager.is_memory:
                conn.close()

    def record_entry(
        self,
        action_type: JournalAction | str,
        original_path: str,
        target_path: Optional[str] = None,
        backup_data: Optional[str] = None,
        is_directory: bool = False,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """Records an entry in the transaction journal.

        Args:
            action_type: Operation type (FILE_DELETE, FILE_MOVE, FILE_WRITE).
            original_path: Original path relative to sandbox root.
            target_path: Relocation or quarantine target path.
            backup_data: Pre-modification content backup (if applicable).
            is_directory: Whether target is a directory.
            details: Additional arbitrary transaction metadata.

        Returns:
            The auto-incremented journal entry ID.
        """
        action_str = (
            action_type.value if isinstance(action_type, JournalAction) else str(action_type)
        )
        norm_orig = str(original_path).replace("\\", "/")
        norm_target = str(target_path).replace("\\", "/") if target_path else None
        details_json = json.dumps(details or {}, default=str)
        ts = time.time()

        with self._lock:
            conn = self.db_manager.get_connection()
            try:
                with conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO file_journal (
                            timestamp, action_type, original_path, target_path,
                            backup_data, is_directory, undone, details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                        """,
                        (
                            ts,
                            action_str,
                            norm_orig,
                            norm_target,
                            backup_data,
                            1 if is_directory else 0,
                            details_json,
                        ),
                    )
                    entry_id = cursor.lastrowid or 0
                return entry_id
            finally:
                if not self.db_manager.is_memory:
                    conn.close()

    def record_quarantine(
        self,
        original_path: str,
        quarantined_target: str,
        is_directory: bool = False,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """Convenience method to record a quarantined file deletion."""
        return self.record_entry(
            action_type=JournalAction.FILE_DELETE,
            original_path=original_path,
            target_path=quarantined_target,
            is_directory=is_directory,
            details=details,
        )

    def record_move(
        self,
        src_path: str,
        dest_path: str,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """Convenience method to record a file move or rename."""
        return self.record_entry(
            action_type=JournalAction.FILE_MOVE,
            original_path=src_path,
            target_path=dest_path,
            details=details,
        )

    def record_write(
        self,
        file_path: str,
        previous_content: Optional[str] = None,
        is_new: bool = True,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """Convenience method to record a file write or update."""
        extra = dict(details or {})
        extra["is_new"] = is_new
        return self.record_entry(
            action_type=JournalAction.FILE_WRITE,
            original_path=file_path,
            backup_data=previous_content,
            details=extra,
        )

    def _row_to_entry(self, row: sqlite3.Row | tuple) -> JournalEntry:
        """Converts an SQLite row into a typed JournalEntry."""
        row_dict = dict(row)
        det_raw = row_dict.get("details_json")
        details = json.loads(det_raw) if det_raw else {}

        return JournalEntry(
            id=row_dict["id"],
            timestamp=row_dict["timestamp"],
            action_type=JournalAction(row_dict["action_type"]),
            original_path=row_dict["original_path"],
            target_path=row_dict.get("target_path"),
            backup_data=row_dict.get("backup_data"),
            is_directory=bool(row_dict.get("is_directory", 0)),
            undone=bool(row_dict.get("undone", 0)),
            details=details,
        )

    def get_last_action(self) -> Optional[JournalEntry]:
        """Retrieves the most recent un-reverted transaction in the journal.

        Returns:
            The most recent un-reverted JournalEntry, or None if none exist.
        """
        with self._lock:
            conn = self.db_manager.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM file_journal
                    WHERE undone = 0
                    ORDER BY timestamp DESC, id DESC
                    LIMIT 1
                    """
                )
                row = cursor.fetchone()
                return self._row_to_entry(row) if row else None
            finally:
                if not self.db_manager.is_memory:
                    conn.close()

    def get_entry(self, entry_id: int) -> Optional[JournalEntry]:
        """Retrieves a specific journal entry by ID."""
        with self._lock:
            conn = self.db_manager.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM file_journal WHERE id = ?", (entry_id,))
                row = cursor.fetchone()
                return self._row_to_entry(row) if row else None
            finally:
                if not self.db_manager.is_memory:
                    conn.close()

    def get_history(
        self, limit: int = 100, include_undone: bool = True
    ) -> list[JournalEntry]:
        """Retrieves recent journal history ordered newest first.

        Args:
            limit: Maximum number of entries to return.
            include_undone: If False, filters only un-reverted transactions.

        Returns:
            List of JournalEntry items.
        """
        with self._lock:
            conn = self.db_manager.get_connection()
            try:
                cursor = conn.cursor()
                if include_undone:
                    cursor.execute(
                        """
                        SELECT * FROM file_journal
                        ORDER BY timestamp DESC, id DESC
                        LIMIT ?
                        """,
                        (limit,),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT * FROM file_journal
                        WHERE undone = 0
                        ORDER BY timestamp DESC, id DESC
                        LIMIT ?
                        """,
                        (limit,),
                    )
                return [self._row_to_entry(r) for r in cursor.fetchall()]
            finally:
                if not self.db_manager.is_memory:
                    conn.close()

    def can_undo(self) -> bool:
        """Returns True if there is at least one un-reverted transaction."""
        return self.get_last_action() is not None

    def _mark_undone(self, entry_id: int) -> None:
        """Marks a journal entry as undone in SQLite."""
        conn = self.db_manager.get_connection()
        try:
            with conn:
                conn.execute(
                    "UPDATE file_journal SET undone = 1 WHERE id = ?",
                    (entry_id,),
                )
        finally:
            if not self.db_manager.is_memory:
                conn.close()

    def undo_last(
        self, sandbox_root: Optional[Path | str] = None
    ) -> UndoResult:
        """Rolls back the most recent un-reverted transaction in the journal.

        Args:
            sandbox_root: Optional override of sandbox root.

        Returns:
            UndoResult indicating success, description message, and the JournalEntry.
        """
        with self._lock:
            entry = self.get_last_action()
            if entry is None:
                return UndoResult(
                    success=False,
                    message="No reversible actions in transaction journal.",
                    entry=None,
                )
            return self.undo_entry(entry.id, sandbox_root=sandbox_root)

    def undo_entry(
        self, entry_id: int, sandbox_root: Optional[Path | str] = None
    ) -> UndoResult:
        """Rolls back a specific journal entry by ID.

        Args:
            entry_id: ID of the journal entry to revert.
            sandbox_root: Optional override of sandbox root.

        Returns:
            UndoResult indicating outcome.
        """
        with self._lock:
            entry = self.get_entry(entry_id)
            if entry is None:
                return UndoResult(
                    success=False,
                    message=f"Journal entry #{entry_id} not found.",
                    entry=None,
                )

            if entry.undone:
                return UndoResult(
                    success=False,
                    message=f"Journal entry #{entry_id} ({entry.action_type.value}) has already been undone.",
                    entry=entry,
                )

            root = ensure_sandbox_root(sandbox_root or self.sandbox_root)
            trash = root / self.trash_dir.name

            try:
                if entry.action_type == JournalAction.FILE_DELETE:
                    # Target was moved into trash
                    target_name = entry.target_path or ""
                    # quarantined item can be located in trash dir
                    quarantined_path = trash / target_name
                    if not quarantined_path.exists():
                        # Try direct path
                        alt_path = root / target_name
                        if alt_path.exists():
                            quarantined_path = alt_path
                        else:
                            return UndoResult(
                                success=False,
                                message=f"Quarantined item '{target_name}' not found in trash directory.",
                                entry=entry,
                            )

                    orig_dest = root / entry.original_path
                    orig_dest.parent.mkdir(parents=True, exist_ok=True)

                    # Move back from trash to original location
                    shutil.move(str(quarantined_path), str(orig_dest))

                    # Clean up associated metadata file if present
                    meta_path = trash / f"{quarantined_path.name}.meta.json"
                    if meta_path.exists():
                        try:
                            meta_path.unlink()
                        except Exception:
                            pass

                    self._mark_undone(entry.id)
                    entry.undone = True
                    return UndoResult(
                        success=True,
                        message=f"Restored '{entry.original_path}' from quarantine.",
                        entry=entry,
                    )

                elif entry.action_type == JournalAction.FILE_MOVE:
                    # Move dest back to src
                    if not entry.target_path:
                        return UndoResult(
                            success=False,
                            message=f"Missing destination path for move entry #{entry.id}.",
                            entry=entry,
                        )

                    current_pos = root / entry.target_path
                    orig_pos = root / entry.original_path

                    if not current_pos.exists():
                        return UndoResult(
                            success=False,
                            message=f"Moved item '{entry.target_path}' not found at current location.",
                            entry=entry,
                        )

                    orig_pos.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(current_pos), str(orig_pos))

                    self._mark_undone(entry.id)
                    entry.undone = True
                    return UndoResult(
                        success=True,
                        message=f"Reverted move: restored '{entry.original_path}' from '{entry.target_path}'.",
                        entry=entry,
                    )

                elif entry.action_type == JournalAction.FILE_WRITE:
                    target_file = root / entry.original_path

                    if entry.backup_data is not None:
                        # File existed prior to write -> restore previous content
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(entry.backup_data)

                        self._mark_undone(entry.id)
                        entry.undone = True
                        return UndoResult(
                            success=True,
                            message=f"Restored prior contents of '{entry.original_path}'.",
                            entry=entry,
                        )
                    else:
                        # File was newly created -> remove it
                        if target_file.exists():
                            if target_file.is_dir():
                                shutil.rmtree(str(target_file))
                            else:
                                target_file.unlink()

                        self._mark_undone(entry.id)
                        entry.undone = True
                        return UndoResult(
                            success=True,
                            message=f"Removed newly written file '{entry.original_path}'.",
                            entry=entry,
                        )

                else:
                    return UndoResult(
                        success=False,
                        message=f"Unsupported journal action type '{entry.action_type}'.",
                        entry=entry,
                    )

            except Exception as exc:
                logger.error("Failed to undo journal entry #%s: %s", entry.id, exc)
                return UndoResult(
                    success=False,
                    message=f"Error executing rollback on #{entry.id}: {exc}",
                    entry=entry,
                )
