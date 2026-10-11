"""Automated Verification Suite for Write-Ahead Transaction Journal and Undo Engine (Phase 6).

Verifies SQLite table persistence, quarantine file restoration, directory recovery,
file move and write rollbacks, LIFO multi-step undo stacking, and FileEngine/SyscallDispatcher integration.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from kernel.file_engine import FileEngine
from kernel.syscalls import (
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallType,
)
from storage.db import DatabaseManager
from storage.journal import (
    JournalAction,
    JournalEntry,
    TransactionJournal,
    UndoResult,
)


@pytest.fixture
def journal_sandbox(tmp_path: Path):
    """Fixture providing isolated sandbox root and TransactionJournal."""
    sandbox = tmp_path / "journal_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    journal = TransactionJournal(db_manager=db, sandbox_root=sandbox)
    return {
        "sandbox": sandbox,
        "db": db,
        "journal": journal,
        "trash": sandbox / ".agentos_trash",
    }


def test_journal_schema_initialization(journal_sandbox: dict):
    """Verifies that the file_journal table and indexes are created properly."""
    db: DatabaseManager = journal_sandbox["db"]
    conn = db.get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='file_journal'"
    )
    assert cursor.fetchone() is not None

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_journal_undone'"
    )
    assert cursor.fetchone() is not None


def test_record_and_get_history(journal_sandbox: dict):
    """Verifies recording multiple entries and retrieving formatted history."""
    journal: TransactionJournal = journal_sandbox["journal"]

    id1 = journal.record_quarantine(
        original_path="docs/spec.txt",
        quarantined_target="1001_spec.txt",
        is_directory=False,
    )
    id2 = journal.record_move(
        src_path="src/main.py",
        dest_path="src/app.py",
    )
    id3 = journal.record_write(
        file_path="config.json",
        previous_content='{"debug": false}',
        is_new=False,
    )

    assert id1 > 0
    assert id2 > id1
    assert id3 > id2

    history = journal.get_history(limit=10, include_undone=True)
    assert len(history) == 3
    assert history[0].id == id3
    assert history[0].action_type == JournalAction.FILE_WRITE
    assert history[1].id == id2
    assert history[1].action_type == JournalAction.FILE_MOVE
    assert history[2].id == id1
    assert history[2].action_type == JournalAction.FILE_DELETE

    # Most recent reversible action
    last = journal.get_last_action()
    assert last is not None
    assert last.id == id3


def test_undo_quarantined_file(journal_sandbox: dict):
    """Verifies that undoing a quarantined file restores it to its original path and content."""
    sandbox: Path = journal_sandbox["sandbox"]
    trash: Path = journal_sandbox["trash"]
    journal: TransactionJournal = journal_sandbox["journal"]

    # 1. Create a file inside sandbox
    sub_dir = sandbox / "nested" / "project"
    sub_dir.mkdir(parents=True, exist_ok=True)
    target_file = sub_dir / "target.py"
    target_content = "def calculate(): return 42\n"
    target_file.write_text(target_content, encoding="utf-8")

    # 2. Simulate quarantine deletion
    quarantined_name = "12345_target.py"
    quarantined_file = trash / quarantined_name
    target_file.rename(quarantined_file)
    meta_file = trash / f"{quarantined_name}.meta.json"
    meta_file.write_text(json.dumps({"original_relative_path": "nested/project/target.py"}), encoding="utf-8")

    # Record in journal
    journal.record_quarantine(
        original_path="nested/project/target.py",
        quarantined_target=quarantined_name,
        is_directory=False,
    )

    assert not target_file.exists()
    assert quarantined_file.exists()
    assert journal.can_undo() is True

    # 3. Undo
    res: UndoResult = journal.undo_last()
    assert res.success is True
    assert "Restored 'nested/project/target.py'" in res.message
    assert target_file.exists()
    assert target_file.read_text(encoding="utf-8") == target_content
    assert not quarantined_file.exists()
    assert not meta_file.exists()

    # Journal should now indicate action was undone
    assert journal.can_undo() is False


def test_undo_quarantined_directory(journal_sandbox: dict):
    """Verifies restoring an entire quarantined directory with its contents."""
    sandbox: Path = journal_sandbox["sandbox"]
    trash: Path = journal_sandbox["trash"]
    journal: TransactionJournal = journal_sandbox["journal"]

    # Create directory with nested files
    pkg_dir = sandbox / "my_package"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "__init__.py").write_text("# init\n", encoding="utf-8")
    (pkg_dir / "core.py").write_text("# core logic\n", encoding="utf-8")

    # Quarantine directory
    trash_target = "99999_my_package"
    quarantined_pkg = trash / trash_target
    pkg_dir.rename(quarantined_pkg)

    journal.record_quarantine(
        original_path="my_package",
        quarantined_target=trash_target,
        is_directory=True,
    )

    assert not pkg_dir.exists()
    assert quarantined_pkg.exists()

    # Revert quarantine
    res = journal.undo_last()
    assert res.success is True
    assert pkg_dir.exists()
    assert (pkg_dir / "__init__.py").read_text(encoding="utf-8") == "# init\n"
    assert (pkg_dir / "core.py").read_text(encoding="utf-8") == "# core logic\n"
    assert not quarantined_pkg.exists()


def test_undo_file_move(journal_sandbox: dict):
    """Verifies that undoing a file move relocates the file back to its original path."""
    sandbox: Path = journal_sandbox["sandbox"]
    journal: TransactionJournal = journal_sandbox["journal"]

    orig = sandbox / "reports" / "summary.csv"
    orig.parent.mkdir(parents=True, exist_ok=True)
    orig.write_text("col1,col2\n1,2\n", encoding="utf-8")

    dest = sandbox / "archive" / "summary_v1.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    orig.rename(dest)

    journal.record_move(src_path="reports/summary.csv", dest_path="archive/summary_v1.csv")

    assert not orig.exists()
    assert dest.exists()

    res = journal.undo_last()
    assert res.success is True
    assert orig.exists()
    assert not dest.exists()
    assert orig.read_text(encoding="utf-8") == "col1,col2\n1,2\n"


def test_undo_file_write_overwritten(journal_sandbox: dict):
    """Verifies restoring previous content when an existing file was overwritten."""
    sandbox: Path = journal_sandbox["sandbox"]
    journal: TransactionJournal = journal_sandbox["journal"]

    conf = sandbox / "settings.env"
    initial_content = "DEBUG=True\nPORT=8000\n"
    conf.write_text(initial_content, encoding="utf-8")

    # Overwrite file
    new_content = "DEBUG=False\nPORT=443\n"
    conf.write_text(new_content, encoding="utf-8")

    journal.record_write(
        file_path="settings.env",
        previous_content=initial_content,
        is_new=False,
    )

    res = journal.undo_last()
    assert res.success is True
    assert "Restored prior contents" in res.message
    assert conf.read_text(encoding="utf-8") == initial_content


def test_undo_file_write_new(journal_sandbox: dict):
    """Verifies removing a newly created file on undo."""
    sandbox: Path = journal_sandbox["sandbox"]
    journal: TransactionJournal = journal_sandbox["journal"]

    new_file = sandbox / "scratch" / "temp.log"
    new_file.parent.mkdir(parents=True, exist_ok=True)
    new_file.write_text("log line 1\n", encoding="utf-8")

    journal.record_write(
        file_path="scratch/temp.log",
        previous_content=None,
        is_new=True,
    )

    assert new_file.exists()
    res = journal.undo_last()
    assert res.success is True
    assert "Removed newly written file" in res.message
    assert not new_file.exists()


def test_multiple_sequential_undos(journal_sandbox: dict):
    """Verifies LIFO stack behavior when reversing multiple actions in sequence."""
    sandbox: Path = journal_sandbox["sandbox"]
    trash: Path = journal_sandbox["trash"]
    journal: TransactionJournal = journal_sandbox["journal"]

    # Action 1: Write file A
    file_a = sandbox / "file_a.txt"
    file_a.write_text("AAA", encoding="utf-8")
    journal.record_write("file_a.txt", previous_content=None, is_new=True)

    # Action 2: Write file B
    file_b = sandbox / "file_b.txt"
    file_b.write_text("BBB", encoding="utf-8")
    journal.record_write("file_b.txt", previous_content=None, is_new=True)

    # Action 3: Quarantine file A
    q_name = "q_file_a.txt"
    file_a.rename(trash / q_name)
    journal.record_quarantine("file_a.txt", quarantined_target=q_name)

    assert not file_a.exists()
    assert file_b.exists()

    # Undo 1: should undo Action 3 (quarantine of file A)
    u1 = journal.undo_last()
    assert u1.success is True
    assert u1.entry.action_type == JournalAction.FILE_DELETE
    assert file_a.exists()
    assert file_a.read_text() == "AAA"

    # Undo 2: should undo Action 2 (creation of file B)
    u2 = journal.undo_last()
    assert u2.success is True
    assert u2.entry.action_type == JournalAction.FILE_WRITE
    assert not file_b.exists()

    # Undo 3: should undo Action 1 (creation of file A)
    u3 = journal.undo_last()
    assert u3.success is True
    assert not file_a.exists()

    # Undo 4: nothing left to undo
    u4 = journal.undo_last()
    assert u4.success is False
    assert "No reversible actions" in u4.message


def test_undo_empty_journal(journal_sandbox: dict):
    """Verifies that undoing an empty journal returns a clean failure result without exceptions."""
    journal: TransactionJournal = journal_sandbox["journal"]
    assert journal.can_undo() is False
    res = journal.undo_last()
    assert res.success is False
    assert res.entry is None


def test_file_engine_integration_with_journal(tmp_path: Path):
    """Verifies that FileEngine automatically writes transactions and supports undo."""
    sandbox = tmp_path / "engine_sandbox"
    fe = FileEngine(sandbox_root=sandbox)

    # 1. Write file
    w_res = fe.file_write("data.txt", "version 1")
    assert w_res.success is True
    assert (sandbox / "data.txt").exists()

    # 2. Delete file (quarantine)
    d_res = fe.file_delete("data.txt", quarantine=True)
    assert d_res.success is True
    assert not (sandbox / "data.txt").exists()

    # 3. Undo delete
    undo_res = fe.undo_last_action()
    assert undo_res.success is True
    assert (sandbox / "data.txt").exists()
    assert (sandbox / "data.txt").read_text(encoding="utf-8") == "version 1"

    # 4. Undo write
    undo_write_res = fe.undo_last_action()
    assert undo_write_res.success is True
    assert not (sandbox / "data.txt").exists()


def test_dispatcher_undo_last_action(tmp_path: Path):
    """Verifies that SyscallDispatcher executes undo and logs it to SQLite audit log."""
    sandbox = tmp_path / "dispatcher_sandbox"
    db = DatabaseManager(db_path=":memory:")
    fe = FileEngine(sandbox_root=sandbox)
    dispatcher = SyscallDispatcher(file_engine=fe, db_manager=db)

    # Dispatch file write
    req_write = SyscallRequest(
        syscall=SyscallType.FILE_WRITE,
        params={"path": "audit_test.txt", "content": "audit data"},
    )
    dispatcher.dispatch(req_write, user_confirmed=True)
    assert (sandbox / "audit_test.txt").exists()

    # Dispatch file delete
    req_del = SyscallRequest(
        syscall=SyscallType.FILE_DELETE,
        params={"path": "audit_test.txt", "quarantine": True},
    )
    dispatcher.dispatch(req_del, user_confirmed=True)
    assert not (sandbox / "audit_test.txt").exists()

    # Dispatch undo through dispatcher
    undo_result = dispatcher.undo_last_action()
    assert undo_result.success is True
    assert "Restored 'audit_test.txt'" in undo_result.output
    assert (sandbox / "audit_test.txt").exists()

    # Verify SQLite audit log recorded the undo action
    audit_logs = db.get_audit_logs(limit=10)
    assert len(audit_logs) >= 3
    undo_log = audit_logs[0]  # newest first
    assert undo_log["success"] == 1
    assert "UNDO_LAST" in undo_log["params_json"]
