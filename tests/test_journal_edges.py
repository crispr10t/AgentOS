"""Comprehensive edge-case tests for storage/journal.py: TransactionJournal, WAL, and Undo Engine."""

from pathlib import Path
import pytest

from storage.db import DatabaseManager
from storage.journal import JournalAction, TransactionJournal, UndoResult


@pytest.fixture
def isolated_journal(tmp_path: Path):
    """Fixture providing an isolated TransactionJournal within tmp_path."""
    sandbox = tmp_path / "journal_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    journal = TransactionJournal(db_manager=db, sandbox_root=sandbox)
    return journal, sandbox


# --- 1. Undo FILE_WRITE Edge Cases ---

def test_undo_file_write_new_file_deletes_it(isolated_journal):
    """Undoing the write of a new file unlinks the file."""
    journal, sandbox = isolated_journal
    test_file = sandbox / "new_created.txt"
    test_file.write_text("initial data")

    entry_id = journal.record_write("new_created.txt", previous_content=None, is_new=True)
    assert journal.can_undo() is True

    res = journal.undo_entry(entry_id)
    assert res.success is True
    assert not test_file.exists()


def test_undo_file_write_overwrite_restores_previous_content(isolated_journal):
    """Undoing an overwrite restores the previous content."""
    journal, sandbox = isolated_journal
    test_file = sandbox / "overwrite.txt"
    test_file.write_text("updated content")

    entry_id = journal.record_write("overwrite.txt", previous_content="original content", is_new=False)

    res = journal.undo_entry(entry_id)
    assert res.success is True
    assert test_file.read_text() == "original content"


# --- 2. Undo FILE_MOVE Edge Cases ---

def test_undo_file_move_relocates_back(isolated_journal):
    """Undoing a move returns the file to its original location."""
    journal, sandbox = isolated_journal
    dest_file = sandbox / "dest_folder" / "moved.txt"
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    dest_file.write_text("file content")

    entry_id = journal.record_move(src_path="orig_folder/moved.txt", dest_path="dest_folder/moved.txt")

    res = journal.undo_entry(entry_id)
    assert res.success is True
    assert (sandbox / "orig_folder" / "moved.txt").exists()
    assert not dest_file.exists()


def test_undo_file_move_missing_dest_fails(isolated_journal):
    """Undoing a move when destination is missing returns failure."""
    journal, _ = isolated_journal
    entry_id = journal.record_move(src_path="orig.txt", dest_path="missing_dest.txt")

    res = journal.undo_entry(entry_id)
    assert res.success is False
    assert "not found" in res.message


# --- 3. Undo FILE_DELETE Edge Cases ---

def test_undo_file_delete_restores_from_trash(isolated_journal):
    """Undoing quarantine moves file back from .agentos_trash to original location."""
    journal, sandbox = isolated_journal
    trash_target = "12345_deleted.txt"
    quarantined = journal.trash_dir / trash_target
    quarantined.write_text("saved from trash")

    entry_id = journal.record_quarantine(original_path="sub/restored.txt", quarantined_target=trash_target)

    res = journal.undo_entry(entry_id)
    assert res.success is True
    assert (sandbox / "sub" / "restored.txt").exists()
    assert (sandbox / "sub" / "restored.txt").read_text() == "saved from trash"
    assert not quarantined.exists()


def test_undo_file_delete_missing_trash_file_fails(isolated_journal):
    """Undoing quarantine when trash file was purged returns failure."""
    journal, _ = isolated_journal
    entry_id = journal.record_quarantine(original_path="restored.txt", quarantined_target="ghost_trash.txt")

    res = journal.undo_entry(entry_id)
    assert res.success is False
    assert "not found in trash directory" in res.message


# --- 4. Journal State Machine and History ---

def test_undo_empty_journal():
    """Undoing when journal has no entries returns failure."""
    db = DatabaseManager(db_path=":memory:")
    journal = TransactionJournal(db_manager=db)
    assert journal.can_undo() is False

    res = journal.undo_last()
    assert res.success is False
    assert "No reversible actions" in res.message


def test_undo_nonexistent_entry_id(isolated_journal):
    """Undoing a non-existent entry ID returns failure."""
    journal, _ = isolated_journal
    res = journal.undo_entry(99999)
    assert res.success is False
    assert "not found" in res.message


def test_undo_already_undone_entry(isolated_journal):
    """Attempting to undo an already undone entry returns failure."""
    journal, sandbox = isolated_journal
    test_file = sandbox / "once.txt"
    test_file.write_text("hello")

    entry_id = journal.record_write("once.txt", is_new=True)
    res1 = journal.undo_entry(entry_id)
    assert res1.success is True

    res2 = journal.undo_entry(entry_id)
    assert res2.success is False
    assert "already been undone" in res2.message


def test_lifo_undo_sequence(isolated_journal):
    """Undoing multiple actions in LIFO sequence."""
    journal, sandbox = isolated_journal

    # Step 1: Write file 1
    f1 = sandbox / "f1.txt"
    f1.write_text("data 1")
    id1 = journal.record_write("f1.txt", is_new=True)

    # Step 2: Write file 2
    f2 = sandbox / "f2.txt"
    f2.write_text("data 2")
    id2 = journal.record_write("f2.txt", is_new=True)

    # Undo last (f2)
    res_last = journal.undo_last()
    assert res_last.success is True
    assert res_last.entry.id == id2
    assert not f2.exists()
    assert f1.exists()

    # Undo next (f1)
    res_prev = journal.undo_last()
    assert res_prev.success is True
    assert res_prev.entry.id == id1
    assert not f1.exists()

    # No more undoable actions
    assert journal.can_undo() is False


def test_journal_get_history_filtering(isolated_journal):
    """Verify get_history filtering with include_undone."""
    journal, sandbox = isolated_journal
    id1 = journal.record_write("a.txt", is_new=True)
    id2 = journal.record_write("b.txt", is_new=True)

    journal.undo_entry(id2)

    all_hist = journal.get_history(include_undone=True)
    assert len(all_hist) == 2

    active_hist = journal.get_history(include_undone=False)
    assert len(active_hist) == 1
    assert active_hist[0].id == id1
