"""Comprehensive edge-case tests for kernel/file_engine.py: Sandboxed File Operations, Trash Quarantine, and System Info."""

import json
from pathlib import Path
import pytest

from kernel.file_engine import FileEngine
from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallType
from storage.db import DatabaseManager


@pytest.fixture
def isolated_engine(tmp_path: Path):
    """Fixture creating an isolated FileEngine instance within tmp_path."""
    sandbox = tmp_path / "engine_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    db = DatabaseManager(db_path=":memory:")
    engine = FileEngine(sandbox_root=sandbox, db_manager=db)
    return engine, sandbox


# --- 1. File Search Edge Cases ---

def test_file_search_empty_sandbox(isolated_engine):
    """Searching in an empty sandbox returns empty data list."""
    engine, _ = isolated_engine
    res = engine.file_search("*")
    assert res.success is True
    assert res.data == []
    assert "No files found" in (res.output or "")


def test_file_search_max_results_limit(isolated_engine):
    """Verify max_results limits number of returned files."""
    engine, sandbox = isolated_engine
    for i in range(10):
        (sandbox / f"file_{i}.txt").write_text(f"content {i}")

    res = engine.file_search("*.txt", max_results=3)
    assert res.success is True
    assert len(res.data) == 3


def test_file_search_ignores_trash_quarantine(isolated_engine):
    """Files inside .agentos_trash must not appear in regular search results."""
    engine, sandbox = isolated_engine
    (sandbox / "legit.txt").write_text("legit")
    # Simulate a file inside trash
    trash_file = engine.trash_dir / "quarantined.txt"
    trash_file.write_text("deleted content")

    res = engine.file_search("*")
    assert res.success is True
    assert "legit.txt" in res.data
    assert not any(".agentos_trash" in p for p in res.data)


def test_file_search_fuzzy_directory_resolution(isolated_engine):
    """Typo in subdirectory name falls back to close match or reports available dirs."""
    engine, sandbox = isolated_engine
    assets_dir = sandbox / "assets_folder"
    assets_dir.mkdir()
    (assets_dir / "sample.png").write_text("data")

    # Slight typo: assets_foldr -> assets_folder
    res = engine.file_search("*", relative_to="assets_foldr")
    assert res.success is True
    assert any("sample.png" in p for p in res.data)


# --- 2. File Read Edge Cases ---

def test_file_read_empty_file(isolated_engine):
    """Reading a zero-byte file succeeds with empty string output."""
    engine, sandbox = isolated_engine
    empty_file = sandbox / "zero.txt"
    empty_file.write_text("")

    res = engine.file_read("zero.txt")
    assert res.success is True
    assert res.output == ""
    assert res.data["bytes_read"] == 0
    assert res.data["total_size"] == 0
    assert res.data["truncated"] is False


def test_file_read_unicode_and_emojis(isolated_engine):
    """Reading Unicode, accented characters, and emojis."""
    engine, sandbox = isolated_engine
    unicode_content = "🚀 Hello World! Ça va? 100€ ñoño"
    (sandbox / "unicode.txt").write_text(unicode_content, encoding="utf-8")

    res = engine.file_read("unicode.txt")
    assert res.success is True
    assert res.output == unicode_content


def test_file_read_truncation_with_max_bytes(isolated_engine):
    """Verify max_bytes cap truncates file reading and sets truncated=True."""
    engine, sandbox = isolated_engine
    long_content = "A" * 500
    (sandbox / "long.txt").write_text(long_content)

    res = engine.file_read("long.txt", max_bytes=50)
    assert res.success is True
    assert len(res.output) == 50
    assert res.data["truncated"] is True
    assert res.data["total_size"] == 500


def test_file_read_nonexistent_fails(isolated_engine):
    """Reading non-existent file returns failure result."""
    engine, _ = isolated_engine
    res = engine.file_read("ghost_file.txt")
    assert res.success is False
    assert "File not found" in (res.error or "")


def test_file_read_directory_fails(isolated_engine):
    """Attempting to read a directory as a file returns failure result."""
    engine, sandbox = isolated_engine
    folder = sandbox / "some_folder"
    folder.mkdir()

    res = engine.file_read("some_folder")
    assert res.success is False
    assert "Target path is a directory" in (res.error or "")


def test_file_read_path_traversal_fails(isolated_engine):
    """Reading outside sandbox returns PathSecurityViolation error."""
    engine, _ = isolated_engine
    res = engine.file_read("../../secret.txt")
    assert res.success is False
    assert "Path traversal detected" in (res.error or "")


# --- 3. File Write Edge Cases ---

def test_file_write_creates_deep_directories(isolated_engine):
    """Writing to deep uncreated directories automatically creates parents."""
    engine, sandbox = isolated_engine
    deep_path = "nested/level1/level2/level3/data.txt"

    res = engine.file_write(deep_path, "deep content")
    assert res.success is True
    assert (sandbox / deep_path).exists()
    assert (sandbox / deep_path).read_text() == "deep content"


def test_file_write_append_mode(isolated_engine):
    """Writing in append mode adds to existing contents."""
    engine, sandbox = isolated_engine
    engine.file_write("append.txt", "Part 1; ")
    res = engine.file_write("append.txt", "Part 2", mode="a")

    assert res.success is True
    assert (sandbox / "append.txt").read_text() == "Part 1; Part 2"


def test_file_write_large_content(isolated_engine):
    """Writing 100,000 characters."""
    engine, sandbox = isolated_engine
    large_payload = "X" * 100_000

    res = engine.file_write("large.txt", large_payload)
    assert res.success is True
    assert res.data["bytes_written"] == 100_000
    assert (sandbox / "large.txt").stat().st_size == 100_000


def test_file_write_path_traversal_blocked(isolated_engine):
    """Writing outside sandbox is rejected."""
    engine, _ = isolated_engine
    res = engine.file_write("../escape.txt", "exploit")
    assert res.success is False
    assert "Path traversal detected" in (res.error or "")


# --- 4. File Move Edge Cases ---

def test_file_move_across_directories(isolated_engine):
    """Moving a file into a newly created target directory."""
    engine, sandbox = isolated_engine
    engine.file_write("orig.txt", "moving file")

    res = engine.file_move("orig.txt", "new_folder/target.txt")
    assert res.success is True
    assert not (sandbox / "orig.txt").exists()
    assert (sandbox / "new_folder" / "target.txt").read_text() == "moving file"


def test_file_move_nonexistent_source_fails(isolated_engine):
    """Moving non-existent source file returns failure."""
    engine, _ = isolated_engine
    res = engine.file_move("nonexistent.txt", "dest.txt")
    assert res.success is False
    assert "Source path not found" in (res.error or "")


def test_file_move_traversal_source_or_dest_blocked(isolated_engine):
    """Path traversal in move source or target must be blocked."""
    engine, sandbox = isolated_engine
    (sandbox / "valid.txt").write_text("data")

    res1 = engine.file_move("../secret.txt", "valid.txt")
    assert res1.success is False
    assert "Path traversal detected" in (res1.error or "")

    res2 = engine.file_move("valid.txt", "../escaped.txt")
    assert res2.success is False
    assert "Path traversal detected" in (res2.error or "")


# --- 5. File Delete & Quarantine Edge Cases ---

def test_file_delete_quarantines_with_metadata(isolated_engine):
    """File deletion defaults to moving into .agentos_trash with metadata JSON."""
    engine, sandbox = isolated_engine
    engine.file_write("delete_me.txt", "goodbye")

    res = engine.file_delete("delete_me.txt", quarantine=True)
    assert res.success is True
    assert not (sandbox / "delete_me.txt").exists()

    trash_name = res.data["quarantined_target"]
    assert (engine.trash_dir / trash_name).exists()
    meta_path = engine.trash_dir / f"{trash_name}.meta.json"
    assert meta_path.exists()

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["original_relative_path"] == "delete_me.txt"


def test_file_delete_permanent(isolated_engine):
    """Permanent delete unlinks file immediately without trash."""
    engine, sandbox = isolated_engine
    engine.file_write("perm.txt", "forever gone")

    res = engine.file_delete("perm.txt", quarantine=False)
    assert res.success is True
    assert not (sandbox / "perm.txt").exists()
    assert res.data["permanent"] is True


def test_file_delete_nonexistent_fails(isolated_engine):
    """Deleting non-existent file returns failure."""
    engine, _ = isolated_engine
    res = engine.file_delete("missing.txt")
    assert res.success is False
    assert "Target path not found" in (res.error or "")


# --- 6. System Info Edge Cases ---

def test_get_sys_info_metrics(isolated_engine):
    """Verify sys_info returns required OS and hardware metrics."""
    engine, sandbox = isolated_engine
    res = engine.get_sys_info()
    assert res.success is True
    assert "os" in res.data
    assert "cpu_count_logical" in res.data
    assert "memory_total_mb" in res.data
    assert "sandbox_root" in res.data
    assert res.data["sandbox_root"] == str(sandbox.resolve())
