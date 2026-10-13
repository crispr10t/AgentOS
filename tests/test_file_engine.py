"""Tests for kernel/file_engine.py: Sandboxed and Transactional File Engine."""

import json
from pathlib import Path
import pytest

from kernel.file_engine import FileEngine
from security.sandbox import PathSecurityViolation


@pytest.fixture
def file_engine(tmp_path: Path) -> FileEngine:
    """Fixture providing a FileEngine instance bound to a test sandbox."""
    sandbox = tmp_path / "engine_sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    return FileEngine(sandbox_root=sandbox)


def test_file_write_and_read(file_engine: FileEngine):
    """Verify writing a new file with directory creation and reading its contents."""
    write_res = file_engine.file_write(
        file_path="src/utils/hello.txt",
        content="Hello AgentOS Kernel!",
    )
    assert write_res.success is True
    assert write_res.exit_code == 0
    assert "Wrote" in (write_res.output or "")

    read_res = file_engine.file_read("src/utils/hello.txt")
    assert read_res.success is True
    assert read_res.output == "Hello AgentOS Kernel!"
    assert read_res.data["bytes_read"] == len("Hello AgentOS Kernel!")
    assert read_res.data["truncated"] is False


def test_file_read_nonexistent(file_engine: FileEngine):
    """Verify reading a non-existent file returns failure result."""
    res = file_engine.file_read("nonexistent.txt")
    assert res.success is False
    assert "File not found" in (res.error or "")


def test_file_read_byte_limit_truncation(file_engine: FileEngine):
    """Verify that file_read respects max_bytes parameter."""
    file_engine.file_write("large.txt", "A" * 1000)
    res = file_engine.file_read("large.txt", max_bytes=50)
    assert res.success is True
    assert len(res.output or "") == 50
    assert res.data["truncated"] is True
    assert res.data["total_size"] == 1000


def test_file_search(file_engine: FileEngine):
    """Verify search matching glob pattern and excluding trash."""
    file_engine.file_write("app.py", "print(1)")
    file_engine.file_write("module/helper.py", "print(2)")
    file_engine.file_write("notes.txt", "some notes")

    search_res = file_engine.file_search(pattern="*.py")
    assert search_res.success is True
    assert "app.py" in search_res.data
    assert "module/helper.py" in search_res.data
    assert "notes.txt" not in search_res.data


def test_file_move(file_engine: FileEngine):
    """Verify file moving/renaming within sandbox."""
    file_engine.file_write("initial.txt", "data to move")
    move_res = file_engine.file_move("initial.txt", "archived/final.txt")

    assert move_res.success is True
    assert file_engine.file_read("archived/final.txt").output == "data to move"
    assert file_engine.file_read("initial.txt").success is False


def test_file_delete_quarantine(file_engine: FileEngine):
    """Verify that delete defaults to quarantining into .agentos_trash with metadata."""
    file_engine.file_write("to_delete.txt", "important draft")
    del_res = file_engine.file_delete("to_delete.txt", quarantine=True)

    assert del_res.success is True
    assert "Quarantined" in (del_res.output or "")
    assert del_res.data["original_relative_path"] == "to_delete.txt"

    # Original path should no longer exist
    assert not (file_engine.sandbox_root / "to_delete.txt").exists()

    # Trash directory should contain quarantined file and meta json
    trash_items = list(file_engine.trash_dir.glob("*.meta.json"))
    assert len(trash_items) == 1
    with open(trash_items[0], "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["original_relative_path"] == "to_delete.txt"


def test_file_delete_permanent(file_engine: FileEngine):
    """Verify permanent file deletion when quarantine=False."""
    file_engine.file_write("permanent.txt", "temp data")
    del_res = file_engine.file_delete("permanent.txt", quarantine=False)
    assert del_res.success is True
    assert "Permanently deleted" in (del_res.output or "")
    assert not (file_engine.sandbox_root / "permanent.txt").exists()


def test_sandbox_path_traversal_rejection(file_engine: FileEngine):
    """Verify that attempts to write or read outside sandbox are rejected."""
    read_res = file_engine.file_read("../../escaped.txt")
    assert read_res.success is False
    assert "Path traversal detected" in (read_res.error or "")

    write_res = file_engine.file_write("../out.txt", "bad content")
    assert write_res.success is False
    assert "Path traversal detected" in (write_res.error or "")


def test_get_sys_info(file_engine: FileEngine):
    """Verify hardware telemetry and environment collection."""
    info_res = file_engine.get_sys_info()
    assert info_res.success is True
    assert "OS:" in (info_res.output or "")
    assert "CPU:" in (info_res.output or "")
    assert "RAM:" in (info_res.output or "")
    assert "cpu_count_logical" in info_res.data
    assert "memory_total_mb" in info_res.data
    assert "sandbox_root" in info_res.data


def test_file_search_fuzzy_typo_directory(file_engine: FileEngine):
    """Verify fuzzy resolution of directory names with slight typos (e.g. demo_assests -> demo_assets)."""
    file_engine.file_write("demo_assets/worker.py", "print('worker')")
    file_engine.file_write("demo_assets/notes.txt", "notes")

    # Pass typo "demo_assests"
    res = file_engine.file_search(pattern="*.py", relative_to="demo_assests")
    assert res.success is True
    assert any("worker.py" in match for match in res.data)


def test_file_search_nonexistent_directory_graceful(file_engine: FileEngine):
    """Verify non-existent directory returns non-crashing informative result."""
    res = file_engine.file_search(pattern="*", relative_to="completely_nonexistent_folder")
    assert res.success is True
    assert res.data == []
    assert "No directory named" in (res.output or "")


def test_file_write_unescapes_literal_newlines(file_engine: FileEngine):
    """Verify that file_write unescapes literal \n sequences when content has no real newlines."""
    raw_content = "import os\\nimport sys\\nprint('hello')\\n"
    res = file_engine.file_write("unescaped.py", raw_content)
    assert res.success is True

    read_res = file_engine.file_read("unescaped.py")
    assert read_res.success is True
    assert read_res.output == "import os\nimport sys\nprint('hello')\n"

