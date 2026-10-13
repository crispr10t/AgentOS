"""Comprehensive edge-case tests for kernel/sync.py: ProducerConsumerQueue, PCBTable, and CriticalSection."""

import threading
import time
import pytest

from kernel.pcb import ProcessState, TaskPCB
from kernel.sync import (
    CriticalSection,
    PCBTable,
    ProducerConsumerQueue,
    QueueEmptyError,
    QueueFullError,
    QueueShutdownError,
    SyncError,
)


# --- 1. ProducerConsumerQueue Edge Cases ---

def test_queue_zero_capacity_clamped_or_min():
    """Verify queue with capacity 1 works as rendezvous buffer."""
    q: ProducerConsumerQueue[str] = ProducerConsumerQueue(maxsize=1)
    assert q.maxsize == 1
    assert q.is_empty()

    q.put("item1", timeout=0.1)
    assert q.qsize() == 1
    assert q.is_full()

    # Second put on full capacity=1 queue must raise QueueFullError
    with pytest.raises(QueueFullError):
        q.put("item2", timeout=0.01)

    assert q.get(timeout=0.01) == "item1"
    assert q.is_empty()


def test_queue_immediate_timeout_zero():
    """Verify immediate non-blocking behavior with timeout=0.0."""
    q: ProducerConsumerQueue[int] = ProducerConsumerQueue(maxsize=2)
    with pytest.raises(QueueEmptyError):
        q.get(timeout=0.0)

    q.put(42, timeout=0.0)
    q.put(43, timeout=0.0)

    with pytest.raises(QueueFullError):
        q.put(44, timeout=0.0)

    assert q.get(timeout=0.0) == 42
    assert q.get(timeout=0.0) == 43


def test_queue_negative_timeout_treated_as_zero():
    """Verify negative timeout behaves like non-blocking zero timeout without hanging."""
    q: ProducerConsumerQueue[str] = ProducerConsumerQueue(maxsize=1)
    with pytest.raises(QueueEmptyError):
        q.get(timeout=-1.0)


def test_queue_shutdown_drains_then_raises():
    """Verify queue shutdown allows extracting remaining items before raising QueueShutdownError."""
    q: ProducerConsumerQueue[str] = ProducerConsumerQueue(maxsize=5)
    q.put("alpha")
    q.put("beta")

    q.shutdown()

    # Remaining items can still be drained
    assert q.get(timeout=0.05) == "alpha"
    assert q.get(timeout=0.05) == "beta"

    # Once exhausted, subsequent get must raise QueueShutdownError
    with pytest.raises(QueueShutdownError):
        q.get(timeout=0.05)

    # Any put after shutdown must raise QueueShutdownError immediately
    with pytest.raises(QueueShutdownError):
        q.put("gamma", timeout=0.05)


def test_queue_shutdown_idempotent():
    """Calling shutdown repeatedly must be completely safe and idempotent."""
    q: ProducerConsumerQueue[int] = ProducerConsumerQueue(maxsize=3)
    q.shutdown()
    q.shutdown()
    q.shutdown()
    assert q.is_shutdown


def test_queue_types_variety():
    """Verify ProducerConsumerQueue handles dicts, TaskPCBs, and None values safely."""
    q: ProducerConsumerQueue[object] = ProducerConsumerQueue(maxsize=5)
    pcb = TaskPCB(pid=1, name="t1")
    q.put(pcb)
    q.put({"key": "value"})
    q.put(None)

    assert q.get() == pcb
    assert q.get() == {"key": "value"}
    assert q.get() is None


# --- 2. PCBTable Edge Cases ---

def test_pcb_table_get_nonexistent_pid():
    """Verify lookup for a non-existent PID returns None."""
    table = PCBTable()
    assert table.get(9999) is None


def test_pcb_table_remove_nonexistent_pid():
    """Verify removing a non-existent PID returns None without raising an exception."""
    table = PCBTable()
    assert table.remove(9999) is None


def test_pcb_table_register_duplicate_pid_overwrites():
    """Registering a task with an existing PID replaces or updates the record cleanly."""
    table = PCBTable()
    t1 = TaskPCB(pid=500, name="original", priority=1)
    t2 = TaskPCB(pid=500, name="replacement", priority=10)

    table.register(t1)
    assert table.get(500).name == "original"

    table.register(t2)
    assert table.get(500).name == "replacement"
    assert len(table) == 1


@pytest.mark.parametrize("state", list(ProcessState))
def test_pcb_table_list_by_state(state: ProcessState):
    """Verify list_by_state accurately filters tasks for each of the 5 process states."""
    table = PCBTable()
    for s in ProcessState:
        table.register(TaskPCB(pid=100 + list(ProcessState).index(s), name=f"t_{s.value}", state=s))

    matches = table.list_by_state(state)
    assert len(matches) == 1
    assert matches[0].state == state


def test_pcb_table_update_state_nonexistent_pid():
    """Updating state for a non-existent PID should be a safe no-op or return None."""
    table = PCBTable()
    result = table.update_state(9999, ProcessState.RUNNING)
    assert result is None


def test_pcb_table_update_metrics_nonexistent_pid():
    """Updating metrics for a non-existent PID should be a safe no-op or return None."""
    table = PCBTable()
    result = table.update_metrics(9999, cpu_time=1.0)
    assert result is None


def test_pcb_table_observer_unsubscribe_idempotent():
    """Unsubscribing a callback not in listeners should be a safe no-op."""
    table = PCBTable()
    dummy_cb = lambda pcb: None
    table.unsubscribe(dummy_cb)  # Never subscribed, should not raise


def test_pcb_table_observer_notified_on_register_and_updates():
    """Verify subscriber callbacks are triggered on registration and state updates."""
    table = PCBTable()
    notifications: list[tuple[int, ProcessState]] = []

    def observer(pcb: TaskPCB):
        notifications.append((pcb.pid, pcb.state))

    table.subscribe(observer)

    t = TaskPCB(pid=700, name="observed_task")
    table.register(t)
    table.update_state(700, ProcessState.READY)
    table.update_state(700, ProcessState.RUNNING)

    assert len(notifications) == 3
    assert notifications[0] == (700, ProcessState.NEW)
    assert notifications[1] == (700, ProcessState.READY)
    assert notifications[2] == (700, ProcessState.RUNNING)

    table.unsubscribe(observer)
    table.update_state(700, ProcessState.TERMINATED)
    assert len(notifications) == 3  # No further notification after unsubscribe


def test_pcb_table_clear():
    """Verify clearing the table removes all tasks and empties size."""
    table = PCBTable()
    table.register(TaskPCB(pid=1, name="t1"))
    table.register(TaskPCB(pid=2, name="t2"))
    assert len(table) == 2

    table.clear()
    assert len(table) == 0
    assert table.list_all() == []


# --- 3. CriticalSection Edge Cases ---

def test_critical_section_reentrant_lock():
    """Verify CriticalSection supports nested re-entrant locking on the same thread."""
    lock = threading.RLock()
    with CriticalSection(lock):
        with CriticalSection(lock):
            assert lock._is_owned()  # Lock is held


def test_critical_section_releases_on_exception():
    """Verify CriticalSection reliably releases lock when an exception is raised within the block."""
    cs = CriticalSection()
    lock = cs.lock

    with pytest.raises(ZeroDivisionError):
        with cs:
            _ = 1 / 0

    # Must be able to acquire lock immediately without blocking
    acquired = lock.acquire(blocking=False)
    assert acquired is True
    lock.release()
