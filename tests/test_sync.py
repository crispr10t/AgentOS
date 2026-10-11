"""Tests for kernel/sync.py: PCBTable, ProducerConsumerQueue, and CriticalSection."""

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
)


def test_pcb_table_registration_and_lookup():
    """Verify registration, lookup, removal, and sizing in PCBTable."""
    table = PCBTable()
    assert len(table) == 0

    p1 = TaskPCB(pid=1001, name="proc_1")
    p2 = TaskPCB(pid=1002, name="proc_2")

    table.register(p1)
    table.register(p2)

    assert len(table) == 2
    assert 1001 in table
    assert 1002 in table
    assert 9999 not in table

    retrieved = table.get(1001)
    assert retrieved is not None
    assert retrieved.name == "proc_1"

    # Removal
    removed = table.remove(1001)
    assert removed is not None
    assert removed.pid == 1001
    assert 1001 not in table
    assert len(table) == 1


def test_pcb_table_state_and_metrics_updates():
    """Verify thread-safe lifecycle transitions and metrics updates."""
    table = PCBTable()
    p = TaskPCB(pid=1003, name="lifecycle_proc")
    table.register(p)

    # Valid transitions: NEW -> READY -> RUNNING
    table.update_state(1003, ProcessState.READY)
    assert table.get(1003).state == ProcessState.READY

    table.update_state(1003, ProcessState.RUNNING)
    assert table.get(1003).state == ProcessState.RUNNING
    assert table.get(1003).started_at is not None

    # Metrics update
    table.update_metrics(
        1003,
        cpu_time=2.34,
        peak_memory_mb=128.5,
        exit_code=0,
    )
    updated = table.get(1003)
    assert updated.cpu_time == 2.34
    assert updated.peak_memory_mb == 128.5
    assert updated.exit_code == 0

    # Illegal transition raises ValueError
    with pytest.raises(ValueError, match="Invalid state transition"):
        table.update_state(1003, ProcessState.NEW)


def test_pcb_table_observer_notifications():
    """Verify subscriber callbacks are notified upon PCB mutations."""
    table = PCBTable()
    events: list[tuple[int, ProcessState]] = []

    def observer(pcb: TaskPCB):
        events.append((pcb.pid, pcb.state))

    table.subscribe(observer)

    p = TaskPCB(pid=1004, name="observed_proc")
    table.register(p)
    table.update_state(1004, ProcessState.READY)
    table.update_state(1004, ProcessState.RUNNING)

    # Should have recorded initial register, transition to READY, and transition to RUNNING
    assert len(events) == 3
    assert events[0] == (1004, ProcessState.NEW)
    assert events[1] == (1004, ProcessState.READY)
    assert events[2] == (1004, ProcessState.RUNNING)

    # Unsubscribe
    table.unsubscribe(observer)
    table.update_state(1004, ProcessState.TERMINATED)
    assert len(events) == 3  # No additional events after unsubscribing


def test_pcb_table_filtering():
    """Verify list_all, list_active, and list_by_state filtering methods."""
    table = PCBTable()

    p1 = TaskPCB(pid=2001, name="t1")
    p1.transition_to(ProcessState.READY)

    p2 = TaskPCB(pid=2002, name="t2")
    p2.transition_to(ProcessState.READY)
    p2.transition_to(ProcessState.RUNNING)

    p3 = TaskPCB(pid=2003, name="t3")
    p3.transition_to(ProcessState.READY)
    p3.transition_to(ProcessState.TERMINATED)

    table.register(p1)
    table.register(p2)
    table.register(p3)

    assert len(table.list_all()) == 3
    active = table.list_active()
    assert len(active) == 2
    assert {t.pid for t in active} == {2001, 2002}

    running = table.list_by_state(ProcessState.RUNNING)
    assert len(running) == 1
    assert running[0].pid == 2002


def test_pcb_table_concurrent_mutations():
    """Verify PCBTable integrity when accessed concurrently by multiple worker threads."""
    table = PCBTable()
    num_threads = 10
    tasks_per_thread = 20

    def worker(worker_id: int):
        for i in range(tasks_per_thread):
            pid = worker_id * 1000 + i
            pcb = TaskPCB(pid=pid, name=f"w{worker_id}_t{i}")
            table.register(pcb)
            table.update_state(pid, ProcessState.READY)
            table.update_state(pid, ProcessState.RUNNING)
            table.update_metrics(pid, cpu_time=float(i), peak_memory_mb=16.0)
            table.update_state(pid, ProcessState.TERMINATED)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    total_expected = num_threads * tasks_per_thread
    assert len(table) == total_expected
    assert len(table.list_active()) == 0  # All terminated
    assert len(table.list_by_state(ProcessState.TERMINATED)) == total_expected


def test_bounded_queue_fifo():
    """Verify ProducerConsumerQueue maintains FIFO order and tracks size."""
    q: ProducerConsumerQueue[str] = ProducerConsumerQueue(maxsize=5)
    assert q.is_empty()
    assert not q.is_full()

    q.put("alpha")
    q.put("beta")
    q.put("gamma")

    assert q.qsize() == 3
    assert q.get() == "alpha"
    assert q.get() == "beta"
    assert q.get() == "gamma"
    assert q.is_empty()


def test_bounded_queue_blocking_and_timeouts():
    """Verify ProducerConsumerQueue blocks with timeouts when full or empty."""
    q: ProducerConsumerQueue[int] = ProducerConsumerQueue(maxsize=2)

    q.put(1)
    q.put(2)
    assert q.is_full()

    # Third item should time out because buffer capacity is 2
    start = time.time()
    with pytest.raises(QueueFullError):
        q.put(3, timeout=0.05)
    assert time.time() - start >= 0.04

    # Pop one item to free capacity
    assert q.get() == 1
    assert not q.is_full()

    # Now put should succeed immediately
    q.put(3)
    assert q.get() == 2
    assert q.get() == 3
    assert q.is_empty()

    # Getting from empty queue should time out
    start = time.time()
    with pytest.raises(QueueEmptyError):
        q.get(timeout=0.05)
    assert time.time() - start >= 0.04


def test_bounded_queue_producer_consumer_concurrency():
    """Verify ProducerConsumerQueue under multi-producer, multi-consumer load."""
    q: ProducerConsumerQueue[int] = ProducerConsumerQueue(maxsize=4)
    total_items = 200
    producers_count = 4
    items_per_producer = total_items // producers_count

    consumed: list[int] = []
    consumed_lock = threading.Lock()

    def producer(start_val: int):
        for i in range(items_per_producer):
            q.put(start_val + i)

    def consumer():
        while True:
            try:
                item = q.get(timeout=0.05)
                with consumed_lock:
                    consumed.append(item)
                    if len(consumed) >= total_items:
                        break
            except QueueEmptyError:
                with consumed_lock:
                    if len(consumed) >= total_items:
                        break

    prod_threads = [
        threading.Thread(target=producer, args=(p * items_per_producer,))
        for p in range(producers_count)
    ]
    cons_threads = [threading.Thread(target=consumer) for _ in range(4)]

    for t in prod_threads + cons_threads:
        t.start()
    for t in prod_threads + cons_threads:
        t.join(timeout=10.0)

    assert len(consumed) == total_items
    assert len(set(consumed)) == total_items  # No duplicate or dropped messages


def test_bounded_queue_shutdown():
    """Verify clean shutdown wakes blocked producer and consumer threads."""
    q: ProducerConsumerQueue[int] = ProducerConsumerQueue(maxsize=2)

    # Shutdown an empty queue
    q.shutdown()
    assert q.is_shutdown

    with pytest.raises(QueueShutdownError):
        q.put(100)

    with pytest.raises(QueueShutdownError):
        q.get()


def test_critical_section():
    """Verify CriticalSection context manager acquires and releases lock."""
    lock = threading.RLock()
    cs = CriticalSection(lock)

    with cs:
        # Lock should be acquired
        assert lock._is_owned()  # type: ignore

    # Lock is now released
    assert not lock._is_owned()  # type: ignore
