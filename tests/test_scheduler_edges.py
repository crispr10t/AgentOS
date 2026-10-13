"""Comprehensive edge-case tests for kernel/scheduler.py: TaskScheduler policies, tie-breakers, and metrics."""

import threading
import time
import pytest

from kernel.pcb import ProcessState, TaskPCB
from kernel.scheduler import SchedulingPolicy, TaskScheduler


# --- 1. Policy Normalization & Validation ---

@pytest.mark.parametrize("policy_input, expected_enum", [
    ("fcfs", SchedulingPolicy.FCFS),
    ("FCFS", SchedulingPolicy.FCFS),
    (" fcfs ", SchedulingPolicy.FCFS),
    ("priority", SchedulingPolicy.PRIORITY),
    ("PRIORITY", SchedulingPolicy.PRIORITY),
    ("sjf", SchedulingPolicy.SJF),
    ("SJF", SchedulingPolicy.SJF),
    (SchedulingPolicy.FCFS, SchedulingPolicy.FCFS),
    (SchedulingPolicy.PRIORITY, SchedulingPolicy.PRIORITY),
    (SchedulingPolicy.SJF, SchedulingPolicy.SJF),
])
def test_scheduler_normalize_policy_success(policy_input, expected_enum):
    """Verify policy strings and enums are correctly normalized regardless of case or whitespace."""
    scheduler = TaskScheduler(policy=policy_input)
    assert scheduler.policy == expected_enum


@pytest.mark.parametrize("invalid_policy", [
    "round_robin",
    "fifo_invalid",
    "",
    "   ",
    123,
    None,
    [],
    {},
])
def test_scheduler_normalize_policy_failure(invalid_policy):
    """Verify invalid policy names raise ValueError or TypeError."""
    with pytest.raises((ValueError, TypeError)):
        TaskScheduler(policy=invalid_policy)  # type: ignore


# --- 2. Deterministic Tie-Breaking (Monotonic Arrival Sequence) ---

def test_fcfs_fifo_order_preserved():
    """Verify FCFS strictly dispatches tasks in arrival sequence order."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    tasks = [TaskPCB(pid=i, name=f"task_{i}") for i in range(10)]
    for t in tasks:
        scheduler.enqueue(t)

    assert len(scheduler) == 10
    dispatched = [scheduler.next_task() for _ in range(10)]
    assert [t.pid for t in dispatched] == list(range(10))
    assert scheduler.is_empty()


def test_priority_tie_breaking_uses_arrival_order():
    """Tasks with equal priority must be dispatched in FIFO arrival order."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.PRIORITY)
    # Tasks with equal priority 5
    t1 = TaskPCB(pid=201, name="first_p5", priority=5)
    t2 = TaskPCB(pid=202, name="second_p5", priority=5)
    t3 = TaskPCB(pid=203, name="third_p5", priority=5)
    # Task with higher priority 10
    t_high = TaskPCB(pid=204, name="high_p10", priority=10)

    scheduler.enqueue(t1)
    scheduler.enqueue(t2)
    scheduler.enqueue(t_high)
    scheduler.enqueue(t3)

    assert scheduler.next_task().pid == 204  # Highest priority first
    assert scheduler.next_task().pid == 201  # Then FIFO amongst priority 5
    assert scheduler.next_task().pid == 202
    assert scheduler.next_task().pid == 203


def test_priority_reversed_mode():
    """Verify higher_priority_first=False dispatches lower numerical priority values first."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.PRIORITY, higher_priority_first=False)
    t_low = TaskPCB(pid=301, name="nice_0", priority=0)
    t_mid = TaskPCB(pid=302, name="nice_5", priority=5)
    t_high = TaskPCB(pid=303, name="nice_10", priority=10)

    scheduler.enqueue(t_mid)
    scheduler.enqueue(t_high)
    scheduler.enqueue(t_low)

    assert scheduler.next_task().pid == 301
    assert scheduler.next_task().pid == 302
    assert scheduler.next_task().pid == 303


def test_sjf_tie_breaking_uses_arrival_order():
    """Tasks with equal estimated duration must be dispatched in FIFO arrival order."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.SJF)
    t1 = TaskPCB(pid=401, name="sjf_1", estimated_duration=2.0)
    t2 = TaskPCB(pid=402, name="sjf_2", estimated_duration=1.0)
    t3 = TaskPCB(pid=403, name="sjf_3", estimated_duration=2.0)
    t4 = TaskPCB(pid=404, name="sjf_4", estimated_duration=0.5)

    scheduler.enqueue(t1)
    scheduler.enqueue(t2)
    scheduler.enqueue(t3)
    scheduler.enqueue(t4)

    # Expected order: 404 (0.5), 402 (1.0), 401 (2.0 first), 403 (2.0 second)
    order = [scheduler.next_task().pid for _ in range(4)]
    assert order == [404, 402, 401, 403]


@pytest.mark.parametrize("zero_or_micro_duration", [0.0, 0.00001, 1e-6])
def test_sjf_zero_and_microsecond_duration_handling(zero_or_micro_duration: float):
    """Verify SJF handles zero or sub-millisecond durations correctly."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.SJF)
    t_tiny = TaskPCB(pid=501, name="micro_task", estimated_duration=zero_or_micro_duration)
    t_normal = TaskPCB(pid=502, name="normal_task", estimated_duration=1.0)

    scheduler.enqueue(t_normal)
    scheduler.enqueue(t_tiny)

    assert scheduler.next_task().pid == 501
    assert scheduler.next_task().pid == 502


# --- 3. Dynamic Policy Switching ---

def test_dynamic_policy_switch_multiple_times():
    """Verify switching policy repeatedly dynamically sorts existing queued tasks."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    # Add tasks: (pid, priority, duration)
    # Task A: arrival 1, priority 1, duration 10.0
    # Task B: arrival 2, priority 10, duration 1.0
    # Task C: arrival 3, priority 5, duration 5.0
    tA = TaskPCB(pid=1, name="A", priority=1, estimated_duration=10.0)
    tB = TaskPCB(pid=2, name="B", priority=10, estimated_duration=1.0)
    tC = TaskPCB(pid=3, name="C", priority=5, estimated_duration=5.0)

    for t in [tA, tB, tC]:
        scheduler.enqueue(t)

    # In FCFS: A, B, C
    assert [t.pid for t in scheduler.get_queue()] == [1, 2, 3]

    # Switch to PRIORITY: B (10), C (5), A (1)
    scheduler.set_policy(SchedulingPolicy.PRIORITY)
    assert [t.pid for t in scheduler.get_queue()] == [2, 3, 1]

    # Switch to SJF: B (1.0), C (5.0), A (10.0)
    scheduler.set_policy(SchedulingPolicy.SJF)
    assert [t.pid for t in scheduler.get_queue()] == [2, 3, 1]

    # Switch back to FCFS: order returns to arrival sequence A, B, C
    scheduler.set_policy(SchedulingPolicy.FCFS)
    assert [t.pid for t in scheduler.get_queue()] == [1, 2, 3]


def test_set_policy_to_same_policy_is_noop():
    """Setting the same policy should not alter queue order."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    t1 = TaskPCB(pid=1, name="t1")
    t2 = TaskPCB(pid=2, name="t2")
    scheduler.enqueue(t1)
    scheduler.enqueue(t2)

    scheduler.set_policy(SchedulingPolicy.FCFS)
    assert [t.pid for t in scheduler.get_queue()] == [1, 2]


# --- 4. Queue Operations: Peek, Remove, Clear, Empty ---

def test_scheduler_empty_queue_operations():
    """Verify operations on an empty scheduler queue return safe defaults."""
    scheduler = TaskScheduler()
    assert scheduler.is_empty()
    assert len(scheduler) == 0
    assert scheduler.queue_size() == 0
    assert scheduler.next_task() is None
    assert scheduler.peek() is None
    assert scheduler.remove(999) is None
    assert scheduler.get_queue() == []


def test_scheduler_peek_does_not_mutate():
    """Verify peek inspects the head task repeatedly without modifying the queue."""
    scheduler = TaskScheduler()
    t1 = TaskPCB(pid=10, name="peek_me")
    scheduler.enqueue(t1)

    assert scheduler.peek().pid == 10
    assert scheduler.peek().pid == 10
    assert len(scheduler) == 1
    assert scheduler.next_task().pid == 10
    assert scheduler.is_empty()


@pytest.mark.parametrize("target_pid, expected_remaining", [
    (1, [2, 3]),  # Remove head
    (2, [1, 3]),  # Remove middle
    (3, [1, 2]),  # Remove tail
    (99, [1, 2, 3]),  # Non-existent
])
def test_scheduler_remove_by_pid(target_pid: int, expected_remaining: list[int]):
    """Verify removing head, middle, tail, or nonexistent PID."""
    scheduler = TaskScheduler()
    for pid in [1, 2, 3]:
        scheduler.enqueue(TaskPCB(pid=pid, name=f"t_{pid}"))

    removed = scheduler.remove(target_pid)
    if target_pid in [1, 2, 3]:
        assert removed is not None
        assert removed.pid == target_pid
    else:
        assert removed is None

    assert [t.pid for t in scheduler.get_queue()] == expected_remaining


def test_scheduler_clear():
    """Verify clear resets both queue and execution history."""
    scheduler = TaskScheduler()
    scheduler.enqueue(TaskPCB(pid=1, name="t1"))
    t_done = TaskPCB(pid=2, name="t2")
    t_done.transition_to(ProcessState.READY)
    t_done.transition_to(ProcessState.RUNNING)
    t_done.transition_to(ProcessState.TERMINATED)
    scheduler.record_completed(t_done)

    assert scheduler.queue_size() == 1
    assert len(scheduler.get_history()) == 1

    scheduler.clear()
    assert scheduler.is_empty()
    assert len(scheduler.get_history()) == 0


# --- 5. Metrics Computation Edge Cases ---

def test_scheduler_compute_metrics_empty():
    """Verify compute_metrics with no tasks returns zeroed stats."""
    scheduler = TaskScheduler()
    metrics = scheduler.compute_metrics()
    assert metrics["total_tasks"] == 0.0
    assert metrics["avg_waiting_time"] == 0.0
    assert metrics["avg_turnaround_time"] == 0.0


def test_scheduler_compute_metrics_tasks_with_none_times():
    """Verify compute_metrics gracefully skips tasks with None waiting or turnaround time."""
    scheduler = TaskScheduler()
    t1 = TaskPCB(pid=1, name="incomplete_1")
    t2 = TaskPCB(pid=2, name="incomplete_2")

    metrics = scheduler.compute_metrics(completed_tasks=[t1, t2])
    assert metrics["total_tasks"] == 2.0
    assert metrics["avg_waiting_time"] == 0.0
    assert metrics["avg_turnaround_time"] == 0.0


def test_scheduler_compute_metrics_normal():
    """Verify accurate averages on completed tasks."""
    now = time.time()
    t1 = TaskPCB(pid=1, name="t1", created_at=now)
    t1.started_at = now + 1.0
    t1.ended_at = now + 3.0

    t2 = TaskPCB(pid=2, name="t2", created_at=now)
    t2.started_at = now + 2.0
    t2.ended_at = now + 5.0

    scheduler = TaskScheduler()
    metrics = scheduler.compute_metrics(completed_tasks=[t1, t2])

    assert metrics["total_tasks"] == 2.0
    assert pytest.approx(metrics["avg_waiting_time"], 0.01) == 1.5
    assert pytest.approx(metrics["avg_turnaround_time"], 0.01) == 4.0
    assert pytest.approx(metrics["max_waiting_time"], 0.01) == 2.0
    assert pytest.approx(metrics["max_turnaround_time"], 0.01) == 5.0


# --- 6. Concurrency Stress Test ---

def test_scheduler_high_concurrency():
    """Verify multi-threaded enqueues and dequeues maintain queue integrity."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    thread_count = 6
    tasks_per_thread = 25

    def worker_enqueue(worker_id: int):
        for i in range(tasks_per_thread):
            pid = worker_id * 1000 + i
            scheduler.enqueue(TaskPCB(pid=pid, name=f"w{worker_id}_{i}"))

    threads = [threading.Thread(target=worker_enqueue, args=(w,)) for w in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert scheduler.queue_size() == thread_count * tasks_per_thread

    # Dequeue all tasks
    dequeued_count = 0
    while not scheduler.is_empty():
        item = scheduler.next_task()
        if item is not None:
            dequeued_count += 1

    assert dequeued_count == thread_count * tasks_per_thread
    assert scheduler.is_empty()
