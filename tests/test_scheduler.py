"""Tests for kernel/scheduler.py: TaskScheduler and Scheduling Policies."""

import threading
import time
import pytest

from kernel.pcb import ProcessState, TaskPCB
from kernel.scheduler import SchedulingPolicy, TaskScheduler


def test_fcfs_dispatch_order():
    """Verify First-Come, First-Served policy dispatches tasks in arrival order (FIFO)."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)

    t1 = TaskPCB(pid=101, name="first", priority=1, estimated_duration=5.0)
    t2 = TaskPCB(pid=102, name="second", priority=10, estimated_duration=1.0)
    t3 = TaskPCB(pid=103, name="third", priority=5, estimated_duration=2.0)

    scheduler.enqueue(t1)
    scheduler.enqueue(t2)
    scheduler.enqueue(t3)

    assert scheduler.queue_size() == 3
    assert scheduler.next_task().pid == 101
    assert scheduler.next_task().pid == 102
    assert scheduler.next_task().pid == 103
    assert scheduler.next_task() is None


def test_priority_dispatch_order():
    """Verify Priority Scheduling dispatches highest-priority tasks first with FIFO tie-breaker."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.PRIORITY, higher_priority_first=True)

    t_low = TaskPCB(pid=201, name="low", priority=1)
    t_high = TaskPCB(pid=202, name="high", priority=10)
    t_med1 = TaskPCB(pid=203, name="med1", priority=5)
    t_med2 = TaskPCB(pid=204, name="med2", priority=5)

    scheduler.enqueue(t_low)
    scheduler.enqueue(t_high)
    scheduler.enqueue(t_med1)
    scheduler.enqueue(t_med2)

    # 10 first, then 5 (med1 before med2 by arrival), then 1
    assert scheduler.next_task().pid == 202
    assert scheduler.next_task().pid == 203
    assert scheduler.next_task().pid == 204
    assert scheduler.next_task().pid == 201
    assert scheduler.is_empty()


def test_sjf_dispatch_order():
    """Verify Shortest Job First policy dispatches tasks with shortest duration first."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.SJF)

    t_long = TaskPCB(pid=301, name="long_job", estimated_duration=25.0)
    t_short = TaskPCB(pid=302, name="short_job", estimated_duration=1.5)
    t_mid1 = TaskPCB(pid=303, name="mid_job1", estimated_duration=5.0)
    t_mid2 = TaskPCB(pid=304, name="mid_job2", estimated_duration=5.0)

    scheduler.enqueue(t_long)
    scheduler.enqueue(t_short)
    scheduler.enqueue(t_mid1)
    scheduler.enqueue(t_mid2)

    # Shortest (1.5), then 5.0 (mid1 before mid2), then 25.0
    assert scheduler.next_task().pid == 302
    assert scheduler.next_task().pid == 303
    assert scheduler.next_task().pid == 304
    assert scheduler.next_task().pid == 301
    assert scheduler.is_empty()


def test_dynamic_policy_switch():
    """Verify switching scheduling policy dynamically reorders the ready queue immediately."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)

    t1 = TaskPCB(pid=401, name="t1", priority=1, estimated_duration=20.0)
    t2 = TaskPCB(pid=402, name="t2", priority=9, estimated_duration=2.0)
    t3 = TaskPCB(pid=403, name="t3", priority=5, estimated_duration=8.0)

    scheduler.enqueue(t1)
    scheduler.enqueue(t2)
    scheduler.enqueue(t3)

    # In FCFS, next is t1
    assert scheduler.peek().pid == 401

    # Switch to Priority: t2 (priority 9) becomes first
    scheduler.set_policy(SchedulingPolicy.PRIORITY)
    assert scheduler.policy == SchedulingPolicy.PRIORITY
    assert scheduler.peek().pid == 402

    # Switch to SJF: t2 (duration 2.0) is still first, but t3 (8.0) comes before t1 (20.0)
    scheduler.set_policy("SJF")
    assert scheduler.policy == SchedulingPolicy.SJF
    assert scheduler.next_task().pid == 402
    assert scheduler.next_task().pid == 403
    assert scheduler.next_task().pid == 401


def test_enqueue_transitions_new_to_ready():
    """Verify that enqueuing a task in NEW state transitions it to READY."""
    scheduler = TaskScheduler()
    pcb = TaskPCB(pid=501, name="new_task")
    assert pcb.state == ProcessState.NEW

    scheduler.enqueue(pcb)
    assert pcb.state == ProcessState.READY


def test_peek_and_remove():
    """Verify peek inspects without popping, and remove cancels by PID."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
    t1 = TaskPCB(pid=601, name="t1")
    t2 = TaskPCB(pid=602, name="t2")
    t3 = TaskPCB(pid=603, name="t3")

    scheduler.enqueue(t1)
    scheduler.enqueue(t2)
    scheduler.enqueue(t3)

    assert scheduler.peek().pid == 601
    assert scheduler.queue_size() == 3

    # Remove the middle task (t2)
    removed = scheduler.remove(602)
    assert removed is not None
    assert removed.pid == 602
    assert scheduler.queue_size() == 2

    # Attempting to remove non-existent PID returns None
    assert scheduler.remove(999) is None

    # Remaining order is t1, t3
    assert scheduler.next_task().pid == 601
    assert scheduler.next_task().pid == 603
    assert scheduler.is_empty()


def test_scheduler_metrics_calculation():
    """Verify calculation of Turnaround Time and Waiting Time averages."""
    scheduler = TaskScheduler()

    now = time.time()
    t1 = TaskPCB(pid=701, name="m1", created_at=now)
    t1.started_at = now + 1.0  # Waiting time: 1.0s
    t1.ended_at = now + 4.0    # Turnaround time: 4.0s

    t2 = TaskPCB(pid=702, name="m2", created_at=now)
    t2.started_at = now + 3.0  # Waiting time: 3.0s
    t2.ended_at = now + 5.0    # Turnaround time: 5.0s

    scheduler.record_completed(t1)
    scheduler.record_completed(t2)

    metrics = scheduler.compute_metrics()
    assert metrics["total_tasks"] == 2.0
    assert metrics["avg_waiting_time"] == pytest.approx(2.0, abs=0.01)
    assert metrics["max_waiting_time"] == pytest.approx(3.0, abs=0.01)
    assert metrics["avg_turnaround_time"] == pytest.approx(4.5, abs=0.01)
    assert metrics["max_turnaround_time"] == pytest.approx(5.0, abs=0.01)


def test_sjf_vs_fcfs_benchmark_comparison():
    """Verify that SJF minimizes average waiting time compared to FCFS on a skewed workload."""
    # Classic Convoy Effect workload: one large job arriving first followed by short jobs
    tasks = [
        TaskPCB(pid=801, name="long_task", created_at=1000.0, estimated_duration=30.0),
        TaskPCB(pid=802, name="short_task1", created_at=1000.0, estimated_duration=2.0),
        TaskPCB(pid=803, name="short_task2", created_at=1000.0, estimated_duration=4.0),
        TaskPCB(pid=804, name="short_task3", created_at=1000.0, estimated_duration=1.0),
    ]

    _, fcfs_metrics = TaskScheduler.simulate_batch(tasks, policy=SchedulingPolicy.FCFS)
    _, sjf_metrics = TaskScheduler.simulate_batch(tasks, policy=SchedulingPolicy.SJF)

    # OS Theory guarantee: SJF achieves strictly lower average waiting time than FCFS
    assert sjf_metrics["avg_waiting_time"] < fcfs_metrics["avg_waiting_time"]
    assert sjf_metrics["avg_turnaround_time"] < fcfs_metrics["avg_turnaround_time"]


def test_invalid_policy_raises_error():
    """Verify that unsupported policy strings or types raise appropriate errors."""
    with pytest.raises(ValueError, match="Unknown scheduling policy"):
        TaskScheduler(policy="ROUND_ROBIN")

    scheduler = TaskScheduler()
    with pytest.raises(ValueError, match="Unknown scheduling policy"):
        scheduler.set_policy("INVALID_NAME")


def test_scheduler_concurrent_access():
    """Stress test verifying thread-safety under concurrent enqueues and dequeues."""
    scheduler = TaskScheduler(policy=SchedulingPolicy.PRIORITY)
    num_tasks = 200
    dequeued: list[int] = []
    lock = threading.Lock()

    def producer(start_id: int, count: int):
        for i in range(count):
            pid = start_id + i
            pcb = TaskPCB(pid=pid, name=f"task_{pid}", priority=i % 10)
            scheduler.enqueue(pcb)

    def consumer():
        while True:
            pcb = scheduler.next_task()
            if pcb is not None:
                with lock:
                    dequeued.append(pcb.pid)
            else:
                # If all tasks were dequeued, exit
                with lock:
                    if len(dequeued) >= num_tasks:
                        break
                time.sleep(0.001)

    threads = [
        threading.Thread(target=producer, args=(1000, 100)),
        threading.Thread(target=producer, args=(2000, 100)),
        threading.Thread(target=consumer),
        threading.Thread(target=consumer),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(dequeued) == num_tasks
    assert len(set(dequeued)) == num_tasks  # No duplicates or dropped tasks
