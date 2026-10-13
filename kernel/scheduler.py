"""Task Scheduler and Scheduling Policies.

Implements deterministic CPU scheduling algorithms in user space:
- First-Come, First-Served (FCFS)
- Priority Scheduling
- Shortest Job First (SJF)

Provides real-time metric computations for Turnaround and Waiting times,
dynamic policy switching, and thread-safe ready-queue management.
"""

from __future__ import annotations

import copy
from enum import Enum
import threading
import time
from typing import Any, Optional

from kernel.pcb import ProcessState, TaskPCB


class SchedulingPolicy(str, Enum):
    """Supported CPU scheduling policies."""

    FCFS = "FCFS"          # First-Come, First-Served (FIFO)
    PRIORITY = "PRIORITY"  # Priority Scheduling (ordered by user priority)
    SJF = "SJF"            # Shortest Job First (ordered by estimated duration)

    @classmethod
    def _missing_(cls, value: object) -> Optional["SchedulingPolicy"]:
        """Enables case-insensitive policy lookup (e.g. 'Priority' -> PRIORITY)."""
        if isinstance(value, str):
            clean = value.strip().upper()
            for member in cls:
                if member.value == clean or member.name == clean:
                    return member
        return None


class TaskScheduler:
    """Thread-safe task scheduler governing the ready-queue dispatch order.

    Supports dynamic switching among FCFS, Priority, and SJF policies,
    calculates Turnaround and Waiting Time performance metrics, and maintains
    deterministic tie-breaking using monotonic arrival sequence indices.
    """

    def __init__(
        self,
        policy: str | SchedulingPolicy = SchedulingPolicy.FCFS,
        higher_priority_first: bool = True,
    ):
        """Initializes the TaskScheduler.

        Args:
            policy: Initial scheduling policy ('FCFS', 'PRIORITY', or 'SJF').
            higher_priority_first: If True, higher priority numbers execute first (e.g. 10 before 1).
                                   If False, lower priority numbers execute first (e.g. 1 before 10).
        """
        self._policy = self._normalize_policy(policy)
        self.higher_priority_first = higher_priority_first
        self._lock = threading.RLock()

        # Internal queue stores tuples of (TaskPCB, arrival_seq)
        self._queue: list[tuple[TaskPCB, int]] = []
        self._seq_counter: int = 0
        self._completed_history: list[TaskPCB] = []

    @property
    def policy(self) -> SchedulingPolicy:
        """Returns the active scheduling policy."""
        with self._lock:
            return self._policy

    @staticmethod
    def _normalize_policy(policy: str | SchedulingPolicy) -> SchedulingPolicy:
        """Normalizes and validates a policy string or Enum value."""
        if isinstance(policy, SchedulingPolicy):
            return policy
        if isinstance(policy, str):
            clean = policy.strip().upper()
            try:
                return SchedulingPolicy(clean)
            except ValueError:
                valid = [p.value for p in SchedulingPolicy]
                raise ValueError(
                    f"Unknown scheduling policy: '{policy}'. Supported policies: {valid}"
                )
        raise TypeError(f"Policy must be a string or SchedulingPolicy enum, got {type(policy)}")

    def _sort_key(self, entry: tuple[TaskPCB, int]) -> Any:
        """Generates the sorting key for a queue entry based on active policy."""
        pcb, seq = entry
        if self._policy == SchedulingPolicy.FCFS:
            # First-Come, First-Served: ordered by monotonic arrival sequence
            return seq
        elif self._policy == SchedulingPolicy.PRIORITY:
            # Priority: higher or lower first, with arrival sequence as tie-breaker
            priority_val = -pcb.priority if self.higher_priority_first else pcb.priority
            return (priority_val, seq)
        elif self._policy == SchedulingPolicy.SJF:
            # Shortest Job First: shortest duration first, with arrival sequence as tie-breaker
            return (pcb.estimated_duration, seq)
        return seq

    def _reorder_queue(self) -> None:
        """Re-sorts the queue in place according to the active policy."""
        self._queue.sort(key=self._sort_key)

    def set_policy(self, policy: str | SchedulingPolicy) -> None:
        """Switches the active scheduling policy and re-sorts queued tasks.

        Args:
            policy: New scheduling policy ('FCFS', 'PRIORITY', or 'SJF').
        """
        new_policy = self._normalize_policy(policy)
        with self._lock:
            if self._policy != new_policy:
                self._policy = new_policy
                self._reorder_queue()

    def enqueue(self, pcb: TaskPCB) -> None:
        """Adds a task to the ready queue and ensures valid state transition.

        If the task is in NEW state, it is transitioned to READY.

        Args:
            pcb: TaskPCB instance to queue for execution.
        """
        with self._lock:
            if pcb.state == ProcessState.NEW:
                pcb.transition_to(ProcessState.READY)
            elif pcb.state != ProcessState.READY:
                # If task was waiting or preempted, transition back to READY
                pcb.transition_to(ProcessState.READY)

            self._seq_counter += 1
            entry = (pcb, self._seq_counter)
            self._queue.append(entry)
            self._reorder_queue()

    def next_task(self) -> Optional[TaskPCB]:
        """Extracts and returns the next highest-priority task from the ready queue.

        Returns:
            The next TaskPCB according to the current policy, or None if the queue is empty.
        """
        with self._lock:
            if not self._queue:
                return None
            pcb, _ = self._queue.pop(0)
            return pcb

    def peek(self) -> Optional[TaskPCB]:
        """Inspects the next task without removing it from the ready queue.

        Returns:
            The next TaskPCB in line, or None if queue is empty.
        """
        with self._lock:
            if not self._queue:
                return None
            return self._queue[0][0]

    def remove(self, pid: int) -> Optional[TaskPCB]:
        """Removes a task from the ready queue by PID (e.g., if cancelled).

        Args:
            pid: Process ID to remove.

        Returns:
            The removed TaskPCB, or None if not present in the ready queue.
        """
        with self._lock:
            for idx, (pcb, _) in enumerate(self._queue):
                if pcb.pid == pid:
                    removed, _ = self._queue.pop(idx)
                    return removed
            return None

    def get_queue(self) -> list[TaskPCB]:
        """Returns a snapshot copy of all tasks in the ready queue in dispatch order."""
        with self._lock:
            return [pcb for pcb, _ in self._queue]

    def queue_size(self) -> int:
        """Returns the number of tasks currently in the ready queue."""
        with self._lock:
            return len(self._queue)

    def is_empty(self) -> bool:
        """Returns True if the ready queue has no tasks."""
        with self._lock:
            return len(self._queue) == 0

    def __len__(self) -> int:
        return self.queue_size()

    def record_completed(self, pcb: TaskPCB) -> None:
        """Records a completed or terminated task into internal execution history.

        Args:
            pcb: TaskPCB instance that has reached TERMINATED state.
        """
        with self._lock:
            self._completed_history.append(pcb)

    def get_history(self) -> list[TaskPCB]:
        """Returns a snapshot copy of all completed tasks in history."""
        with self._lock:
            return list(self._completed_history)

    def clear(self) -> None:
        """Clears both ready queue and completion history."""
        with self._lock:
            self._queue.clear()
            self._completed_history.clear()

    def compute_metrics(
        self, completed_tasks: Optional[list[TaskPCB]] = None
    ) -> dict[str, float]:
        """Calculates scheduling metrics (Turnaround Time and Waiting Time).

        Formula definitions:
        - Turnaround Time = T_ended - T_created
        - Waiting Time = T_started - T_created

        Args:
            completed_tasks: Optional list of TaskPCBs to evaluate. If None,
                             uses the scheduler's internal completion history.

        Returns:
            Dictionary containing task counts, averages, and maximums:
            {
                'total_tasks': float,
                'avg_waiting_time': float,
                'max_waiting_time': float,
                'avg_turnaround_time': float,
                'max_turnaround_time': float,
            }
        """
        with self._lock:
            tasks = completed_tasks if completed_tasks is not None else self._completed_history
            if not tasks:
                return {
                    "total_tasks": 0.0,
                    "avg_waiting_time": 0.0,
                    "max_waiting_time": 0.0,
                    "avg_turnaround_time": 0.0,
                    "max_turnaround_time": 0.0,
                }

            waiting_times: list[float] = []
            turnaround_times: list[float] = []

            for pcb in tasks:
                wt = pcb.waiting_time
                if wt is not None:
                    waiting_times.append(wt)

                tt = pcb.turnaround_time
                if tt is not None:
                    turnaround_times.append(tt)

            n_wait = len(waiting_times)
            n_turn = len(turnaround_times)

            avg_wait = sum(waiting_times) / n_wait if n_wait > 0 else 0.0
            max_wait = max(waiting_times) if n_wait > 0 else 0.0

            avg_turn = sum(turnaround_times) / n_turn if n_turn > 0 else 0.0
            max_turn = max(turnaround_times) if n_turn > 0 else 0.0

            return {
                "total_tasks": float(len(tasks)),
                "avg_waiting_time": round(avg_wait, 4),
                "max_waiting_time": round(max_wait, 4),
                "avg_turnaround_time": round(avg_turn, 4),
                "max_turnaround_time": round(max_turn, 4),
            }

    @staticmethod
    def simulate_batch(
        tasks: list[TaskPCB],
        policy: str | SchedulingPolicy = SchedulingPolicy.FCFS,
        higher_priority_first: bool = True,
    ) -> tuple[list[TaskPCB], dict[str, float]]:
        """Simulates non-preemptive execution of a batch of tasks under a specified policy.

        Ideal for academic demonstrations and benchmarking to compare average
        Waiting Time and Turnaround Time between FCFS, Priority, and SJF without
        requiring real-time physical delays.

        Args:
            tasks: List of TaskPCB instances to simulate.
            policy: Scheduling policy to simulate.
            higher_priority_first: Priority ordering direction.

        Returns:
            Tuple of (simulated_task_copies, metrics_dict).
        """
        temp_scheduler = TaskScheduler(
            policy=policy, higher_priority_first=higher_priority_first
        )

        # Deep-copy tasks so simulation doesn't mutate caller's state
        cloned_tasks = [copy.deepcopy(t) for t in tasks]

        # Use the earliest created_at as virtual time t=0
        base_arrival = min((t.created_at for t in cloned_tasks), default=0.0)

        for t in cloned_tasks:
            temp_scheduler.enqueue(t)

        current_time = 0.0
        completed: list[TaskPCB] = []

        while not temp_scheduler.is_empty():
            pcb = temp_scheduler.next_task()
            if pcb is None:
                break

            relative_arrival = max(0.0, pcb.created_at - base_arrival)
            # Process cannot start before its relative arrival time
            start_time = max(current_time, relative_arrival)
            duration = max(0.01, pcb.estimated_duration)
            end_time = start_time + duration

            pcb.transition_to(ProcessState.RUNNING)
            pcb.transition_to(ProcessState.TERMINATED)
            pcb.started_at = pcb.created_at + (start_time - relative_arrival)
            pcb.ended_at = pcb.started_at + duration

            current_time = end_time
            completed.append(pcb)

        metrics = temp_scheduler.compute_metrics(completed)
        return completed, metrics
