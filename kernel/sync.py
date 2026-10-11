"""Concurrency and Synchronization Engine.

Implements core OS synchronization primitives in user space:
- Thread-safe Process Control Block (PCB) Table protected by re-entrant mutex locks.
- Bounded Producer-Consumer Queue implementing the classic Monitor / Condition Variable pattern.
- CriticalSection context managers to prevent race conditions on shared supervisor resources.
"""

from __future__ import annotations

from collections import deque
import threading
import time
from typing import Any, Callable, Generic, Optional, TypeVar

from kernel.pcb import ProcessState, TaskPCB

T = TypeVar("T")


class SyncError(Exception):
    """Base exception for concurrency and synchronization errors."""


class QueueFullError(SyncError):
    """Raised when an insertion times out on a saturated bounded queue."""


class QueueEmptyError(SyncError):
    """Raised when an extraction times out on an empty bounded queue."""


class QueueShutdownError(SyncError):
    """Raised when an operation is attempted on a terminated producer-consumer queue."""


class CriticalSection:
    """Explicit critical section context manager.

    Provides transparent mutex locking around shared supervisor resources
    for clear OS concept demonstration and viva explanations.
    """

    def __init__(self, lock: Optional[threading.Lock | threading.RLock] = None):
        """Initializes the CriticalSection with a supplied or new re-entrant lock."""
        self._lock = lock if lock is not None else threading.RLock()

    def __enter__(self) -> threading.Lock | threading.RLock:
        self._lock.acquire()
        return self._lock

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._lock.release()

    @property
    def lock(self) -> threading.Lock | threading.RLock:
        """Returns the underlying lock instance."""
        return self._lock


class PCBTable:
    """Thread-safe central registry tracking all TaskPCBs in the Micro-Supervisor.

    Protected by re-entrant mutex locks to guarantee data consistency against
    concurrent updates from worker execution threads, watchdog threads,
    and the PyQt6 graphical shell.
    """

    def __init__(self):
        """Initializes an empty thread-safe PCB table."""
        self._lock = threading.RLock()
        self._table: dict[int, TaskPCB] = {}
        self._listeners: list[Callable[[TaskPCB], None]] = []

    @property
    def lock(self) -> threading.RLock:
        """Returns the internal re-entrant lock for compound atomic operations."""
        return self._lock

    def subscribe(self, callback: Callable[[TaskPCB], None]) -> None:
        """Subscribes an observer callback invoked whenever a PCB changes.

        Args:
            callback: Function taking updated TaskPCB instance.
        """
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def unsubscribe(self, callback: Callable[[TaskPCB], None]) -> None:
        """Unsubscribes a previously registered observer callback.

        Args:
            callback: Function to remove.
        """
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def _notify(self, pcb: TaskPCB) -> None:
        """Dispatches notification to all registered observers."""
        listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(pcb)
            except Exception:
                # Observers must not crash supervisor execution
                pass

    def register(self, pcb: TaskPCB) -> None:
        """Registers a new TaskPCB or updates an existing entry in the table.

        Args:
            pcb: TaskPCB instance to store.
        """
        with self._lock:
            self._table[pcb.pid] = pcb
            self._notify(pcb)

    def get(self, pid: int) -> Optional[TaskPCB]:
        """Retrieves a TaskPCB by process ID.

        Args:
            pid: Process ID.

        Returns:
            The TaskPCB instance, or None if not registered.
        """
        with self._lock:
            return self._table.get(pid)

    def update_state(self, pid: int, new_state: ProcessState) -> Optional[TaskPCB]:
        """Transitions a registered task to a new lifecycle state in a thread-safe manner.

        Args:
            pid: Process ID.
            new_state: Target ProcessState.

        Returns:
            The updated TaskPCB, or None if not found.

        Raises:
            ValueError: If the state transition is illegal according to OS lifecycle rules.
        """
        with self._lock:
            pcb = self._table.get(pid)
            if pcb is None:
                return None
            pcb.transition_to(new_state)
            self._notify(pcb)
            return pcb

    def update_metrics(
        self,
        pid: int,
        cpu_time: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
        exit_code: Optional[int] = None,
        error_msg: Optional[str] = None,
    ) -> Optional[TaskPCB]:
        """Updates runtime performance metrics and exit status for a registered task.

        Args:
            pid: Process ID.
            cpu_time: CPU execution time in seconds.
            peak_memory_mb: Peak memory footprint in MB.
            exit_code: Process return code.
            error_msg: Error message string.

        Returns:
            The updated TaskPCB, or None if not found.
        """
        with self._lock:
            pcb = self._table.get(pid)
            if pcb is None:
                return None
            pcb.record_metrics(
                cpu_time=cpu_time,
                peak_memory_mb=peak_memory_mb,
                exit_code=exit_code,
                error_msg=error_msg,
            )
            self._notify(pcb)
            return pcb

    def remove(self, pid: int) -> Optional[TaskPCB]:
        """Removes a TaskPCB entry from the table.

        Args:
            pid: Process ID to remove.

        Returns:
            The removed TaskPCB, or None if not found.
        """
        with self._lock:
            return self._table.pop(pid, None)

    def list_all(self) -> list[TaskPCB]:
        """Returns a snapshot copy of all registered tasks."""
        with self._lock:
            return list(self._table.values())

    def list_active(self) -> list[TaskPCB]:
        """Returns a snapshot copy of all tasks that have not terminated."""
        with self._lock:
            return [
                pcb
                for pcb in self._table.values()
                if pcb.state != ProcessState.TERMINATED
            ]

    def list_by_state(self, state: ProcessState) -> list[TaskPCB]:
        """Returns all registered tasks currently in a specific lifecycle state."""
        with self._lock:
            return [pcb for pcb in self._table.values() if pcb.state == state]

    def clear(self) -> None:
        """Clears all records from the table."""
        with self._lock:
            self._table.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._table)

    def __contains__(self, pid: int) -> bool:
        with self._lock:
            return pid in self._table


class ProducerConsumerQueue(Generic[T]):
    """Thread-safe bounded queue implementing the classic Monitor pattern.

    Solves the Bounded Buffer Producer-Consumer synchronization problem using
    mutex locks and two condition variables:
    - not_full: Signaled when an item is removed, unblocking waiting producers.
    - not_empty: Signaled when an item is added, unblocking waiting consumers.
    """

    def __init__(self, maxsize: int = 100):
        """Initializes the bounded queue.

        Args:
            maxsize: Maximum buffer capacity. Must be > 0.
        """
        if maxsize <= 0:
            raise ValueError(f"maxsize must be positive, got {maxsize}")

        self.maxsize = maxsize
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)
        self._buffer: deque[T] = deque()
        self._is_shutdown: bool = False

    def put(self, item: T, timeout: Optional[float] = None) -> None:
        """Inserts an item into the queue, blocking if full until space is available.

        Args:
            item: Item to enqueue.
            timeout: Maximum duration to block in seconds, or None to block indefinitely.

        Raises:
            QueueShutdownError: If the queue has been shut down.
            QueueFullError: If the timeout expires while waiting for buffer capacity.
        """
        with self._lock:
            if self._is_shutdown:
                raise QueueShutdownError("Cannot put to a shut down queue")

            end_time = time.time() + timeout if timeout is not None else None

            while len(self._buffer) >= self.maxsize:
                if self._is_shutdown:
                    raise QueueShutdownError("Queue was shut down while waiting to put")

                if timeout is not None:
                    remaining = end_time - time.time()  # type: ignore
                    if remaining <= 0:
                        raise QueueFullError("Timed out waiting for free queue slot")
                    self._not_full.wait(timeout=remaining)
                else:
                    self._not_full.wait()

            if self._is_shutdown:
                raise QueueShutdownError("Queue was shut down while waiting to put")

            self._buffer.append(item)
            self._not_empty.notify()

    def get(self, timeout: Optional[float] = None) -> T:
        """Pops and returns an item from the queue, blocking if empty.

        Args:
            timeout: Maximum duration to block in seconds, or None to block indefinitely.

        Returns:
            The dequeued item.

        Raises:
            QueueShutdownError: If the queue has been shut down and is empty.
            QueueEmptyError: If the timeout expires while waiting for an item.
        """
        with self._lock:
            end_time = time.time() + timeout if timeout is not None else None

            while len(self._buffer) == 0:
                if self._is_shutdown:
                    raise QueueShutdownError("Queue is shut down and empty")

                if timeout is not None:
                    remaining = end_time - time.time()  # type: ignore
                    if remaining <= 0:
                        raise QueueEmptyError("Timed out waiting for an item")
                    self._not_empty.wait(timeout=remaining)
                else:
                    self._not_empty.wait()

            item = self._buffer.popleft()
            self._not_full.notify()
            return item

    def qsize(self) -> int:
        """Returns current number of items buffered in the queue."""
        with self._lock:
            return len(self._buffer)

    def is_empty(self) -> bool:
        """Returns True if the buffer contains zero items."""
        with self._lock:
            return len(self._buffer) == 0

    def is_full(self) -> bool:
        """Returns True if the buffer capacity has reached maxsize."""
        with self._lock:
            return len(self._buffer) >= self.maxsize

    def shutdown(self) -> None:
        """Gracefully shuts down the queue and wakes all blocked threads."""
        with self._lock:
            self._is_shutdown = True
            self._not_full.notify_all()
            self._not_empty.notify_all()

    @property
    def is_shutdown(self) -> bool:
        """Returns True if the queue has been marked as shut down."""
        with self._lock:
            return self._is_shutdown

    def __len__(self) -> int:
        return self.qsize()
