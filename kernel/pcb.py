"""Process Control Block (PCB) and Process State Machine.

Implements the fundamental OS abstractions for tracking task execution,
lifecycle state transitions, resource utilization, and scheduling metrics.
"""

from __future__ import annotations

from enum import Enum
import time
from typing import Optional

from pydantic import BaseModel, Field


class ProcessState(str, Enum):
    """Five-state process lifecycle model aligned with classic OS theory."""

    NEW = "NEW"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    TERMINATED = "TERMINATED"


# Valid state transitions mapping
VALID_TRANSITIONS: dict[ProcessState, set[ProcessState]] = {
    ProcessState.NEW: {ProcessState.READY, ProcessState.TERMINATED},
    ProcessState.READY: {ProcessState.RUNNING, ProcessState.TERMINATED},
    ProcessState.RUNNING: {
        ProcessState.WAITING,
        ProcessState.READY,
        ProcessState.TERMINATED,
    },
    ProcessState.WAITING: {ProcessState.READY, ProcessState.TERMINATED},
    ProcessState.TERMINATED: set(),
}


class TaskPCB(BaseModel):
    """Process Control Block representing an OS task managed by the Micro-Supervisor.

    Tracks identity, lifecycle status, scheduling priority, execution timing,
    and runtime resource consumption.
    """

    pid: int
    name: str
    state: ProcessState = ProcessState.NEW
    priority: int = 1
    created_at: float = Field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    cpu_time: float = 0.0
    peak_memory_mb: float = 0.0
    exit_code: Optional[int] = None
    error_msg: Optional[str] = None
    estimated_duration: float = 1.0

    def transition_to(self, new_state: ProcessState) -> None:
        """Transitions task to a new lifecycle state if the transition is valid.

        Args:
            new_state: Target ProcessState.

        Raises:
            ValueError: If the state transition is illegal.
        """
        if new_state == self.state:
            return

        allowed = VALID_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise ValueError(
                f"Invalid state transition for PID {self.pid} ({self.name}): "
                f"{self.state.value} -> {new_state.value}"
            )

        now = time.time()
        if new_state == ProcessState.RUNNING and self.started_at is None:
            self.started_at = now
        elif new_state == ProcessState.TERMINATED:
            self.ended_at = now

        self.state = new_state

    def record_metrics(
        self,
        cpu_time: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
        exit_code: Optional[int] = None,
        error_msg: Optional[str] = None,
    ) -> None:
        """Updates runtime performance metrics and exit status.

        Args:
            cpu_time: Consumed CPU time in seconds.
            peak_memory_mb: Peak resident set memory in Megabytes.
            exit_code: Process return code (0 for success).
            error_msg: Error message or traceback if failed.
        """
        if cpu_time is not None:
            self.cpu_time = max(0.0, float(cpu_time))
        if peak_memory_mb is not None:
            self.peak_memory_mb = max(0.0, float(peak_memory_mb))
        if exit_code is not None:
            self.exit_code = int(exit_code)
        if error_msg is not None:
            self.error_msg = error_msg

    @property
    def turnaround_time(self) -> Optional[float]:
        """Calculates Turnaround Time: T_turnaround = T_ended - T_created.

        Returns:
            Elapsed time from task creation to termination in seconds, or None if still active.
        """
        if self.ended_at is not None and self.created_at is not None:
            return max(0.0, self.ended_at - self.created_at)
        return None

    @property
    def waiting_time(self) -> Optional[float]:
        """Calculates Waiting Time: T_waiting = T_started - T_created.

        Returns:
            Time spent waiting in the ready queue before first execution, or None if not started.
        """
        if self.started_at is not None and self.created_at is not None:
            return max(0.0, self.started_at - self.created_at)
        return None
