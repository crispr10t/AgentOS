"""Tests for kernel/pcb.py: TaskPCB and ProcessState machine."""

import time
import pytest
from pydantic import ValidationError

from kernel.pcb import ProcessState, TaskPCB


def test_pcb_initialization_defaults():
    """Verify that a newly instantiated TaskPCB has correct default attributes."""
    now = time.time()
    pcb = TaskPCB(pid=1001, name="compile_task")

    assert pcb.pid == 1001
    assert pcb.name == "compile_task"
    assert pcb.state == ProcessState.NEW
    assert pcb.priority == 1
    assert pcb.created_at >= now
    assert pcb.started_at is None
    assert pcb.ended_at is None
    assert pcb.cpu_time == 0.0
    assert pcb.peak_memory_mb == 0.0
    assert pcb.exit_code is None
    assert pcb.error_msg is None
    assert pcb.turnaround_time is None
    assert pcb.waiting_time is None


def test_pcb_custom_initialization():
    """Verify custom priority and estimated duration."""
    pcb = TaskPCB(pid=1002, name="priority_task", priority=5, estimated_duration=2.5)
    assert pcb.priority == 5
    assert pcb.estimated_duration == 2.5


def test_pcb_valid_lifecycle_transitions():
    """Verify full linear lifecycle: NEW -> READY -> RUNNING -> TERMINATED."""
    pcb = TaskPCB(pid=1003, name="lifecycle_task")

    # Transition to READY
    pcb.transition_to(ProcessState.READY)
    assert pcb.state == ProcessState.READY
    assert pcb.started_at is None
    assert pcb.ended_at is None

    # Transition to RUNNING (should record started_at)
    pcb.transition_to(ProcessState.RUNNING)
    assert pcb.state == ProcessState.RUNNING
    assert pcb.started_at is not None
    assert pcb.waiting_time is not None
    assert pcb.waiting_time >= 0.0

    # Transition to TERMINATED (should record ended_at)
    pcb.transition_to(ProcessState.TERMINATED)
    assert pcb.state == ProcessState.TERMINATED
    assert pcb.ended_at is not None
    assert pcb.turnaround_time is not None
    assert pcb.turnaround_time >= 0.0


def test_pcb_waiting_and_preemption_lifecycle():
    """Verify RUNNING -> WAITING -> READY -> RUNNING -> READY -> TERMINATED."""
    pcb = TaskPCB(pid=1004, name="io_task")
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)
    initial_started_at = pcb.started_at

    # Wait for I/O
    pcb.transition_to(ProcessState.WAITING)
    assert pcb.state == ProcessState.WAITING

    # Return to READY queue
    pcb.transition_to(ProcessState.READY)
    assert pcb.state == ProcessState.READY

    # Re-scheduled to RUNNING (should not overwrite original started_at)
    pcb.transition_to(ProcessState.RUNNING)
    assert pcb.state == ProcessState.RUNNING
    assert pcb.started_at == initial_started_at

    # Preemption back to READY
    pcb.transition_to(ProcessState.READY)
    assert pcb.state == ProcessState.READY

    # Termination from READY (e.g. cancelled)
    pcb.transition_to(ProcessState.TERMINATED)
    assert pcb.state == ProcessState.TERMINATED


def test_pcb_same_state_transition_is_noop():
    """Transitioning to the current state should be a safe no-op."""
    pcb = TaskPCB(pid=1005, name="noop_task")
    pcb.transition_to(ProcessState.NEW)
    assert pcb.state == ProcessState.NEW


def test_pcb_invalid_state_transitions():
    """Illegal transitions must raise ValueError."""
    pcb = TaskPCB(pid=1006, name="illegal_task")

    # Cannot jump straight from NEW to RUNNING (must be queued via READY)
    with pytest.raises(ValueError, match="Invalid state transition"):
        pcb.transition_to(ProcessState.RUNNING)

    # Cannot jump from NEW to WAITING
    with pytest.raises(ValueError, match="Invalid state transition"):
        pcb.transition_to(ProcessState.WAITING)

    # Advance to TERMINATED
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.TERMINATED)

    # Cannot transition out of TERMINATED
    with pytest.raises(ValueError, match="Invalid state transition"):
        pcb.transition_to(ProcessState.RUNNING)

    with pytest.raises(ValueError, match="Invalid state transition"):
        pcb.transition_to(ProcessState.READY)


def test_pcb_record_metrics():
    """Verify metrics recording updates fields properly."""
    pcb = TaskPCB(pid=1007, name="metric_task")
    pcb.record_metrics(
        cpu_time=1.45,
        peak_memory_mb=64.2,
        exit_code=0,
        error_msg=None,
    )
    assert pcb.cpu_time == 1.45
    assert pcb.peak_memory_mb == 64.2
    assert pcb.exit_code == 0
    assert pcb.error_msg is None

    # Update with an error exit code
    pcb.record_metrics(exit_code=1, error_msg="Segmentation fault")
    assert pcb.exit_code == 1
    assert pcb.error_msg == "Segmentation fault"


def test_pcb_pydantic_validation():
    """Verify pydantic type safety."""
    with pytest.raises(ValidationError):
        TaskPCB(pid="not_an_int", name="bad_task")  # type: ignore
