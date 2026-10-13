"""Comprehensive edge-case tests for kernel/pcb.py: TaskPCB, ProcessState, and metrics."""

import time
import pytest
from pydantic import ValidationError

from kernel.pcb import ProcessState, TaskPCB, VALID_TRANSITIONS


# --- 1. State Machine Transitions Matrix (Exhaustive) ---

ALL_STATES = list(ProcessState)

@pytest.mark.parametrize("state", ALL_STATES)
def test_pcb_same_state_self_transition_is_noop_for_all_states(state: ProcessState):
    """Every state transitioning to itself must be an idempotent no-op."""
    pcb = TaskPCB(pid=100, name="test_noop", state=state)
    pcb.transition_to(state)
    assert pcb.state == state


@pytest.mark.parametrize("from_state, to_state", [
    (ProcessState.NEW, ProcessState.READY),
    (ProcessState.NEW, ProcessState.TERMINATED),
    (ProcessState.READY, ProcessState.RUNNING),
    (ProcessState.READY, ProcessState.TERMINATED),
    (ProcessState.RUNNING, ProcessState.WAITING),
    (ProcessState.RUNNING, ProcessState.READY),
    (ProcessState.RUNNING, ProcessState.TERMINATED),
    (ProcessState.WAITING, ProcessState.READY),
    (ProcessState.WAITING, ProcessState.TERMINATED),
])
def test_pcb_all_valid_transitions(from_state: ProcessState, to_state: ProcessState):
    """Verify each allowed state transition executes successfully."""
    pcb = TaskPCB(pid=101, name="valid_trans", state=from_state)
    pcb.transition_to(to_state)
    assert pcb.state == to_state


@pytest.mark.parametrize("from_state, to_state", [
    (ProcessState.NEW, ProcessState.RUNNING),
    (ProcessState.NEW, ProcessState.WAITING),
    (ProcessState.READY, ProcessState.NEW),
    (ProcessState.READY, ProcessState.WAITING),
    (ProcessState.RUNNING, ProcessState.NEW),
    (ProcessState.WAITING, ProcessState.NEW),
    (ProcessState.WAITING, ProcessState.RUNNING),
    (ProcessState.TERMINATED, ProcessState.NEW),
    (ProcessState.TERMINATED, ProcessState.READY),
    (ProcessState.TERMINATED, ProcessState.RUNNING),
    (ProcessState.TERMINATED, ProcessState.WAITING),
])
def test_pcb_all_illegal_transitions_raise_value_error(from_state: ProcessState, to_state: ProcessState):
    """Verify that every forbidden state transition raises ValueError with PID and names."""
    pcb = TaskPCB(pid=102, name="illegal_trans", state=from_state)
    with pytest.raises(ValueError, match="Invalid state transition"):
        pcb.transition_to(to_state)


# --- 2. Timestamp and Timing Invariants ---

def test_pcb_started_at_not_overwritten_on_subsequent_running_states():
    """Verify that started_at timestamp remains frozen when re-entering RUNNING from WAITING."""
    pcb = TaskPCB(pid=103, name="timing_task")
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)
    first_started = pcb.started_at
    assert first_started is not None

    time.sleep(0.005)
    pcb.transition_to(ProcessState.WAITING)
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)

    assert pcb.started_at == first_started


def test_pcb_ended_at_not_overwritten_if_already_set():
    """Verify ended_at is set once when reaching TERMINATED."""
    pcb = TaskPCB(pid=104, name="term_task")
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.TERMINATED)
    first_ended = pcb.ended_at
    assert first_ended is not None
    assert pcb.state == ProcessState.TERMINATED

    # Re-transitioning to TERMINATED is a no-op
    pcb.transition_to(ProcessState.TERMINATED)
    assert pcb.ended_at == first_ended


def test_pcb_turnaround_and_waiting_time_none_before_execution():
    """Turnaround time and waiting time must be None before task starts or ends."""
    pcb = TaskPCB(pid=105, name="unstarted_task")
    assert pcb.waiting_time is None
    assert pcb.turnaround_time is None

    pcb.transition_to(ProcessState.READY)
    assert pcb.waiting_time is None
    assert pcb.turnaround_time is None


def test_pcb_waiting_and_turnaround_time_clamping_to_zero_on_clock_skew():
    """Verify turnaround and waiting times clamp to 0.0 if timestamps are reversed (clock skew)."""
    future_time = time.time() + 1000.0
    past_time = time.time() - 1000.0

    pcb = TaskPCB(pid=106, name="skew_task", created_at=future_time)
    pcb.started_at = past_time
    pcb.ended_at = past_time

    assert pcb.waiting_time == 0.0
    assert pcb.turnaround_time == 0.0


# --- 3. Resource and Metrics Clamping ---

@pytest.mark.parametrize("cpu_val, mem_val", [
    (-1.0, -10.0),
    (-0.0001, -0.0001),
    (-1000.0, -500.0),
])
def test_pcb_negative_metrics_clamped_to_zero(cpu_val: float, mem_val: float):
    """Negative CPU time and memory values must clamp to 0.0."""
    pcb = TaskPCB(pid=107, name="negative_metrics")
    pcb.record_metrics(cpu_time=cpu_val, peak_memory_mb=mem_val)
    assert pcb.cpu_time == 0.0
    assert pcb.peak_memory_mb == 0.0


@pytest.mark.parametrize("exit_code", [0, 1, -1, 126, 127, 130, 143, 255])
def test_pcb_various_exit_codes(exit_code: int):
    """Verify various standard and POSIX/Windows return codes are preserved correctly."""
    pcb = TaskPCB(pid=108, name="exit_codes")
    pcb.record_metrics(exit_code=exit_code)
    assert pcb.exit_code == exit_code


def test_pcb_partial_metrics_update():
    """Verify that partial metric updates leave unpassed fields unchanged."""
    pcb = TaskPCB(pid=109, name="partial_metrics")
    pcb.record_metrics(cpu_time=2.5)
    assert pcb.cpu_time == 2.5
    assert pcb.peak_memory_mb == 0.0
    assert pcb.exit_code is None

    pcb.record_metrics(peak_memory_mb=128.0, exit_code=0)
    assert pcb.cpu_time == 2.5
    assert pcb.peak_memory_mb == 128.0
    assert pcb.exit_code == 0


# --- 4. Validation and Pydantic Safety ---

@pytest.mark.parametrize("invalid_pid", ["abc", None, [], {}, 12.34])
def test_pcb_invalid_pid_type_raises_validation_error(invalid_pid):
    """Non-integer PID values must trigger Pydantic validation errors."""
    with pytest.raises(ValidationError):
        TaskPCB(pid=invalid_pid, name="bad_pid")  # type: ignore


@pytest.mark.parametrize("special_name", [
    "",
    "   ",
    "🚀_unicode_task_123",
    "a" * 1000,
    "path/with/slashes/and\\backslashes",
    "newline\ntask\nname",
])
def test_pcb_special_character_and_length_names(special_name: str):
    """Verify that task names support various lengths, Unicode, and special characters."""
    pcb = TaskPCB(pid=110, name=special_name)
    assert pcb.name == special_name


@pytest.mark.parametrize("priority", [-10, 0, 1, 10, 999999])
def test_pcb_priority_range_acceptance(priority: int):
    """Verify PCB accepts a wide range of priority values."""
    pcb = TaskPCB(pid=111, name="priority_task", priority=priority)
    assert pcb.priority == priority


@pytest.mark.parametrize("duration", [0.0, 0.0001, 1.5, 9999.0])
def test_pcb_estimated_duration_acceptance(duration: float):
    """Verify estimated duration supports fractional, zero, and large values."""
    pcb = TaskPCB(pid=112, name="duration_task", estimated_duration=duration)
    assert pcb.estimated_duration == duration


# --- 5. Serialization and Roundtrip ---

def test_pcb_serialization_roundtrip():
    """Verify TaskPCB model dumping and recreation retains all fields."""
    pcb = TaskPCB(
        pid=113,
        name="roundtrip_task",
        priority=3,
        estimated_duration=4.2,
    )
    pcb.transition_to(ProcessState.READY)
    pcb.transition_to(ProcessState.RUNNING)
    pcb.record_metrics(cpu_time=0.85, peak_memory_mb=32.1, exit_code=0, error_msg="No error")
    pcb.transition_to(ProcessState.TERMINATED)

    dumped_dict = pcb.model_dump()
    recreated = TaskPCB.model_validate(dumped_dict)

    assert recreated.pid == pcb.pid
    assert recreated.name == pcb.name
    assert recreated.state == ProcessState.TERMINATED
    assert recreated.priority == 3
    assert recreated.cpu_time == 0.85
    assert recreated.peak_memory_mb == 32.1
    assert recreated.exit_code == 0
    assert recreated.error_msg == "No error"
    assert recreated.turnaround_time == pcb.turnaround_time
    assert recreated.waiting_time == pcb.waiting_time
