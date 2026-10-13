"""Comprehensive edge-case tests for agent/planner.py: DAG validation, topological sorting, JSON parsing, and parameter sanitization."""

import pytest
from pydantic import ValidationError

from agent.planner import (
    PlanParsingError,
    PlanSecurityViolation,
    PlanStep,
    PlanValidationError,
    SyscallPlan,
    extract_json_payload,
    sanitize_step_params,
)
from kernel.pcb import ProcessState
from kernel.syscalls import PrivilegeRing, SyscallType


# --- 1. PlanStep Model Edge Cases ---

def test_plan_step_invalid_syscall_type():
    """Invalid syscall string or type must raise ValueError."""
    with pytest.raises(ValueError, match="Unknown syscall"):
        PlanStep(step_id=1, syscall="NON_EXISTENT_SYSCALL")


@pytest.mark.parametrize("invalid_ring", [-1, 1, 2, 4, "admin", None])
def test_plan_step_invalid_ring(invalid_ring):
    """Ring values other than 0 or 3 must raise ValueError."""
    with pytest.raises(ValueError):
        PlanStep(step_id=1, syscall=SyscallType.CALCULATE, ring=invalid_ring)  # type: ignore


def test_plan_step_to_pcb_and_request_conversions():
    """Verify PlanStep accurately converts to TaskPCB and SyscallRequest."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.CALCULATE,
        params={"expr": "1 + 1"},
        priority=5,
        estimated_duration=0.5,
        description="Calculate addition",
    )

    req = step.to_syscall_request()
    assert req.syscall == SyscallType.CALCULATE
    assert req.params == {"expr": "1 + 1"}
    assert req.ring == PrivilegeRing.RING_3

    pcb = step.to_pcb(pid=100)
    assert pcb.pid == 100
    assert pcb.name == "Calculate addition"
    assert pcb.priority == 5
    assert pcb.estimated_duration == 0.5
    assert pcb.state == ProcessState.NEW


# --- 2. DAG Cycles and Validation Edge Cases ---

def test_dag_validation_duplicate_step_ids():
    """Duplicate step_id must raise PlanValidationError."""
    step1 = PlanStep(step_id=1, syscall=SyscallType.CALCULATE)
    step2 = PlanStep(step_id=1, syscall=SyscallType.FILE_SEARCH)
    plan = SyscallPlan(user_prompt="test", plan_description="test", steps=[step1, step2])

    with pytest.raises(PlanValidationError, match="Duplicate step_id"):
        plan.validate_dag()


def test_dag_validation_self_dependency():
    """Step depending on itself must raise PlanValidationError."""
    step = PlanStep(step_id=1, syscall=SyscallType.CALCULATE, dependencies=[1])
    plan = SyscallPlan(user_prompt="test", plan_description="test", steps=[step])

    with pytest.raises(PlanValidationError, match="cannot depend on itself"):
        plan.validate_dag()


def test_dag_validation_nonexistent_dependency():
    """Step depending on an unknown step_id must raise PlanValidationError."""
    step = PlanStep(step_id=1, syscall=SyscallType.CALCULATE, dependencies=[99])
    plan = SyscallPlan(user_prompt="test", plan_description="test", steps=[step])

    with pytest.raises(PlanValidationError, match="non-existent step_id"):
        plan.validate_dag()


def test_dag_validation_direct_cycle_2_nodes():
    """Cycle: 1 -> 2 -> 1 must raise PlanValidationError."""
    s1 = PlanStep(step_id=1, syscall=SyscallType.CALCULATE, dependencies=[2])
    s2 = PlanStep(step_id=2, syscall=SyscallType.CALCULATE, dependencies=[1])
    plan = SyscallPlan(user_prompt="test", plan_description="test", steps=[s1, s2])

    with pytest.raises(PlanValidationError, match="Cyclical dependency detected"):
        plan.validate_dag()


def test_dag_validation_indirect_cycle_3_nodes():
    """Cycle: 1 -> 2 -> 3 -> 1 must raise PlanValidationError."""
    s1 = PlanStep(step_id=1, syscall=SyscallType.CALCULATE, dependencies=[3])
    s2 = PlanStep(step_id=2, syscall=SyscallType.CALCULATE, dependencies=[1])
    s3 = PlanStep(step_id=3, syscall=SyscallType.CALCULATE, dependencies=[2])
    plan = SyscallPlan(user_prompt="test", plan_description="test", steps=[s1, s2, s3])

    with pytest.raises(PlanValidationError, match="Cyclical dependency detected"):
        plan.validate_dag()


def test_dag_topological_sort_diamond():
    """Verify diamond DAG: 1 -> (2, 3) -> 4 produces valid ordering."""
    s1 = PlanStep(step_id=1, syscall=SyscallType.CALCULATE)
    s2 = PlanStep(step_id=2, syscall=SyscallType.CALCULATE, dependencies=[1])
    s3 = PlanStep(step_id=3, syscall=SyscallType.CALCULATE, dependencies=[1])
    s4 = PlanStep(step_id=4, syscall=SyscallType.CALCULATE, dependencies=[2, 3])

    # Pass in scrambled order
    plan = SyscallPlan(user_prompt="test", plan_description="test", steps=[s4, s3, s2, s1])
    ordered = plan.get_topological_steps()

    ordered_ids = [s.step_id for s in ordered]
    assert ordered_ids[0] == 1
    assert ordered_ids[-1] == 4
    assert set(ordered_ids[1:3]) == {2, 3}


# --- 3. JSON Extraction from LLM Output ---

@pytest.mark.parametrize("raw_input", [
    '{"plan_description": "Clean JSON", "steps": []}',
    '```json\n{"plan_description": "Fenced JSON", "steps": []}\n```',
    '```\n{"plan_description": "Unspecified fence", "steps": []}\n```',
    'Here is your requested plan:\n```json\n{"plan_description": "Prose before", "steps": []}\n```\nHope this helps!',
    'Prefix note... {"plan_description": "Raw in middle", "steps": []} ...suffix note',
])
def test_extract_json_payload_valid_variants(raw_input: str):
    """Verify extract_json_payload extracts dictionary from various LLM formatting styles."""
    data = extract_json_payload(raw_input)
    assert isinstance(data, dict)
    assert "plan_description" in data


@pytest.mark.parametrize("invalid_raw", [
    "No json here at all.",
    "```json\n[1, 2, 3]\n```",  # List, not dict
    "{ unclosed json",
    "",
    "   ",
])
def test_extract_json_payload_invalid_raises(invalid_raw: str):
    """Malformed or non-dict JSON output must raise PlanParsingError."""
    with pytest.raises(PlanParsingError):
        extract_json_payload(invalid_raw)


# --- 4. Parameter Sanitization Edge Cases ---

def test_sanitize_step_proc_spawn_string_auto_split():
    """String command in PROC_SPAWN is automatically split into token list."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": "git status --short"},
    )
    sanitize_step_params(step)
    assert step.params["cmd"] == ["git", "status", "--short"]


def test_sanitize_step_proc_spawn_empty_cmd_fails():
    """Empty command list in PROC_SPAWN raises PlanSecurityViolation."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": []},
    )
    with pytest.raises(PlanSecurityViolation, match="must have a non-empty list"):
        sanitize_step_params(step)


def test_sanitize_step_proc_spawn_prohibited_prefix_fails():
    """Prohibited shell wrapper prefix raises PlanSecurityViolation."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": ["cmd.exe", "/c", "dir"]},
    )
    with pytest.raises(PlanSecurityViolation, match="forbidden shell wrapper"):
        sanitize_step_params(step)


def test_sanitize_step_path_traversal_fails():
    """Path traversal in file operation params raises PlanSecurityViolation."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.FILE_READ,
        params={"path": "../../secret.env"},
    )
    with pytest.raises(PlanSecurityViolation, match="Path traversal detected"):
        sanitize_step_params(step)
