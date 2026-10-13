"""Unit and Integration Tests for Agent Planner and Syscall Plan Compiler."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.llm_client import LLMClient, LLMClientError, LLMConfig, LLMProvider
from agent.planner import (
    AgentPlanner,
    PlanError,
    PlanParsingError,
    PlanSecurityViolation,
    PlanStep,
    PlanValidationError,
    SyscallPlan,
    extract_json_payload,
    sanitize_step_params,
)
from kernel.pcb import ProcessState
from kernel.scheduler import SchedulingPolicy, TaskScheduler
from kernel.sync import PCBTable
from kernel.syscalls import (
    PrivilegeRing,
    SyscallDispatcher,
    SyscallResult,
    SyscallType,
)
from security.privilege import PrivilegeGate


def test_extract_json_payload_clean():
    """Verifies extracting pure JSON string without wrappers."""
    raw = '{"plan_description": "Clean plan", "steps": []}'
    parsed = extract_json_payload(raw)
    assert parsed["plan_description"] == "Clean plan"
    assert parsed["steps"] == []


def test_extract_json_payload_markdown_fences():
    """Verifies stripping markdown code block fences."""
    raw = """
Here is the requested plan:
```json
{
  "plan_description": "Fenced plan",
  "steps": [
    {"step_id": 1, "syscall": "SYS_INFO", "params": {}}
  ]
}
```
Hope this helps!
"""
    parsed = extract_json_payload(raw)
    assert parsed["plan_description"] == "Fenced plan"
    assert len(parsed["steps"]) == 1


def test_extract_json_payload_with_surrounding_prose():
    """Verifies extracting JSON embedded within conversational text."""
    raw = 'Sure! {"plan_description": "Embedded", "steps": []} Let me know if you need anything.'
    parsed = extract_json_payload(raw)
    assert parsed["plan_description"] == "Embedded"


def test_extract_json_payload_invalid_raises():
    """Verifies PlanParsingError when no JSON structure exists."""
    with pytest.raises(PlanParsingError):
        extract_json_payload("I cannot compile this request.")


def test_plan_step_default_ring_assignment():
    """Verifies automatic privilege ring assignment per syscall type."""
    step_safe = PlanStep(step_id=1, syscall=SyscallType.FILE_SEARCH, params={})
    assert step_safe.ring == PrivilegeRing.RING_3

    step_priv = PlanStep(step_id=2, syscall=SyscallType.FILE_WRITE, params={"path": "a.txt"})
    assert step_priv.ring == PrivilegeRing.RING_0

    step_proc = PlanStep(step_id=3, syscall=SyscallType.PROC_SPAWN, params={"cmd": ["python", "app.py"]})
    assert step_proc.ring == PrivilegeRing.RING_0


def test_dag_validation_valid():
    """Verifies successful validation of a valid DAG."""
    plan = SyscallPlan(
        user_prompt="Build and run",
        plan_description="Two step pipeline",
        steps=[
            PlanStep(step_id=1, syscall=SyscallType.FILE_SEARCH, params={"pattern": "*.java"}),
            PlanStep(
                step_id=2,
                syscall=SyscallType.PROC_SPAWN,
                params={"cmd": ["javac", "Main.java"]},
                dependencies=[1],
            ),
            PlanStep(
                step_id=3,
                syscall=SyscallType.PROC_SPAWN,
                params={"cmd": ["java", "Main"]},
                dependencies=[2],
            ),
        ],
    )
    plan.validate_dag()
    ordered = plan.get_topological_steps()
    assert [s.step_id for s in ordered] == [1, 2, 3]


def test_dag_validation_duplicate_step_id():
    """Verifies rejection of duplicate step_ids."""
    plan = SyscallPlan(
        user_prompt="Test",
        plan_description="Duplicate IDs",
        steps=[
            PlanStep(step_id=1, syscall=SyscallType.SYS_INFO),
            PlanStep(step_id=1, syscall=SyscallType.FILE_SEARCH),
        ],
    )
    with pytest.raises(PlanValidationError, match="Duplicate step_id"):
        plan.validate_dag()


def test_dag_validation_nonexistent_dependency():
    """Verifies rejection of dependencies referencing non-existent steps."""
    plan = SyscallPlan(
        user_prompt="Test",
        plan_description="Bad dep",
        steps=[
            PlanStep(step_id=1, syscall=SyscallType.SYS_INFO, dependencies=[99]),
        ],
    )
    with pytest.raises(PlanValidationError, match="non-existent step_id"):
        plan.validate_dag()


def test_dag_validation_self_dependency():
    """Verifies rejection of self-referencing step dependency."""
    plan = SyscallPlan(
        user_prompt="Test",
        plan_description="Self loop",
        steps=[
            PlanStep(step_id=1, syscall=SyscallType.SYS_INFO, dependencies=[1]),
        ],
    )
    with pytest.raises(PlanValidationError, match="cannot depend on itself"):
        plan.validate_dag()


def test_dag_validation_cycle_detection():
    """Verifies rejection of circular dependencies."""
    plan = SyscallPlan(
        user_prompt="Cycle",
        plan_description="Circular loop",
        steps=[
            PlanStep(step_id=1, syscall=SyscallType.FILE_SEARCH, dependencies=[3]),
            PlanStep(step_id=2, syscall=SyscallType.FILE_READ, dependencies=[1]),
            PlanStep(step_id=3, syscall=SyscallType.FILE_WRITE, dependencies=[2]),
        ],
    )
    with pytest.raises(PlanValidationError, match="Cyclical dependency detected"):
        plan.validate_dag()


def test_sanitize_proc_spawn_string_cmd():
    """Verifies that string commands are converted to lists of tokens."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": "python script.py --verbose"},
    )
    sanitize_step_params(step)
    assert step.params["cmd"] == ["python", "script.py", "--verbose"]
    assert step.params["timeout"] == 10  # default watchdog timeout added


def test_sanitize_proc_spawn_prohibited_shell_wrapper():
    """Verifies rejection of forbidden shell escape prefixes."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": ["cmd.exe", "/c", "dir"]},
    )
    with pytest.raises(PlanSecurityViolation, match="forbidden shell wrapper"):
        sanitize_step_params(step)

    step_sh = PlanStep(
        step_id=2,
        syscall=SyscallType.PROC_SPAWN,
        params={"cmd": ["sh", "-c", "rm -rf /"]},
    )
    with pytest.raises(PlanSecurityViolation, match="forbidden shell wrapper"):
        sanitize_step_params(step_sh)


def test_sanitize_path_traversal_rejected():
    """Verifies rejection of directory traversal attempts in path arguments."""
    step = PlanStep(
        step_id=1,
        syscall=SyscallType.FILE_READ,
        params={"path": "../../../etc/passwd"},
    )
    with pytest.raises(PlanSecurityViolation, match="Path traversal detected"):
        sanitize_step_params(step)


def test_planner_compile_successful():
    """Verifies end-to-end plan compilation from prompt using mock LLM."""
    mock_payload = {
        "plan_description": "Search Java source code",
        "steps": [
            {
                "step_id": 1,
                "syscall": "FILE_SEARCH",
                "params": {"pattern": "*.java"},
                "ring": 3,
                "description": "Find java files",
                "estimated_duration": 0.2,
                "priority": 15,
                "dependencies": [],
            }
        ],
    }

    client = LLMClient(
        config=LLMConfig(provider=LLMProvider.MOCK),
        mock_handler=lambda p, s: json.dumps(mock_payload),
    )
    planner = AgentPlanner(llm_client=client)

    plan = planner.compile("Find all Java files")
    assert isinstance(plan, SyscallPlan)
    assert plan.plan_description == "Search Java source code"
    assert len(plan.steps) == 1
    assert plan.steps[0].syscall == SyscallType.FILE_SEARCH
    assert plan.metadata["attempts_needed"] == 1


def test_planner_default_mock_provider_returns_explicit_noop_plan():
    """Verifies mock mode compiles a valid no-op instead of invalid empty JSON."""
    client = LLMClient(config=LLMConfig(provider=LLMProvider.MOCK))
    planner = AgentPlanner(llm_client=client)

    plan = planner.compile("Can u open my task manager")

    assert plan.plan_description == (
        "Mock mode is active; no actions were generated or executed."
    )
    assert plan.steps == []
    assert plan.metadata["provider"] == "mock"
    assert plan.metadata["attempts_needed"] == 1


def test_planner_reprompt_recovery_loop():
    """Verifies self-healing recovery loop when initial response is malformed."""
    call_count = 0

    def mock_flaky_llm(prompt: str, system: str | None) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First attempt returns invalid syntax / missing required fields
            return "This is not valid JSON at all!"
        # Second attempt returns valid schema
        return json.dumps({
            "plan_description": "Recovered plan",
            "steps": [
                {
                    "step_id": 1,
                    "syscall": "SYS_INFO",
                    "params": {},
                    "ring": 3,
                    "description": "System hardware info",
                }
            ],
        })

    client = LLMClient(
        config=LLMConfig(provider=LLMProvider.MOCK),
        mock_handler=mock_flaky_llm,
    )
    planner = AgentPlanner(llm_client=client, max_retries=3)

    plan = planner.compile("Check hardware status")
    assert plan.plan_description == "Recovered plan"
    assert plan.metadata["attempts_needed"] == 2
    assert call_count == 2


def test_planner_does_not_retry_llm_request_failures():
    """Verifies provider failures are reported immediately rather than retried."""
    call_count = 0

    def failing_llm(prompt: str, system: str | None) -> str:
        nonlocal call_count
        call_count += 1
        raise LLMClientError("Gemini request timed out")

    client = LLMClient(
        config=LLMConfig(provider=LLMProvider.MOCK),
        mock_handler=failing_llm,
    )
    planner = AgentPlanner(llm_client=client, max_retries=3)

    with pytest.raises(PlanError, match="Language model request failed"):
        planner.compile("Show system information")

    assert call_count == 1


def test_planner_enqueue_to_scheduler():
    """Verifies enqueuing compiled plan steps into TaskScheduler under Priority policy."""
    plan = SyscallPlan(
        user_prompt="Run multi-step pipeline",
        plan_description="Pipeline with priorities",
        steps=[
            PlanStep(
                step_id=1,
                syscall=SyscallType.FILE_SEARCH,
                priority=10,
                estimated_duration=0.5,
            ),
            PlanStep(
                step_id=2,
                syscall=SyscallType.PROC_SPAWN,
                params={"cmd": ["python", "app.py"]},
                priority=50,  # Higher priority
                estimated_duration=3.0,
            ),
            PlanStep(
                step_id=3,
                syscall=SyscallType.SYS_INFO,
                priority=5,
                estimated_duration=0.1,
            ),
        ],
    )

    scheduler = TaskScheduler(policy=SchedulingPolicy.PRIORITY)
    pcb_table = PCBTable()
    planner = AgentPlanner(llm_client=LLMClient(config=LLMConfig(provider=LLMProvider.MOCK)))

    pcbs = planner.enqueue_plan(plan, scheduler=scheduler, pcb_table=pcb_table, starting_pid=100)
    assert len(pcbs) == 3
    # Check that all PCBs are in READY state
    for pcb in pcbs:
        assert pcb.state == ProcessState.READY
        assert pcb_table.get(pcb.pid) is not None

    # Under Priority scheduling, highest priority (50) should be dispatched first
    first = scheduler.next_task()
    assert first is not None
    assert first.priority == 50

    second = scheduler.next_task()
    assert second is not None
    assert second.priority == 10

    third = scheduler.next_task()
    assert third is not None
    assert third.priority == 5


def test_planner_execute_plan_integration(tmp_path):
    """Verifies sequential plan execution through SyscallDispatcher."""
    # Setup test sandbox environment
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()

    plan = SyscallPlan(
        user_prompt="Write file and read it back",
        plan_description="File roundtrip plan",
        steps=[
            PlanStep(
                step_id=1,
                syscall=SyscallType.FILE_WRITE,
                params={"path": "hello.txt", "content": "Hello AgentOS Phase 4!"},
                ring=PrivilegeRing.RING_0,
            ),
            PlanStep(
                step_id=2,
                syscall=SyscallType.FILE_READ,
                params={"path": "hello.txt"},
                ring=PrivilegeRing.RING_3,
                dependencies=[1],
            ),
        ],
    )

    gate = PrivilegeGate(enable_ring0_prompt=False)
    from kernel.file_engine import FileEngine
    file_engine = FileEngine(sandbox_root=sandbox_dir)
    dispatcher = SyscallDispatcher(privilege_gate=gate, file_engine=file_engine)

    planner = AgentPlanner(llm_client=LLMClient(config=LLMConfig(provider=LLMProvider.MOCK)))
    results = planner.execute_plan(plan, dispatcher=dispatcher, user_confirmed=True)

    assert len(results) == 2
    assert results[0].success is True
    assert results[1].success is True
    assert "Hello AgentOS Phase 4!" in (results[1].output or "")


def test_diamond_dag_topological_sort():
    """Verifies topological sorting for a diamond dependency graph."""
    # 1 -> 2, 1 -> 3, (2, 3) -> 4
    plan = SyscallPlan(
        user_prompt="Diamond task",
        plan_description="Diamond execution graph",
        steps=[
            PlanStep(step_id=1, syscall=SyscallType.FILE_SEARCH, params={"pattern": "*.py"}),
            PlanStep(step_id=2, syscall=SyscallType.FILE_READ, params={"path": "a.py"}, dependencies=[1]),
            PlanStep(step_id=3, syscall=SyscallType.FILE_READ, params={"path": "b.py"}, dependencies=[1]),
            PlanStep(step_id=4, syscall=SyscallType.PROC_SPAWN, params={"cmd": ["python", "main.py"]}, dependencies=[2, 3]),
        ],
    )
    ordered = plan.get_topological_steps()
    ids = [s.step_id for s in ordered]
    assert ids[0] == 1
    assert ids[-1] == 4
    assert set(ids[1:3]) == {2, 3}


def test_few_shot_examples_are_valid_schemas():
    """Verifies that all FEW_SHOT_EXAMPLES in prompts.py conform to SyscallPlan."""
    from agent.prompts import FEW_SHOT_EXAMPLES

    for ex in FEW_SHOT_EXAMPLES:
        raw_plan = ex["plan"]
        raw_plan["user_prompt"] = ex["user_request"]
        plan = SyscallPlan(**raw_plan)
        plan.validate_dag()
        assert len(plan.steps) > 0


def test_build_planning_prompt_with_context():
    """Verifies prompt construction with environmental context."""
    from agent.prompts import build_planning_prompt

    ctx = {
        "existing_files": ["Main.java", "test.py"],
        "cwd": "assignment_1",
        "last_error": "Class not found",
    }
    prompt = build_planning_prompt("Fix compile error", context=ctx)
    assert 'USER REQUEST: "Fix compile error"' in prompt
    assert "Main.java" in prompt
    assert "assignment_1" in prompt
    assert "Class not found" in prompt


def test_planner_exhausted_retries_raises_error():
    """Verifies PlanError raised when LLM repeatedly returns invalid output."""
    client = LLMClient(
        config=LLMConfig(provider=LLMProvider.MOCK),
        mock_handler=lambda p, s: "Invalid response garbage",
    )
    planner = AgentPlanner(llm_client=client, max_retries=2)

    with pytest.raises(PlanError, match="Failed to compile plan after 2 attempts"):
        planner.compile("Something impossible")


def test_sanitize_step_params_unescapes_literal_newlines():
    """Verifies that sanitize_step_params unescapes literal \n sequences in FILE_WRITE."""
    from agent.planner import sanitize_step_params

    step = PlanStep(
        step_id=1,
        syscall=SyscallType.FILE_WRITE,
        params={"path": "script.py", "content": "import sys\\nprint('hi')\\n"},
    )
    sanitize_step_params(step)
    assert step.params["content"] == "import sys\nprint('hi')\n"

