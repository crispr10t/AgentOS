"""Plan Compiler, DAG Validator, and Error Recovery Loop for AgentOS.

Decomposes natural language requests into verified System Call Directed Acyclic Graphs (DAGs),
sanitizes command and file parameters against security policy violations, handles
automatic LLM self-healing re-prompting, and connects directly into the Micro-Supervisor
ready queue.
"""

from __future__ import annotations

from collections import deque
import json
import re
import shlex
import time
from typing import Any, Callable, Optional
import uuid

from pydantic import BaseModel, Field, field_validator

from agent.llm_client import LLMClient, LLMClientError, LLMResponse
from agent.prompts import (
    SYSTEM_PROMPT,
    build_planning_prompt,
    build_reprompt_prompt,
)
from kernel.pcb import ProcessState, TaskPCB
from kernel.process_manager import PROHIBITED_SHELL_PREFIXES
from kernel.scheduler import TaskScheduler
from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)


class PlanError(Exception):
    """Base exception for plan compilation, parsing, or validation failures."""

    pass


class PlanParsingError(PlanError):
    """Raised when the LLM response cannot be parsed as valid JSON."""

    pass


class PlanValidationError(PlanError):
    """Raised when a plan violates schema rules, DAG constraints, or security bounds."""

    pass


class PlanSecurityViolation(PlanError):
    """Raised when a plan contains prohibited shell escapes or path traversal."""

    pass


class PlanStep(BaseModel):
    """Represents an individual node in the System Call execution DAG."""

    step_id: int
    syscall: SyscallType
    params: dict[str, Any] = Field(default_factory=dict)
    ring: PrivilegeRing = PrivilegeRing.RING_3
    description: Optional[str] = None
    estimated_duration: float = 1.0
    priority: int = 10
    dependencies: list[int] = Field(default_factory=list)

    def __init__(self, **data: Any):
        # Automatically assign default ring based on syscall if not provided
        if "ring" not in data and "syscall" in data:
            sc_val = data["syscall"]
            if isinstance(sc_val, str):
                try:
                    sc_val = SyscallType(sc_val)
                except ValueError:
                    pass
            if isinstance(sc_val, SyscallType):
                data["ring"] = DEFAULT_SYSCALL_RINGS.get(sc_val, PrivilegeRing.RING_3)
        super().__init__(**data)

    @field_validator("syscall", mode="before")
    @classmethod
    def _validate_syscall(cls, v: Any) -> SyscallType:
        if isinstance(v, SyscallType):
            return v
        if isinstance(v, str):
            clean = v.strip().upper()
            try:
                return SyscallType(clean)
            except ValueError:
                valid = [s.value for s in SyscallType]
                raise ValueError(f"Unknown syscall '{v}'. Allowed syscalls: {valid}")
        raise ValueError(f"Syscall must be a string or SyscallType enum, got {type(v)}")

    @field_validator("ring", mode="before")
    @classmethod
    def _validate_ring(cls, v: Any) -> PrivilegeRing:
        if isinstance(v, PrivilegeRing):
            return v
        if isinstance(v, int):
            if v in (0, 3):
                return PrivilegeRing(v)
            raise ValueError(f"Invalid privilege ring {v}. Must be 0 or 3.")
        raise ValueError(f"Invalid ring type: {type(v)}")

    def to_syscall_request(self) -> SyscallRequest:
        """Converts this step into a kernel SyscallRequest packet."""
        return SyscallRequest(
            call_id=str(uuid.uuid4()),
            syscall=self.syscall,
            params=self.params,
            ring=self.ring,
        )

    def to_pcb(self, pid: int) -> TaskPCB:
        """Instantiates a corresponding TaskPCB for scheduler tracking."""
        name = self.description or f"Step {self.step_id}: {self.syscall.value}"
        return TaskPCB(
            pid=pid,
            name=name,
            state=ProcessState.NEW,
            priority=self.priority,
            estimated_duration=self.estimated_duration,
        )


class SyscallPlan(BaseModel):
    """Complete multi-step execution plan representing a verified Syscall DAG."""

    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_prompt: str
    plan_description: str
    steps: list[PlanStep] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def validate_dag(self) -> None:
        """Validates that step dependencies form an acyclic directed graph (DAG).

        Raises:
            PlanValidationError: If step IDs are duplicate, dependencies reference
                                non-existent steps, or cyclical dependencies exist.
        """
        step_ids = set()
        step_map: dict[int, PlanStep] = {}

        for step in self.steps:
            if step.step_id in step_ids:
                raise PlanValidationError(
                    f"Duplicate step_id {step.step_id} detected in plan."
                )
            step_ids.add(step.step_id)
            step_map[step.step_id] = step

        # Verify dependency existence
        for step in self.steps:
            for dep_id in step.dependencies:
                if dep_id not in step_map:
                    raise PlanValidationError(
                        f"Step {step.step_id} depends on non-existent step_id {dep_id}."
                    )
                if dep_id == step.step_id:
                    raise PlanValidationError(
                        f"Step {step.step_id} cannot depend on itself."
                    )

        # Cycle detection using Kahn's algorithm (topological sort)
        in_degree: dict[int, int] = {s.step_id: 0 for s in self.steps}
        adjacency: dict[int, list[int]] = {s.step_id: [] for s in self.steps}

        for step in self.steps:
            for dep_id in step.dependencies:
                adjacency[dep_id].append(step.step_id)
                in_degree[step.step_id] += 1

        queue = deque([sid for sid, deg in in_degree.items() if deg == 0])
        visited_count = 0

        while queue:
            curr = queue.popleft()
            visited_count += 1
            for neighbor in adjacency[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if visited_count != len(self.steps):
            raise PlanValidationError(
                "Cyclical dependency detected in plan steps. Steps must form a DAG."
            )

    def get_topological_steps(self) -> list[PlanStep]:
        """Returns the plan steps sorted in a valid topological execution order."""
        self.validate_dag()
        step_map = {s.step_id: s for s in self.steps}
        in_degree: dict[int, int] = {s.step_id: len(s.dependencies) for s in self.steps}
        adjacency: dict[int, list[int]] = {s.step_id: [] for s in self.steps}

        for step in self.steps:
            for dep in step.dependencies:
                adjacency[dep].append(step.step_id)

        # Deterministic sort: initial nodes with 0 in-degree, sorted by step_id
        queue = sorted([sid for sid, deg in in_degree.items() if deg == 0])
        ordered: list[PlanStep] = []

        while queue:
            curr_id = queue.pop(0)
            ordered.append(step_map[curr_id])
            for neighbor in sorted(adjacency[curr_id]):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
            queue.sort()

        return ordered

    def to_syscall_requests(self) -> list[SyscallRequest]:
        """Converts all steps in topological order to kernel SyscallRequests."""
        return [step.to_syscall_request() for step in self.get_topological_steps()]

    def to_pcbs(self, starting_pid: int = 100) -> list[TaskPCB]:
        """Converts all steps in topological order to TaskPCBs."""
        pcbs: list[TaskPCB] = []
        for i, step in enumerate(self.get_topological_steps()):
            pcbs.append(step.to_pcb(pid=starting_pid + i))
        return pcbs


def extract_json_payload(raw_text: str) -> dict[str, Any]:
    """Extracts and parses a JSON object from raw LLM output.

    Handles leading/trailing prose and markdown code block wrappers
    (```json ... ```).

    Args:
        raw_text: Unprocessed LLM response string.

    Returns:
        Parsed dictionary.

    Raises:
        PlanParsingError: If no valid JSON structure could be extracted.
    """
    clean = raw_text.strip()

    # 1. Strip markdown fences if present
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", clean, re.DOTALL | re.IGNORECASE)
    if match:
        clean = match.group(1).strip()

    # 2. Direct JSON load attempt
    try:
        data = json.loads(clean)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 3. Locate outermost curly braces {}
    first_brace = clean.find("{")
    last_brace = clean.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        snippet = clean[first_brace : last_brace + 1]
        try:
            data = json.loads(snippet)
            if isinstance(data, dict):
                return data
        except Exception as err:
            raise PlanParsingError(
                f"Failed to parse extracted JSON substring: {err}"
            ) from err

    raise PlanParsingError(
        f"No valid JSON object could be extracted from LLM response: {raw_text[:200]}..."
    )


def sanitize_step_params(step: PlanStep) -> None:
    """Sanitizes step parameters to enforce security boundaries and type invariants.

    Args:
        step: PlanStep to sanitize in place.

    Raises:
        PlanSecurityViolation: If malicious command prefixes or path escapes are detected.
    """
    params = step.params

    # 1. Subprocess command sanitization
    if step.syscall == SyscallType.PROC_SPAWN:
        cmd = params.get("cmd")
        if isinstance(cmd, str):
            # Convert single string command into discrete argument list
            cmd = shlex.split(cmd)
            params["cmd"] = cmd

        if not isinstance(cmd, list) or not cmd:
            raise PlanSecurityViolation(
                f"PROC_SPAWN step {step.step_id} must have a non-empty list of command tokens."
            )

        # Check for prohibited shell wrapper injections (e.g. ['cmd.exe', '/c'])
        cmd_lower = [str(t).lower() for t in cmd]
        for prefix in PROHIBITED_SHELL_PREFIXES:
            if len(cmd_lower) >= len(prefix) and cmd_lower[: len(prefix)] == prefix:
                # Disallow arbitrary shell wrappers
                raise PlanSecurityViolation(
                    f"PROC_SPAWN in step {step.step_id} uses forbidden shell wrapper: {' '.join(prefix)}. "
                    f"Direct approved executables must be used."
                )

        # Ensure default timeout is set
        if "timeout" not in params and "timeout_sec" not in params:
            params["timeout"] = 10

    # 2. Filesystem path sanitization
    path_keys = ["path", "src", "dest"]
    for pk in path_keys:
        if pk in params and isinstance(params[pk], str):
            val = params[pk].strip()
            # Reject blatant directory traversal attempts
            if "../" in val or "..\\" in val or val.startswith(".."):
                raise PlanSecurityViolation(
                    f"Path traversal detected in step {step.step_id} ('{pk}': '{val}'). "
                    f"All paths must be contained within the sandbox root."
                )


class AgentPlanner:
    """Cognitive Shell compiler that turns natural language into validated Syscall Plans."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        max_retries: int = 3,
        auto_sanitize: bool = True,
    ):
        """Initializes the AgentPlanner.

        Args:
            llm_client: LLMClient instance. Defaults to standard configuration.
            max_retries: Maximum self-healing re-prompt attempts if validation fails.
            auto_sanitize: Whether to automatically sanitize command & path parameters.
        """
        self.llm_client = llm_client or LLMClient()
        self.max_retries = max(1, int(max_retries))
        self.auto_sanitize = auto_sanitize

    def compile(
        self,
        user_instruction: str,
        context: Optional[dict[str, Any]] = None,
    ) -> SyscallPlan:
        """Compiles a user's natural language request into a validated SyscallPlan.

        Implements an automatic self-healing recovery loop that re-prompts the LLM
        with error feedback if syntactic or semantic validation fails.

        Args:
            user_instruction: Raw natural language instruction.
            context: Optional workspace state dictionary.

        Returns:
            Validated and sanitized SyscallPlan instance.

        Raises:
            PlanError: If compilation fails after exhausting retry budget.
        """
        if not user_instruction or not user_instruction.strip():
            raise PlanError("User instruction cannot be empty.")

        planning_prompt = build_planning_prompt(user_instruction, context)
        last_error_msg = ""
        last_raw_response = ""

        for attempt in range(self.max_retries):
            try:
                # 1. Determine active prompt (initial or re-prompt)
                if attempt == 0:
                    current_prompt = planning_prompt
                else:
                    current_prompt = build_reprompt_prompt(
                        validation_error=last_error_msg,
                        malformed_output=last_raw_response,
                    )

                # 2. Invoke LLM Shell
                llm_resp: LLMResponse = self.llm_client.generate(
                    prompt=current_prompt,
                    system=SYSTEM_PROMPT,
                    format_json=True,
                )
                last_raw_response = llm_resp.content

                # 3. Extract and parse JSON
                raw_dict = extract_json_payload(llm_resp.content)

                # Ensure user_prompt is populated
                if "user_prompt" not in raw_dict:
                    raw_dict["user_prompt"] = user_instruction.strip()

                # 4. Instantiate and validate Pydantic model
                plan = SyscallPlan(**raw_dict)

                # 5. Sanitize steps if enabled
                if self.auto_sanitize:
                    for step in plan.steps:
                        sanitize_step_params(step)

                # 6. Validate DAG invariants
                plan.validate_dag()

                # Attach compilation metadata
                plan.metadata["provider"] = llm_resp.provider
                plan.metadata["model"] = llm_resp.model
                plan.metadata["generation_duration_sec"] = llm_resp.duration_sec
                plan.metadata["attempts_needed"] = attempt + 1
                plan.metadata["fallback_occurred"] = llm_resp.fallback_occurred

                return plan

            except LLMClientError as exc:
                raise PlanError(f"Language model request failed: {exc}") from exc
            except Exception as exc:
                last_error_msg = f"{type(exc).__name__}: {exc}"
                if attempt == self.max_retries - 1:
                    raise PlanError(
                        f"Failed to compile plan after {self.max_retries} attempts. "
                        f"Last error: {last_error_msg}"
                    ) from exc

        raise PlanError(f"Plan compilation failed: {last_error_msg}")

    def enqueue_plan(
        self,
        plan: SyscallPlan,
        scheduler: TaskScheduler,
        pcb_table: Optional[Any] = None,
        starting_pid: int = 100,
    ) -> list[TaskPCB]:
        """Translates a SyscallPlan into TaskPCBs and enqueues them into the TaskScheduler.

        Args:
            plan: Validated SyscallPlan.
            scheduler: Kernel TaskScheduler ready queue.
            pcb_table: Optional central PCBTable for global registry tracking.
            starting_pid: Base PID counter for generated PCBs.

        Returns:
            List of enqueued TaskPCBs in READY state.
        """
        pcbs = plan.to_pcbs(starting_pid=starting_pid)

        for pcb in pcbs:
            # Register in central PCBTable if provided
            if pcb_table is not None:
                pcb_table.register(pcb)

            # Enqueue transitions pcb state from NEW -> READY
            scheduler.enqueue(pcb)

        return pcbs

    def execute_plan(
        self,
        plan: SyscallPlan,
        dispatcher: SyscallDispatcher,
        user_confirmed: bool = False,
        stop_on_error: bool = True,
        on_step_start: Optional[Callable[[PlanStep, Optional[TaskPCB]], None]] = None,
        on_step_complete: Optional[Callable[[PlanStep, SyscallResult], None]] = None,
    ) -> list[SyscallResult]:
        """Executes a SyscallPlan sequentially through the Micro-Supervisor dispatcher.

        Args:
            plan: Validated SyscallPlan.
            dispatcher: Kernel SyscallDispatcher instance.
            user_confirmed: True if Ring 0 operations are pre-authorized by user.
            stop_on_error: If True, halts execution upon any failed system call.
            on_step_start: Optional callback before each step execution.
            on_step_complete: Optional callback after each step execution.

        Returns:
            List of SyscallResults corresponding to each executed step.
        """
        ordered_steps = plan.get_topological_steps()
        results: list[SyscallResult] = []

        for i, step in enumerate(ordered_steps):
            pcb = step.to_pcb(pid=200 + i)
            req = step.to_syscall_request()

            if on_step_start:
                on_step_start(step, pcb)

            res = dispatcher.dispatch(
                request=req,
                pcb=pcb,
                user_confirmed=user_confirmed,
            )
            results.append(res)

            if on_step_complete:
                on_step_complete(step, res)

            if not res.success and stop_on_error:
                break

        return results


# Convenient alias matching plan terminology
PlanCompiler = AgentPlanner
