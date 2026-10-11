"""System Instructions, Prompt Templates, and JSON Schemas for AgentOS LLM Shell.

Defines the Cognitive Shell's interface with language models, enforcing structured
System Call DAG emission, parameter constraints, and security boundaries.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from kernel.syscalls import DEFAULT_SYSCALL_RINGS, PrivilegeRing, SyscallType

# Formal JSON Schema defining the expected output of the Cognitive Planner
PLAN_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SyscallPlan",
    "description": "Deterministic System Call Directed Acyclic Graph emitted by AgentOS Shell",
    "type": "object",
    "required": ["plan_description", "steps"],
    "properties": {
        "plan_description": {
            "type": "string",
            "description": "Concise summary of the planned operating system operations.",
        },
        "steps": {
            "type": "array",
            "description": "Ordered or DAG-linked system call execution steps.",
            "items": {
                "type": "object",
                "required": ["step_id", "syscall", "params"],
                "properties": {
                    "step_id": {
                        "type": "integer",
                        "description": "Unique 1-based sequential step identifier.",
                    },
                    "syscall": {
                        "type": "string",
                        "enum": [s.value for s in SyscallType],
                        "description": "Micro-Supervisor system call primitive.",
                    },
                    "params": {
                        "type": "object",
                        "description": "Arguments tailored to the designated system call.",
                    },
                    "ring": {
                        "type": "integer",
                        "enum": [0, 3],
                        "description": "Privilege ring: 3 (Unprivileged/Safe) or 0 (Privileged/Destructive).",
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable explanation of this individual step.",
                    },
                    "estimated_duration": {
                        "type": "number",
                        "description": "Estimated execution duration in seconds for Shortest Job First scheduling.",
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Priority weight (1-100, where higher numbers execute sooner in Priority scheduling).",
                    },
                    "dependencies": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of step_ids that must finish before this step runs.",
                    },
                },
            },
        },
    },
}

# Master System Prompt instructing the LLM to behave as a user-space OS Command Interpreter
SYSTEM_PROMPT: str = f"""You are the Cognitive Command Interpreter (LLM Shell) of AgentOS, a user-space micro-supervisor.
Your purpose is to translate user natural-language requests into a deterministic, validated sequence of System Calls (a Syscall Plan).

You do NOT execute commands yourself. You compile instructions into a structured JSON execution plan for the Micro-Supervisor Kernel.

=== AVAILABLE SYSTEM CALLS ===
1. FILE_SEARCH (Ring 3 - Safe):
   - Search for files matching a glob pattern inside the sandboxed workspace.
   - Params:
     * "pattern": string (e.g. "*.java", "*.py", "data/*.txt", default "*")
     * "relative_to": string (optional subdirectory within sandbox)
     * "max_results": integer (optional, default 100)

2. FILE_READ (Ring 3 - Safe):
   - Read content from a file within the sandbox.
   - Params:
     * "path": string (relative path inside sandbox)
     * "max_bytes": integer (optional, default 1048576)
     * "encoding": string (optional, default "utf-8")

3. FILE_WRITE (Ring 0 - Privileged):
   - Create or overwrite/append a file inside the sandbox.
   - Params:
     * "path": string (relative path inside sandbox)
     * "content": string (file contents to write)
     * "mode": string ("w" for write/overwrite, "a" for append, default "w")
     * "encoding": string (optional, default "utf-8")

4. FILE_MOVE (Ring 0 - Privileged):
   - Rename or move a file/directory within the sandbox.
   - Params:
     * "src": string (source path)
     * "dest": string (destination path)

5. FILE_DELETE (Ring 0 - Privileged):
   - Delete or quarantine a file.
   - Params:
     * "path": string (path to delete)
     * "quarantine": boolean (true moves to .agentos_trash/ for safe undo; default true)

6. PROC_SPAWN (Ring 0 - Privileged):
   - Spawn a monitored subprocess with an active watchdog timer and memory cap.
   - Params:
     * "cmd": list of strings (e.g. ["python", "script.py"] or ["javac", "Main.java"])
     * "timeout": integer (optional execution timeout in seconds, default 10)
     * "cwd": string (optional working directory within sandbox)
     * "memory_limit_mb": integer (optional ceiling, default 512)

7. PROC_KILL (Ring 0 - Privileged):
   - Terminate an active process tree by PID.
   - Params:
     * "pid": integer (PID to kill)

8. SYS_INFO (Ring 3 - Safe):
   - Retrieve host CPU count, platform info, and memory diagnostics.
   - Params: {{}} (empty object)

=== PRIVILEGE RINGS ===
- Ring 3 (Unprivileged / Safe): Read-only operations (FILE_SEARCH, FILE_READ, SYS_INFO). Executed automatically.
- Ring 0 (Privileged / Destructive): File mutations and subprocess execution (FILE_WRITE, FILE_MOVE, FILE_DELETE, PROC_SPAWN, PROC_KILL). Requires human elevation or supervisor confirmation.

=== SECURITY MANDATES ===
1. NEVER invoke arbitrary shell wrapper commands such as ["cmd.exe", "/c", ...], ["powershell", "-command", ...], or ["sh", "-c", ...].
2. The "cmd" parameter in PROC_SPAWN MUST always be an array of discrete arguments with the direct approved executable (e.g. ["python", "app.py"], ["javac", "Main.java"], ["java", "Main"]).
3. NEVER reference paths outside the sandbox (e.g., no "../", no absolute paths outside the workspace).
4. For multi-step workflows where step B depends on step A (such as compile -> run), set "dependencies": [A] on step B.
5. Provide reasonable "estimated_duration" (seconds) for Shortest Job First scheduling (e.g. 0.1 for FILE_SEARCH, 1.0 for compilation, 2.0 for execution).
6. Provide reasonable "priority" (1-100) for Priority scheduling.

=== OUTPUT FORMAT ===
You MUST reply with ONLY a raw JSON object matching this schema. Do not enclose in conversational prose.
Do NOT output markdown commentary before or after the JSON.

```json
{{
  "plan_description": "Brief description of what this plan accomplishes",
  "steps": [
    {{
      "step_id": 1,
      "syscall": "FILE_SEARCH",
      "params": {{"pattern": "*.java"}},
      "ring": 3,
      "description": "Find all Java source files",
      "estimated_duration": 0.2,
      "priority": 10,
      "dependencies": []
    }},
    {{
      "step_id": 2,
      "syscall": "PROC_SPAWN",
      "params": {{"cmd": ["javac", "Main.java"], "timeout": 10}},
      "ring": 0,
      "description": "Compile Main.java into bytecode",
      "estimated_duration": 1.5,
      "priority": 20,
      "dependencies": [1]
    }},
    {{
      "step_id": 3,
      "syscall": "PROC_SPAWN",
      "params": {{"cmd": ["java", "Main"], "timeout": 5}},
      "ring": 0,
      "description": "Execute compiled Java application with 5s watchdog timeout",
      "estimated_duration": 2.0,
      "priority": 30,
      "dependencies": [2]
    }}
  ]
}}
```
"""


FEW_SHOT_EXAMPLES: list[dict[str, Any]] = [
    {
        "user_request": "Find all Java files, compile Main.java, and run it with a 5-second timeout.",
        "plan": {
            "plan_description": "Locate Java source files, compile Main.java, and execute bytecode with a 5s timeout guard",
            "steps": [
                {
                    "step_id": 1,
                    "syscall": "FILE_SEARCH",
                    "params": {"pattern": "*.java"},
                    "ring": 3,
                    "description": "Locate Java files in sandbox",
                    "estimated_duration": 0.2,
                    "priority": 10,
                    "dependencies": [],
                },
                {
                    "step_id": 2,
                    "syscall": "PROC_SPAWN",
                    "params": {"cmd": ["javac", "Main.java"], "timeout": 10},
                    "ring": 0,
                    "description": "Compile Main.java",
                    "estimated_duration": 1.5,
                    "priority": 20,
                    "dependencies": [1],
                },
                {
                    "step_id": 3,
                    "syscall": "PROC_SPAWN",
                    "params": {"cmd": ["java", "Main"], "timeout": 5},
                    "ring": 0,
                    "description": "Execute Main class under 5s watchdog",
                    "estimated_duration": 2.0,
                    "priority": 30,
                    "dependencies": [2],
                },
            ],
        },
    },
    {
        "user_request": "Create a Python script named fibonacci.py that prints the first 10 numbers, then run it.",
        "plan": {
            "plan_description": "Create fibonacci script and execute it via Python interpreter",
            "steps": [
                {
                    "step_id": 1,
                    "syscall": "FILE_WRITE",
                    "params": {
                        "path": "fibonacci.py",
                        "content": "a, b = 0, 1\nfor _ in range(10):\n    print(a, end=' ')\n    a, b = b, a + b\nprint()\n",
                        "mode": "w",
                    },
                    "ring": 0,
                    "description": "Write fibonacci.py code",
                    "estimated_duration": 0.5,
                    "priority": 15,
                    "dependencies": [],
                },
                {
                    "step_id": 2,
                    "syscall": "PROC_SPAWN",
                    "params": {"cmd": ["python", "fibonacci.py"], "timeout": 5},
                    "ring": 0,
                    "description": "Execute fibonacci.py with Python",
                    "estimated_duration": 1.0,
                    "priority": 25,
                    "dependencies": [1],
                },
            ],
        },
    },
    {
        "user_request": "Show CPU and memory hardware stats.",
        "plan": {
            "plan_description": "Retrieve host system hardware telemetry",
            "steps": [
                {
                    "step_id": 1,
                    "syscall": "SYS_INFO",
                    "params": {},
                    "ring": 3,
                    "description": "Fetch system information and CPU/RAM statistics",
                    "estimated_duration": 0.1,
                    "priority": 10,
                    "dependencies": [],
                }
            ],
        },
    },
    {
        "user_request": "Clean up all old backup files ending with .bak by moving them to trash.",
        "plan": {
            "plan_description": "Search for .bak files and safely quarantine them",
            "steps": [
                {
                    "step_id": 1,
                    "syscall": "FILE_SEARCH",
                    "params": {"pattern": "*.bak"},
                    "ring": 3,
                    "description": "Search for .bak backup files",
                    "estimated_duration": 0.3,
                    "priority": 10,
                    "dependencies": [],
                },
                {
                    "step_id": 2,
                    "syscall": "FILE_DELETE",
                    "params": {"path": "backup.bak", "quarantine": True},
                    "ring": 0,
                    "description": "Quarantine backup file to .agentos_trash",
                    "estimated_duration": 0.2,
                    "priority": 20,
                    "dependencies": [1],
                },
            ],
        },
    },
]


def build_planning_prompt(
    user_instruction: str,
    context: Optional[dict[str, Any]] = None,
) -> str:
    """Constructs the prompt sent to the LLM Shell for task compilation.

    Args:
        user_instruction: Raw natural language command from the user.
        context: Optional environmental context (active sandbox files, previous outputs).

    Returns:
        Structured user prompt string.
    """
    prompt_lines: list[str] = [
        f"USER REQUEST: \"{user_instruction.strip()}\"",
    ]

    if context:
        prompt_lines.append("\nCURRENT SYSTEM CONTEXT:")
        if "existing_files" in context:
            files = context["existing_files"]
            prompt_lines.append(f"- Workspace files: {', '.join(files[:30])}")
        if "cwd" in context:
            prompt_lines.append(f"- Sandbox directory: {context['cwd']}")
        if "last_error" in context:
            prompt_lines.append(f"- Prior command error: {context['last_error']}")

    prompt_lines.append(
        "\nTranslate this request into an AgentOS Syscall Plan JSON object. "
        "Output ONLY the JSON object."
    )
    return "\n".join(prompt_lines)


def build_reprompt_prompt(
    validation_error: str,
    malformed_output: str,
) -> str:
    """Constructs an error-correction prompt for the LLM self-healing recovery loop.

    Args:
        validation_error: Error message detailing the schema or syntactic violation.
        malformed_output: The previous failed response produced by the model.

    Returns:
        Re-prompt string targeting the specific validation failure.
    """
    truncated_output = malformed_output[:1000] if len(malformed_output) > 1000 else malformed_output
    return (
        "CRITICAL ERROR: Your previous response failed schema validation and could not be compiled.\n\n"
        f"VALIDATION ERROR:\n{validation_error}\n\n"
        f"YOUR PREVIOUS RESPONSE (TRUNCATED):\n{truncated_output}\n\n"
        "INSTRUCTIONS FOR CORRECTION:\n"
        "1. Fix the error above and ensure all required fields ('plan_description', 'steps') are present.\n"
        "2. Ensure every step has 'step_id', 'syscall', and 'params'.\n"
        "3. Ensure 'syscall' is one of: FILE_SEARCH, FILE_READ, FILE_WRITE, FILE_MOVE, FILE_DELETE, PROC_SPAWN, PROC_KILL, SYS_INFO.\n"
        "4. In PROC_SPAWN, ensure 'cmd' is an array of strings (e.g. [\"python\", \"script.py\"]).\n"
        "5. Respond with ONLY the corrected JSON object. Do NOT include markdown commentary."
    )
