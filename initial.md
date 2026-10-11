# AgentOS — Intelligent Agentic Operating Environment

AgentOS is an AI-powered desktop assistant that lets users control selected laptop operations through natural-language instructions. Instead of manually performing every step, users describe the goal and AgentOS plans the actions, executes them through approved tools, and reports the outcome.

> **Project scope:** AgentOS is an application running on an existing operating system—not a replacement for the Windows or Linux kernel. Its initial version focuses on a small set of useful, testable laptop operations.

## Key Features

- **Application control:** Open supported desktop applications and close selected applications where permitted.
- **File management:** Search for files and create, copy, move, or organize files and folders within approved locations.
- **Program execution:** Run supported Python scripts and compile/execute Java programs, then display output and errors.
- **System monitoring:** View CPU and memory usage and inspect processes using system resources.
- **Multi-step task execution:** Turn a request into a sequence of supported actions, execute them in order, and report progress and results.
- **Permission checks:** Confirm potentially destructive or sensitive actions before execution.

The exact applications and operations supported depend on the tools configured in the implementation.

## Example Requests

- “Open VS Code.”
- “Find the Java files in my project folder.”
- “Create a folder named `OS Project` on my Desktop.”
- “Compile and run this Java program.”
- “Show CPU and RAM usage.”
- “Find my OS project, run the Java server, and show me any errors.”

## Project Objectives

1. Provide a natural-language interface for common laptop operations.
2. Translate user requests into structured, executable actions.
3. Support reliable multi-step workflows with progress and result reporting.
4. Demonstrate Operating Systems concepts through practical implementation.
5. Reduce unsafe execution through permissions, input validation, and user confirmation.

## Technology Stack

The planned stack is:

| Component | Technology |
|---|---|
| Main language | Python |
| Desktop interface | PyQt6 |
| Language understanding and planning | LLM API or a compatible local LLM |
| Agent workflow orchestration | LangGraph (optional, depending on implementation) |
| Process and resource monitoring | `psutil` |
| File and path operations | `pathlib`, `shutil`, `os` |
| Program/process execution | `subprocess` |
| Desktop automation, if required | PyAutoGUI |
| Local task history/settings | SQLite |
| Charts/monitoring visuals, if required | PyQtGraph or Matplotlib |
| Version control | Git and GitHub |

Not every dependency is mandatory. Keep the final dependencies aligned with the tools actually used in the source code.

## Operating Systems Concepts

AgentOS connects its implementation to the following OS topics:

- **Process management:** Launching and monitoring child processes, collecting exit codes, and handling termination.
- **Resource monitoring:** Observing CPU and memory usage.
- **File-system operations:** Working with directories and files using controlled paths.
- **Scheduling and task states:** Managing a task queue and tracking tasks as pending, running, completed, failed, or cancelled. Any custom scheduling policy should be documented and evaluated.
- **Inter-process communication (IPC):** Using queues or other IPC mechanisms if work is split across processes.
- **Synchronization:** Preventing conflicting operations on shared resources where concurrent execution is supported.
- **Security and protection:** Applying tool allowlists, path restrictions, command validation, and approval checks.
- **Performance evaluation:** Measuring task completion time, success rate, failures, and resource usage.

Only list a concept as implemented once the corresponding functionality exists in the project.

## High-Level Architecture

```text
User
 |
 v
PyQt6 Desktop Interface
 |
 v
Agent Core
 |
 v
Intent Understanding and Task Planner
 |
 v
Structured Action Plan
 |
 v
Permission and Validation Layer
 |
 v
Approved Tool Executor
 |          |            |
 v          v            v
Files   Applications   Programs
 |
 v
Result Verification and Status Reporting

System Monitor ---> CPU, RAM, and process information
Task History    ---> SQLite (if enabled)
```

### Typical Task Lifecycle

1. Receive a natural-language request.
2. Identify the goal and required operations.
3. Convert the request into a structured action plan.
4. Validate each action and check permissions.
5. Ask for confirmation when an action is sensitive or destructive.
6. Execute supported operations and capture results.
7. Verify the outcome where possible.
8. Report successes, failures, and any steps requiring user intervention.

## Safety and Security

AgentOS can perform real operations on the host laptop, so safety is a core requirement.

- Use an **allowlist of supported tools and actions** rather than executing arbitrary model-generated commands.
- Validate paths and restrict file operations to configured directories.
- Require confirmation before deletion, overwriting, terminating important processes, or other risky actions.
- Never store API keys directly in source code; use environment variables or a suitable secrets mechanism.
- Avoid running the application with administrator/root privileges unless absolutely necessary.
- Apply timeouts and capture standard output, standard error, and exit codes for launched programs.
- Treat content from files and web pages as untrusted input; it must not override system permissions or safety checks.
- Provide a way to cancel a running workflow and log important actions.

These are design goals; the README should be updated to reflect the protections actually implemented.

## Installation

The following is a starter setup. Adjust filenames and dependencies to match the repository.

### Requirements

- Python 3.11 or another version supported by the selected dependencies
- Git
- A supported Windows or Linux environment
- An LLM API key or a compatible local model, if LLM-based planning is enabled

### Setup

```bash
git clone <repository-url>
cd AgentOS

python -m venv .venv
```

Activate the virtual environment:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

**Windows Command Prompt**
```bat
.venv\Scripts\activate.bat
```

**Linux**
```bash
source .venv/bin/activate
```

Install dependencies once `requirements.txt` has been created:

```bash
pip install -r requirements.txt
```

If the project uses an LLM API, configure the required key using an environment variable. For example, in PowerShell:

```powershell
$env:LLM_API_KEY="your-api-key"
```

Use the actual variable name expected by the implementation. Do not commit keys or secrets to Git.

### Run

Once the application entry point has been created, launch it with the relevant command, for example:

```bash
python main.py
```

Replace `main.py` with the actual entry-point filename if different.

## Suggested Project Structure

```text
AgentOS/
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
├── README.md
├── .env.example             # Names of required environment variables; no secrets
├── agent/
│   ├── planner.py            # Request interpretation and task planning
│   └── workflow.py           # Multi-step task coordination
├── tools/
│   ├── applications.py       # Supported application operations
│   ├── files.py              # Safe file operations
│   ├── programs.py           # Program execution
│   └── system_monitor.py     # CPU, RAM, and process information
├── security/
│   ├── permissions.py        # Permission checks and confirmations
│   └── validation.py         # Input and path validation
├── ui/
│   └── dashboard.py          # PyQt6 interface
├── storage/
│   └── history.py            # Optional SQLite task history
└── tests/
    ├── test_files.py
    ├── test_permissions.py
    └── test_workflows.py
```

This is a suggested structure; modules can be simplified or reorganized to fit the final implementation.

## Testing and Evaluation

Test each operation independently before testing full workflows.

| Test | Expected result |
|---|---|
| Open a supported application | Application launches or a clear error is reported |
| Search for a file in an allowed directory | Matching paths are returned |
| Create a folder in an allowed location | Folder is created and verified |
| Run a valid program | Output and exit status are captured |
| Run an invalid program | Error is displayed without crashing AgentOS |
| Request a restricted path operation | Operation is rejected |
| Request a destructive action | Confirmation is required |
| Execute a multi-step workflow | Each step's status and final outcome are reported |
| Inspect system usage | CPU and memory metrics are displayed |

Record task success rate, execution time, failure cases, and CPU/memory overhead. Compare simple single-step tasks with multi-step workflows and include the results in the final report.

## Team Contributions

For a team of up to three members, responsibilities could be divided as follows:

1. **Agent planning and integration:** Natural-language interpretation, task planning, workflow coordination, and LLM integration.
2. **OS tools and monitoring:** File operations, application/program execution, process handling, and resource monitoring.
3. **Interface, safety, and testing:** PyQt6 interface, permission layer, logging, test cases, performance evaluation, and documentation.

All members should contribute to integration, testing, and the final demonstration.

## Limitations

- AgentOS operates through the permissions and capabilities of the host OS; it does not replace the OS kernel.
- It can only perform operations for which a supported tool has been implemented.
- LLM planning can be incorrect, so actions must be validated before execution.
- GUI automation may be affected by screen layout, focus, pop-ups, or application updates.
- Network-based LLM services require connectivity and may have usage costs.
- Some system operations require elevated permissions and should remain out of scope unless specifically justified.

## Future Enhancements

- Voice input and spoken responses
- More application integrations
- Additional workflow templates
- Better task recovery and cancellation
- Sandboxed execution for untrusted programs
- More advanced scheduling and resource-aware execution
- User-configurable permissions and audit history

## Contributors

- Member 1: Name / Registration Number
- Member 2: Name / Registration Number
- Member 3: Name / Registration Number

## License

Add the license selected by the team and permitted by the course requirements.

---

**Academic note:** This README describes the planned project. Update the feature list, architecture, commands, screenshots, dependencies, and test results as implementation progresses. Do not claim a feature is complete until it has been implemented and tested.
