# AgentOS — Viva Defense & Live Demonstration Guide

This guide is designed for candidates presenting **AgentOS** before examiners during the academic project defense. It contains a **5-minute timed live demonstration script**, complete step-by-step instructions for all 6 core demo scenarios, and an exhaustive **Viva Examination Q&A Bank**.

---

## Table of Contents

- [5-Minute Live Demonstration Timeline](#5-minute-live-demonstration-timeline)
- [Step-by-Step Demonstration Scenarios](#step-by-step-demonstration-scenarios)
  - [Demo 1: Multi-Step Task Compilation & PCB Tracking](#demo-1-multi-step-task-compilation--pcb-tracking)
  - [Demo 2: Process Watchdog Catching an Infinite Loop](#demo-2-process-watchdog-catching-an-infinite-loop)
  - [Demo 3: Ring 0 Privilege Elevation Gate](#demo-3-ring-0-privilege-elevation-gate)
  - [Demo 4: Transactional Undo Recovery from Trash](#demo-4-transactional-undo-recovery-from-trash)
  - [Demo 5: Scheduling Policy Benchmark & Convoy Effect](#demo-5-scheduling-policy-benchmark--convoy-effect)
  - [Demo 6: 100% Offline Resilience via Local Ollama](#demo-6-100-offline-resilience-via-local-ollama)
- [Comprehensive Viva Examination Q&A Bank](#comprehensive-viva-examination-qa-bank)

---

## 5-Minute Live Demonstration Timeline

Use this exact timing breakdown during your presentation:

```
[00:00 - 01:00]  Minute 1: The Problem & Live Architecture
                 - Open AgentOS desktop GUI (`python main.py`).
                 - Explain three-tier architecture: Cognitive Shell -> Supervisor Kernel -> Host OS.
                 - Highlight the Live Process Table (PCB), Telemetry Gauges, and Streaming Console.

[01:00 - 02:00]  Minute 2: Demo 1 (Compilation) & Demo 2 (Infinite Loop Watchdog)
                 - Submit a multi-step build instruction; point out PCB state transitions: NEW -> RUNNING -> TERMINATED.
                 - Run `demo_assets/infinite_loop.py` with 3s timeout.
                 - Show watchdog terminating the process tree with `TIMEOUT_EXPIRED` (exit code 124).

[02:00 - 03:00]  Minute 3: Demo 3 (Ring 0 Privilege Separation)
                 - Submit a file deletion command.
                 - Show the interactive Ring 0 Privilege Elevation modal halting execution.
                 - Explain hardware ring analogy (Ring 0 supervisor vs Ring 3 user mode).

[03:00 - 04:00]  Minute 4: Demo 4 (Undo Rollback) & Demo 5 (Scheduling Comparison)
                 - Click "Undo Last Action" to immediately restore the quarantined file from `.agentos_trash/`.
                 - Switch scheduler policy to SJF; explain why SJF eliminates the FCFS Convoy Effect.

[04:00 - 05:00]  Minute 5: Demo 6 (Offline Ollama Fallback) & Conclusion
                 - Show local model fallback (`llama3.2:3b`) operating with no cloud API keys.
                 - Conclude with summary of 134 automated unit/integration tests and academic contributions.
```

---

## Step-by-Step Demonstration Scenarios

### Demo 1: Multi-Step Task Compilation & PCB Tracking

**Objective:** Prove that user prompts compile into typed System Call DAGs and execute under full PCB lifecycle accounting.

1. **Start AgentOS GUI:**
   ```powershell
   python main.py
   ```
2. **Submit Input Prompt:**
   ```text
   Compile and run demo_assets/HelloWorld.java with a 5-second timeout.
   ```
   *(Alternative pure-Python demo prompt: `Execute demo_assets/sample_worker.py 1.5 worker_a`)*
3. **What to Show the Examiner:**
   - In the **Process Table Widget (Left)**: The PCB row appears with state transitioning from `NEW` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `TERMINATED`.
   - The CPU execution time, memory footprint, and exit code (`0`) are recorded in real time.
   - The **Streaming Console (Right)** displays the compilation stdout in green/off-white channels.

---

### Demo 2: Process Watchdog Catching an Infinite Loop

**Objective:** Prove that runaway or hung processes cannot lock up the host system or create orphaned zombie processes.

1. **Submit Input Prompt:**
   ```text
   Run demo_assets/infinite_loop.py with a 3-second timeout.
   ```
2. **What to Show the Examiner:**
   - The process begins executing and enters its non-terminating busy loop.
   - Exactly at $t=3.0\text{s}$, the background `ProcessManager` watchdog triggers.
   - The watchdog recursively halts the child process tree via `psutil`.
   - The PCB badge updates to `TERMINATED` with exit code `124` and error status `TIMEOUT_EXPIRED`.
   - Point out that AgentOS GUI remains fully responsive at 60 FPS throughout the termination.

---

### Demo 3: Ring 0 Privilege Elevation Gate

**Objective:** Prove that unvetted or destructive operations cannot execute autonomously without explicit user elevation.

1. **Create a Test File in Sandbox:**
   ```powershell
   python -c "import pathlib; pathlib.Path('sandbox_workspace/temp_notes.txt').write_text('Sensitive notes')"
   ```
2. **Submit Input Prompt:**
   ```text
   Delete temp_notes.txt from the workspace.
   ```
3. **What to Show the Examiner:**
   - Execution immediately halts and displays the **Ring 0 Privilege Elevation Modal Dialog**.
   - Show the examiner the highlighted syscall type (`FILE_DELETE`), canonical target path, and risk warning badge.
   - Click **Reject**: Execution terminates with `PERMISSION_DENIED` (exit code `126`) and logs an audit failure.
   - Run again and click **Approve**: Execution proceeds, deleting the file with user consent.

---

### Demo 4: Transactional Undo Recovery from Trash

**Objective:** Demonstrate write-ahead transaction logging and 1-click disaster recovery.

1. **Context:** After deleting `temp_notes.txt` in Demo 3:
2. **Action:** Click the **"↺ Undo"** button in the top toolbar (or press `Ctrl+Z`).
3. **What to Show the Examiner:**
   - The console displays:
     ```text
     [UNDO] Restored 'temp_notes.txt' from quarantine.
     ```
   - Show that the file is instantly restored in `sandbox_workspace/` with its original content intact.
   - Explain how `.agentos_trash/` isolates quarantined files with timestamped UUID prefixes.

---

### Demo 5: Scheduling Policy Benchmark & Convoy Effect

**Objective:** Demonstrate theoretical and empirical differences between FCFS, Priority, and SJF scheduling.

1. **Run the Benchmark CLI Tool:**
   ```powershell
   python benchmark_scheduler.py --format table
   ```
2. **What to Show the Examiner:**
   - Show the 5-task synthetic batch:
     - `heavy_compile` ($12.0\text{s}$, Priority 1)
     - `quick_lint` ($1.5\text{s}$, Priority 5)
     - `unit_tests` ($4.0\text{s}$, Priority 8)
     - `clean_cache` ($0.5\text{s}$, Priority 2)
     - `security_audit` ($3.0\text{s}$, Priority 10)
   - Point out the metrics:
     - **FCFS**: Average Waiting Time = $12.20\text{s}$ (Suffers from the **Convoy Effect**).
     - **Priority**: Critical task `security_audit` dispatched first ($W=0.00\text{s}$).
     - **SJF**: Average Waiting Time = $3.30\text{s}$ (**73.0% latency reduction**).
3. **Export Markdown Report:**
   ```powershell
   python benchmark_scheduler.py --format markdown
   ```

---

### Demo 6: 100% Offline Resilience via Local Ollama

**Objective:** Prove that AgentOS operates entirely without external cloud internet access.

1. **Verify Ollama Configuration in `.env`:**
   ```ini
   LLM_PROVIDER=ollama
   OLLAMA_MODEL=llama3.2:3b
   OLLAMA_HOST=http://localhost:11434
   ```
2. **Demonstration Action:**
   - Disconnect Wi-Fi or run with no `GEMINI_API_KEY`.
   - Submit prompt: *"List all files in the sandbox directory."*
   - Show the plan compiling locally via Ollama in under 800ms.

---

## Comprehensive Viva Examination Q&A Bank

### Section A: Core OS Concepts & Architecture

#### Q1: "How is this an Operating Systems project rather than a standard AI agent wrapper?"
> **Answer:** *"Conventional AI agents are merely Python scripts that pass unbounded strings into `bash` or `cmd.exe`. AgentOS implements fundamental OS abstractions in user space:
> 1. It acts as a micro-supervisor kernel mediating every request into typed system calls.
> 2. It tracks tasks via formal Process Control Blocks (PCBs) with explicit 5-state finite-state machines.
> 3. It schedules tasks using deterministic OS queue algorithms (FCFS, Priority, SJF).
> 4. It enforces dual-mode privilege rings (Ring 0 vs. Ring 3) and canonical sandboxing.
> 5. It supervises processes with watchdog timers and recursive tree termination.
> The LLM functions merely as the Command Interpreter (the cognitive equivalent of bash or zsh), while our kernel handles execution, protection, and resource allocation."*

#### Q2: "What is a Process Control Block (PCB) in AgentOS and what information does it store?"
> **Answer:** *"Defined in `kernel/pcb.py` as `TaskPCB`, it is an in-memory data structure tracking:
> - Process Identifiers: PID and optional PPID.
> - State: The current lifecycle state (`NEW`, `READY`, `RUNNING`, `WAITING`, `TERMINATED`).
> - Priority: Integer from 1 to 10 used by the Priority Scheduler.
> - Timing & Accounting: `created_at`, `started_at`, `ended_at`, Turnaround Time ($T_{\text{ended}} - T_{\text{created}}$), and Waiting Time ($T_{\text{started}} - T_{\text{created}}$).
> - Resource Usage: Cumulative CPU execution time and peak RAM footprint sampled via `psutil`.
> - Outcome: Subprocess exit code and error diagnostics."*

#### Q3: "What is the Convoy Effect, and how does your project demonstrate it?"
> **Answer:** *"The Convoy Effect occurs under First-Come, First-Served (FCFS) scheduling when a long CPU-burst process arrives before short processes, forcing all short processes to wait behind it.
> In our benchmark (`benchmark_scheduler.py`), a 12-second `heavy_compile` task arrives first. Under FCFS, short tasks (like `clean_cache` taking 0.5s) experience an average waiting time of 12.20s. When switched to Shortest Job First (SJF), short tasks run first, dropping average waiting time to 3.30s—a 73.0% reduction. The Convoy Penalty Ratio is 3.7x."*

#### Q4: "Is Shortest Job First (SJF) always optimal? What is its main limitation in real operating systems?"
> **Answer:** *"SJF is mathematically proven to minimize average waiting time for non-preemptive batches arriving simultaneously. However, its primary practical challenge in real-world general-purpose OS kernels is knowing the exact burst time in advance. In AgentOS, our Cognitive Shell estimates burst duration heuristically based on the system call type (e.g., `FILE_SEARCH` $\approx 0.5\text{s}$, `PROC_SPAWN` compilation $\approx 5.0\text{s}$). The second limitation is Starvation: continuous arrival of short jobs can indefinitely postpone long jobs. This is mitigated through aging or Priority scheduling."*

---

### Section B: Concurrency, Synchronization & Memory

#### Q5: "What was the Critical Section in your design, and how did you prevent race conditions?"
> **Answer:** *"The central `PCBTable` and the `TaskScheduler` ready queues are shared between multiple threads: the PyQt6 GUI thread (which renders table rows and handles user inputs), the `SupervisorWorker` thread (which compiles plans and executes tasks), and the background `TelemetryDaemon` thread.
> If a worker updates a PCB state at the same instant the GUI queries it, race conditions and data corruption occur. We solved this by encapsulating all queue mutations and PCB table modifications within mutual exclusion locks (`threading.Lock`)."*

#### Q6: "How did you prevent the PyQt6 GUI from freezing during long-running tasks?"
> **Answer:** *"In PyQt6, running blocking operations (like subprocess execution, network requests, or disk I/O) on the main thread locks the Qt Event Loop, making the window unresponsive.
> We decoupled execution by creating a dedicated `QThread` subclass (`SupervisorWorker`). The worker performs all plan compilation, scheduling, and subprocess supervision in the background. It communicates state back to the GUI exclusively through asynchronous Qt Signals (`sig_pcb_updated`, `sig_console_stream`, `sig_telemetry_tick`)."*

#### Q7: "How do you handle zombie processes and orphaned child processes?"
> **Answer:** *"When a subprocess spawns child processes (e.g., a Python script launching background workers) and is killed directly via PID, the children can become orphaned zombies detached from the process tree.
> Our `ProcessManager` uses `psutil.Process(pid).children(recursive=True)` to traverse the full process tree. When a timeout occurs, the watchdog terminates all child processes first before terminating the parent (`proc.kill()`), guaranteeing no orphaned zombie processes remain on the host."*

---

### Section C: Security & Filesystem Sandboxing

#### Q8: "How does your Dual-Mode Privilege Ring boundary work?"
> **Answer:** *"Analogous to hardware Ring 0 (kernel mode) and Ring 3 (user mode):
> - **Ring 3**: Read-only, safe operations (`FILE_SEARCH`, `FILE_READ`, `SYS_INFO`) execute autonomously without interrupting the user.
> - **Ring 0**: Mutating, destructive, or execution operations (`PROC_SPAWN`, `FILE_WRITE`, `FILE_DELETE`, `FILE_MOVE`) are gated by `PrivilegeGate`.
> When a Ring 0 call is encountered, the supervisor halts and emits `sig_privilege_request`. The GUI displays an interactive modal showing the command and resolved paths. Execution only proceeds if explicit user approval is granted; otherwise, it exits with exit code 126 (`PERMISSION_DENIED`)."*

#### Q9: "How do you prevent path traversal attacks (e.g., `../../../../etc/shadow`)?"
> **Answer:** *"In `security/sandbox.py`, we implement `validate_safe_path()`. Before any filesystem operation is executed, the target path is resolved canonically using `Path.resolve()`, which resolves all symbolic links, relative `..` segments, and Windows short 8.3 filenames.
> It then validates that the resolved absolute path starts with the configured `SANDBOX_ROOT`. If any path traverses outside the jail, a `PermissionError` is raised immediately."*

#### Q10: "How does the Transactional Undo Journal work?"
> **Answer:** *"In `storage/journal.py`, every file mutation is recorded in an SQLite Write-Ahead Log (`file_journal`). When a file deletion is requested, AgentOS does not un-link the file permanently; instead, it relocates it to a hidden `.agentos_trash/` directory with a timestamped UUID.
> When the user clicks 'Undo', the supervisor retrieves the last un-reverted transaction from SQLite, moves the file back to its canonical sandbox path, and marks the transaction as undone."*

---

### Section D: Testing & Verification Metrics

#### Q11: "How did you verify and test your system?"
> **Answer:** *"We built an automated test suite with **134 passing tests across 17 test modules** using `pytest`. The suite tests:
> - PCB state machine transitions and invalid transition rejections.
> - Scheduler dispatch ordering under FCFS, Priority, and SJF.
> - Path traversal penetration attacks.
> - Process watchdog timeouts catching runaway loops.
> - Transactional undo recovery and bit-identical file restoration.
> - Offscreen PyQt6 headless UI integration and worker thread signal delivery."*

#### Q12: "What are the key technical conclusions of this project?"
> **Answer:** *"AgentOS proves that applying classical Operating Systems principles (mediated system calls, process control blocks, dual privilege rings, and deterministic scheduling) provides a robust, provably safe framework for running autonomous AI agents, eliminating the security and stability risks of unconstrained shell execution."*
