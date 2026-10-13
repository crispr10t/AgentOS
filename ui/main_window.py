"""Central PyQt6 Graphical Shell Dashboard for AgentOS.

Integrates the natural language prompt input bar, live Process Control Block
table, streaming console output, hardware telemetry bar, and non-blocking
supervisor worker thread.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Optional

from PyQt6.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from agent.llm_client import LLMClient
from agent.planner import AgentPlanner, SyscallPlan
from kernel.pcb import ProcessState, TaskPCB
from kernel.scheduler import SchedulingPolicy, TaskScheduler
from kernel.sync import PCBTable
from kernel.syscalls import (
    DEFAULT_SYSCALL_RINGS,
    PrivilegeRing,
    SyscallDispatcher,
    SyscallRequest,
    SyscallResult,
    SyscallType,
)
from kernel.telemetry import TelemetryDaemon
from ui.elevation_dialog import ElevationDialog
from ui.pcb_table_widget import PcbTableWidget
from ui.telemetry_widget import TelemetryWidget
from ui.terminal_widget import TerminalWidget


class ElevationBridge(QObject):
    """Synchronization bridge for cross-thread modal elevation dialogs."""

    def __init__(self, request: SyscallRequest):
        super().__init__()
        self.request = request
        self.approved: bool = False
        self.event = threading.Event()


class TelemetryWorker(QThread):
    """Background hardware telemetry worker thread polling psutil and emitting Qt signals."""

    sig_telemetry_tick = pyqtSignal(dict)

    def __init__(
        self,
        daemon: Optional[TelemetryDaemon] = None,
        interval_sec: float = 1.0,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.daemon = daemon or TelemetryDaemon(interval_sec=interval_sec)
        self._stop_requested = threading.Event()

    def run(self) -> None:
        """Continuously samples hardware telemetry at periodic intervals on background thread."""
        while not self._stop_requested.is_set():
            try:
                metrics = self.daemon.sample()
                self.sig_telemetry_tick.emit(metrics)
            except Exception:
                pass
            self._stop_requested.wait(timeout=self.daemon.interval_sec)

    def stop(self, timeout_ms: int = 1500) -> None:
        """Requests thread stop and waits for exit."""
        self._stop_requested.set()
        if self.isRunning():
            self.wait(timeout_ms)


class SupervisorWorker(QThread):
    """Dedicated background worker executing Agent planning and Kernel dispatching."""

    sig_pcb_updated = pyqtSignal(object)              # TaskPCB
    sig_console_stream = pyqtSignal(str, str)         # text, channel
    sig_privilege_request = pyqtSignal(object)        # ElevationBridge
    sig_status_updated = pyqtSignal(str)              # status message
    sig_plan_compiled = pyqtSignal(object)            # SyscallPlan
    sig_execution_finished = pyqtSignal(bool, str)    # success, summary message

    def __init__(
        self,
        prompt: str,
        policy: SchedulingPolicy,
        planner: Optional[AgentPlanner] = None,
        dispatcher: Optional[SyscallDispatcher] = None,
        scheduler: Optional[TaskScheduler] = None,
        pcb_table: Optional[PCBTable] = None,
        starting_pid: int = 100,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.prompt = prompt
        self.policy = policy
        self.planner = planner if planner is not None else AgentPlanner()
        self.dispatcher = dispatcher if dispatcher is not None else SyscallDispatcher()
        self.scheduler = scheduler if scheduler is not None else TaskScheduler(policy=policy)
        self.pcb_table = pcb_table if pcb_table is not None else PCBTable()
        self.starting_pid = starting_pid

        self._cancel_requested = threading.Event()
        self._active_pcb: Optional[TaskPCB] = None

    def cancel(self) -> None:
        """Signals worker to abort execution and kills any active process."""
        self._cancel_requested.set()
        if self._active_pcb is not None and self.dispatcher.process_manager is not None:
            try:
                self.dispatcher.process_manager.kill_process(self._active_pcb.pid)
            except Exception:
                pass

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_requested.is_set()

    def run(self) -> None:
        """Executes the full Cognitive Shell -> Micro-Supervisor pipeline."""
        start_time = time.time()
        self.sig_status_updated.emit("Compiling natural language plan...")
        self.sig_console_stream.emit(
            f"[PLANNER] Compiling request: '{self.prompt}'\n", "system"
        )

        # 1. Compile Plan
        try:
            # Provide current sandbox workspace files and directory context to LLM Shell
            context: dict[str, Any] = {}
            try:
                s_root = getattr(self.dispatcher.file_engine, "sandbox_root", None)
                if s_root and Path(s_root).is_dir():
                    s_path = Path(s_root)
                    workspace_items = [
                        str(p.relative_to(s_path)).replace("\\", "/")
                        for p in s_path.rglob("*")
                        if not p.name.startswith(".") and ".agentos_trash" not in str(p)
                    ][:40]
                    context["existing_files"] = workspace_items
                    context["cwd"] = str(s_path)
            except Exception:
                pass

            plan = self.planner.compile(self.prompt, context=context if context else None)
            self.sig_plan_compiled.emit(plan)
            self.sig_console_stream.emit(
                f"[PLANNER] Plan compiled successfully: {plan.plan_description} "
                f"({len(plan.steps)} steps)\n",
                "success",
            )
        except Exception as exc:
            err_msg = f"Plan compilation failed: {exc}"
            self.sig_console_stream.emit(f"[ERROR] {err_msg}\n", "stderr")
            self.sig_execution_finished.emit(False, err_msg)
            return

        if self.is_cancelled:
            self.sig_console_stream.emit("[KERNEL] Execution aborted by user.\n", "warning")
            self.sig_execution_finished.emit(False, "Aborted by user.")
            return

        # 2. Configure Scheduler Policy & Queue Tasks
        self.scheduler.clear()
        self.scheduler.set_policy(self.policy)
        self.sig_status_updated.emit(f"Scheduling steps with {self.policy.value} policy...")

        ordered_steps = plan.get_topological_steps()
        pcbs: list[TaskPCB] = []
        for i, step in enumerate(ordered_steps):
            pcb = step.to_pcb(pid=self.starting_pid + i)
            pcbs.append(pcb)
            self.pcb_table.register(pcb)
            self.scheduler.enqueue(pcb)
            self.sig_pcb_updated.emit(pcb)

        # 3. Execution Loop
        self.sig_status_updated.emit("Executing system call DAG...")
        step_map = {self.starting_pid + i: step for i, step in enumerate(ordered_steps)}
        overall_success = True
        executed_count = 0

        while not self.scheduler.is_empty():
            if self.is_cancelled:
                self.sig_console_stream.emit(
                    "[KERNEL] Execution aborted by user.\n", "warning"
                )
                overall_success = False
                break

            pcb = self.scheduler.next_task()
            if pcb is None:
                break

            self._active_pcb = pcb
            step = step_map.get(pcb.pid)
            if step is None:
                continue

            # Update lifecycle to RUNNING and broadcast to live PCB table
            if pcb.state == ProcessState.READY:
                pcb.transition_to(ProcessState.RUNNING)
                self.sig_pcb_updated.emit(pcb)

            executed_count += 1
            self.sig_status_updated.emit(
                f"Running step {executed_count}/{len(ordered_steps)}: {step.syscall.value}..."
            )
            self.sig_console_stream.emit(
                f"\n>>> [STEP {step.step_id}] {step.syscall.value}: "
                f"{step.description or ''}\n",
                "system",
            )

            # Check Ring 0 Privilege Elevation
            req = step.to_syscall_request()
            user_confirmed = False

            needs_elevation = self.dispatcher.privilege_gate.requires_elevation(req)
            user_confirmed = not needs_elevation

            if needs_elevation:
                self.sig_console_stream.emit(
                    f"[SECURITY] Requesting Ring 0 elevation for {req.syscall.value}...\n",
                    "warning",
                )
                bridge = ElevationBridge(req)
                self.sig_privilege_request.emit(bridge)

                # Wait for user response from GUI thread
                bridge.event.wait()

                if not bridge.approved or self.is_cancelled:
                    user_confirmed = False
                    self.sig_console_stream.emit(
                        f"[SECURITY] Elevation denied for {req.syscall.value}.\n",
                        "stderr",
                    )
                else:
                    user_confirmed = True
                    self.sig_console_stream.emit(
                        f"[SECURITY] Elevation granted by user.\n", "audit"
                    )
                    # Dynamically add to whitelist so user is not prompted again
                    if req.syscall in (SyscallType.APP_OPEN, SyscallType.APP_CLOSE):
                        app_target = req.params.get("app", "")
                        self.dispatcher.privilege_gate.whitelist_app(app_target)
                        self.dispatcher.process_manager.whitelist_app(app_target)
            elif req.ring == PrivilegeRing.RING_0:
                self.sig_console_stream.emit(
                    f"[SECURITY] Operation '{req.syscall.value}' authorized by existing whitelist.\n",
                    "audit",
                )

            # Dispatch Syscall
            res: SyscallResult = self.dispatcher.dispatch(
                request=req,
                pcb=pcb,
                user_confirmed=user_confirmed,
            )

            # Record in scheduler history
            self.scheduler.record_completed(pcb)
            self.sig_pcb_updated.emit(pcb)

            # Stream output / error
            if res.output:
                self.sig_console_stream.emit(f"{res.output}\n", "stdout")
            if res.error:
                self.sig_console_stream.emit(f"Error: {res.error}\n", "stderr")

            if not res.success:
                overall_success = False
                self.sig_console_stream.emit(
                    f"[STEP FAILED] Step {step.step_id} exited with error (exit code: {res.exit_code}).\n",
                    "stderr",
                )
                break
            else:
                self.sig_console_stream.emit(
                    f"[STEP COMPLETED] Step {step.step_id} finished in {res.duration_sec:.3f}s.\n",
                    "success",
                )

        # Drain any remaining unexecuted tasks if stopped or failed so none linger in READY state
        while not self.scheduler.is_empty():
            rem_pcb = self.scheduler.next_task()
            if rem_pcb is not None:
                if rem_pcb.state in (ProcessState.NEW, ProcessState.READY):
                    try:
                        rem_pcb.transition_to(ProcessState.TERMINATED)
                        rem_pcb.record_metrics(
                            exit_code=1,
                            error_msg="Cancelled or aborted due to step failure.",
                        )
                    except Exception:
                        pass
                self.sig_pcb_updated.emit(rem_pcb)

        self._active_pcb = None
        elapsed = time.time() - start_time
        summary = (
            f"Execution {'succeeded' if overall_success else 'failed'} "
            f"({executed_count}/{len(ordered_steps)} steps in {elapsed:.2f}s)"
        )
        self.sig_console_stream.emit(f"\n[SUMMARY] {summary}\n", "audit" if overall_success else "stderr")
        self.sig_execution_finished.emit(overall_success, summary)


class MainWindow(QMainWindow):
    """Main AgentOS graphical shell window."""

    def __init__(
        self,
        planner: Optional[AgentPlanner] = None,
        dispatcher: Optional[SyscallDispatcher] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.planner = planner or AgentPlanner()
        self.dispatcher = dispatcher or SyscallDispatcher()
        self.scheduler = TaskScheduler(policy=SchedulingPolicy.FCFS)
        self.pcb_table_data = PCBTable()
        self._next_pid: int = 100

        self._worker: Optional[SupervisorWorker] = None
        self._telemetry_daemon = TelemetryDaemon(interval_sec=1.0)
        self.telemetry_worker: Optional[TelemetryWorker] = None

        self.setWindowTitle("AgentOS")
        self.resize(1200, 750)
        self.setMinimumSize(850, 560)

        self._init_ui()
        self._init_telemetry_pipeline()

    def _init_ui(self) -> None:
        """Constructs layout, widgets, and connections."""
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #0d0f14;
            }
            QWidget {
                color: #e2e8f0;
                font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            }
            QSplitter::handle {
                background-color: #1a1d26;
                width: 2px;
                height: 2px;
            }
            """
        )

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 10, 12, 6)
        main_layout.setSpacing(8)

        # 1. Top Header & Prompt Input Bar
        top_frame = QFrame()
        top_frame.setObjectName("topNavFrame")
        top_frame.setStyleSheet(
            """
            #topNavFrame {
                background-color: #141720;
                border: 1px solid #202432;
                border-radius: 10px;
            }
            """
        )
        top_layout = QVBoxLayout(top_frame)
        top_layout.setContentsMargins(10, 8, 10, 8)
        top_layout.setSpacing(8)

        # App Title Row
        app_title_row = QHBoxLayout()
        logo_label = QLabel("<b>AgentOS</b>")
        logo_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #f8fafc;")
        app_title_row.addWidget(logo_label)
        app_title_row.addStretch()

        policy_label = QLabel("Policy:")
        policy_label.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 500;")
        app_title_row.addWidget(policy_label)

        self.policy_combo = QComboBox()
        self.policy_combo.addItems(["FCFS", "Priority", "SJF"])
        self.policy_combo.setStyleSheet(
            """
            QComboBox {
                background-color: #1c202d;
                color: #cbd5e1;
                border: 1px solid #282e40;
                border-radius: 6px;
                padding: 3px 8px;
                font-size: 11px;
                font-weight: 500;
            }
            QComboBox:hover {
                border-color: #3b445c;
            }
            QComboBox::drop-down {
                border: none;
            }
            """
        )
        app_title_row.addWidget(self.policy_combo)

        top_layout.addLayout(app_title_row)

        # Prompt & Action Buttons Row
        prompt_row = QHBoxLayout()
        prompt_row.setSpacing(8)

        self.prompt_input = QLineEdit()
        self.prompt_input.setPlaceholderText(
            "Enter instruction (e.g., 'Find all python files in project and show system info')..."
        )
        self.prompt_input.setStyleSheet(
            """
            QLineEdit {
                background-color: #0a0b10;
                color: #f8fafc;
                border: 1px solid #232838;
                border-radius: 8px;
                padding: 9px 14px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #6366f1;
                background-color: #0c0d14;
            }
            """
        )
        self.prompt_input.returnPressed.connect(self.on_execute_clicked)
        prompt_row.addWidget(self.prompt_input)

        self.execute_btn = QPushButton("Execute Plan")
        self.execute_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.execute_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #4f46e5;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 9px 20px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #6366f1;
            }
            QPushButton:pressed {
                background-color: #4338ca;
            }
            QPushButton:disabled {
                background-color: #1c202d;
                color: #475569;
            }
            """
        )
        self.execute_btn.clicked.connect(self.on_execute_clicked)
        prompt_row.addWidget(self.execute_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setVisible(False)  # Hidden when idle
        self.stop_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 9px 20px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #ef4444;
            }
            QPushButton:pressed {
                background-color: #b91c1c;
            }
            QPushButton:disabled {
                background-color: #1c202d;
                color: #475569;
            }
            """
        )
        self.stop_btn.clicked.connect(self.on_stop_clicked)
        prompt_row.addWidget(self.stop_btn)

        self.undo_btn = QPushButton("Undo")
        self.undo_btn.setToolTip("Roll back the last file modification or quarantined file deletion (Ctrl+Z)")
        self.undo_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.undo_btn.setVisible(False)  # Hidden by default when no undo history exists
        self.undo_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #1c202d;
                color: #cbd5e1;
                border: 1px solid #282e40;
                border-radius: 8px;
                padding: 9px 14px;
                font-weight: 500;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #262c3e;
                color: #f8fafc;
                border-color: #3b445c;
            }
            QPushButton:pressed {
                background-color: #141722;
            }
            QPushButton:disabled {
                background-color: #12141c;
                color: #475569;
                border-color: #1c202d;
            }
            """
        )
        self.undo_btn.clicked.connect(self.on_undo_clicked)
        prompt_row.addWidget(self.undo_btn)

        self.undo_shortcut = QShortcut(QKeySequence.StandardKey.Undo, self)
        self.undo_shortcut.activated.connect(self.on_undo_clicked)

        top_layout.addLayout(prompt_row)
        main_layout.addWidget(top_frame)

        # 2. Center Splitter: PCB Table (Left) + Console (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.pcb_table = PcbTableWidget()
        self.pcb_table.sig_cleared.connect(self._on_pcb_registry_cleared)
        splitter.addWidget(self.pcb_table)

        self.terminal = TerminalWidget()
        splitter.addWidget(self.terminal)

        splitter.setSizes([600, 580])
        main_layout.addWidget(splitter, 1)

        # 3. Bottom Hardware Telemetry Bar
        self.telemetry_widget = TelemetryWidget()
        main_layout.addWidget(self.telemetry_widget)

        # Status Bar disabled for clean layout
        self.setStatusBar(None)
        self.status_bar = None

        # Welcome message in terminal
        self.terminal.append_line("=== AgentOS Micro-Supervisor Shell Initialized ===", "audit")
        self.terminal.append_line("Kernel status: Online | Privilege Ring Gating: Active", "system")
        self.terminal.append_line("Type an instruction above or select a scheduling policy.\n", "stdout")

    def _init_telemetry_pipeline(self) -> None:
        """Starts background TelemetryWorker and connects its Qt signal to TelemetryWidget."""
        self.telemetry_worker = TelemetryWorker(
            daemon=self._telemetry_daemon,
            interval_sec=1.0,
            parent=self,
        )
        self.telemetry_worker.sig_telemetry_tick.connect(self._on_telemetry_tick)
        self.telemetry_worker.start()

        # Backward compatibility for any external timer checks
        self._telemetry_timer = QTimer(self)

        # Initial sample to immediately populate gauges
        self._on_telemetry_tick(self._telemetry_daemon.get_last_sample())

    def _init_telemetry_timer(self) -> None:
        """Legacy alias redirecting to _init_telemetry_pipeline."""
        self._init_telemetry_pipeline()

    def _on_telemetry_tick(self, data: Optional[dict[str, Any]] = None) -> None:
        """Samples hardware telemetry or consumes background packet to update widget."""
        metrics = data if data is not None else self._telemetry_daemon.sample()
        self.telemetry_widget.update_telemetry(metrics)

    def on_undo_clicked(self) -> None:
        """Executes undo rollback on the most recent journaled file transaction."""
        self.undo_btn.setEnabled(False)
        try:
            res: SyscallResult = self.dispatcher.undo_last_action()
            if res.success:
                self.terminal.append_line(f"\n[UNDO] {res.output}", "audit")
            else:
                self.terminal.append_line(f"\n[UNDO] {res.error}", "warning")
        finally:
            has_undo = False
            try:
                if hasattr(self.dispatcher, "file_engine") and self.dispatcher.file_engine is not None:
                    history = self.dispatcher.file_engine.get_journal_history(limit=5)
                    has_undo = any(not getattr(e, "undone", False) for e in history)
            except Exception:
                has_undo = False
            self.undo_btn.setVisible(has_undo)
            self.undo_btn.setEnabled(True)

    def _on_pcb_registry_cleared(self) -> None:
        """Resets kernel process table, scheduler, and PID allocator when user clears registry."""
        self.pcb_table_data.clear()
        self.scheduler.clear()
        self._next_pid = 100

    def _on_plan_compiled(self, plan: SyscallPlan) -> None:
        """Advances PID sequence allocator by the number of steps in the compiled plan."""
        self._next_pid += len(plan.steps)

    def on_execute_clicked(self) -> None:
        """Handles Execution trigger from button or Return key."""
        prompt = self.prompt_input.text().strip()
        if not prompt:
            QMessageBox.information(
                self, "Empty Instruction", "Please enter a natural language instruction."
            )
            return

        policy_str = self.policy_combo.currentText()
        policy = TaskScheduler._normalize_policy(policy_str)

        # Update UI state - show Stop, hide Execute & Undo
        self.execute_btn.setEnabled(False)
        self.execute_btn.setVisible(False)
        self.stop_btn.setVisible(True)
        self.stop_btn.setEnabled(True)
        self.undo_btn.setVisible(False)
        self.undo_btn.setEnabled(False)
        self.prompt_input.setEnabled(False)
        self.policy_combo.setEnabled(False)

        # Spawn Worker Thread
        self._worker = SupervisorWorker(
            prompt=prompt,
            policy=policy,
            planner=self.planner,
            dispatcher=self.dispatcher,
            scheduler=self.scheduler,
            pcb_table=self.pcb_table_data,
            starting_pid=self._next_pid,
            parent=self,
        )

        self._worker.sig_plan_compiled.connect(self._on_plan_compiled)
        self._worker.sig_pcb_updated.connect(self.pcb_table.update_pcb)
        self._worker.sig_console_stream.connect(self.terminal.append_stream)
        self._worker.sig_privilege_request.connect(self._handle_elevation_request)
        self._worker.sig_execution_finished.connect(self._on_execution_finished)

        self._worker.start()

    def on_stop_clicked(self) -> None:
        """Handles Stop / Abort button click."""
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self.stop_btn.setEnabled(False)

    def _handle_elevation_request(self, bridge: ElevationBridge) -> None:
        """Opens ElevationDialog on GUI thread and sets result in synchronization bridge."""
        approved = ElevationDialog.prompt_elevation(bridge.request, parent=self)
        bridge.approved = approved
        bridge.event.set()

    def _on_execution_finished(self, success: bool, message: str) -> None:
        """Restores UI controls when worker completes."""
        self.execute_btn.setVisible(True)
        self.execute_btn.setEnabled(True)
        self.stop_btn.setVisible(False)
        self.stop_btn.setEnabled(False)
        self.prompt_input.setEnabled(True)
        self.policy_combo.setEnabled(True)
        self._worker = None

        # Reveal undo button only if an undoable action was recorded in journal
        has_undo = False
        try:
            if hasattr(self.dispatcher, "file_engine") and self.dispatcher.file_engine is not None:
                history = self.dispatcher.file_engine.get_journal_history(limit=5)
                has_undo = any(not getattr(e, "undone", False) for e in history)
        except Exception:
            has_undo = False
        self.undo_btn.setVisible(has_undo)
        self.undo_btn.setEnabled(has_undo)

    def close(self) -> bool:
        """Clean teardown ensuring threads stop even if window was not shown."""
        if hasattr(self, "telemetry_worker") and self.telemetry_worker is not None:
            self.telemetry_worker.stop()
        if hasattr(self, "_telemetry_daemon") and self._telemetry_daemon.is_running:
            self._telemetry_daemon.stop()
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(1500)
        return super().close()

    def closeEvent(self, event: Any) -> None:
        """Clean teardown on application exit."""
        if hasattr(self, "telemetry_worker") and self.telemetry_worker is not None:
            self.telemetry_worker.stop()
        if hasattr(self, "_telemetry_timer") and self._telemetry_timer.isActive():
            self._telemetry_timer.stop()
        if self._telemetry_daemon.is_running:
            self._telemetry_daemon.stop()
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(1500)
        super().closeEvent(event)
