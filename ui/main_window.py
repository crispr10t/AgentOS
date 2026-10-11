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
    QStatusBar,
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
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.prompt = prompt
        self.policy = policy
        self.planner = planner or AgentPlanner()
        self.dispatcher = dispatcher or SyscallDispatcher()
        self.scheduler = scheduler or TaskScheduler(policy=policy)
        self.pcb_table = pcb_table or PCBTable()

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
            plan = self.planner.compile(self.prompt)
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
        self.scheduler.set_policy(self.policy)
        self.sig_status_updated.emit(f"Scheduling steps with {self.policy.value} policy...")

        ordered_steps = plan.get_topological_steps()
        pcbs: list[TaskPCB] = []
        for i, step in enumerate(ordered_steps):
            pcb = step.to_pcb(pid=100 + i)
            pcbs.append(pcb)
            self.pcb_table.register(pcb)
            self.scheduler.enqueue(pcb)
            self.sig_pcb_updated.emit(pcb)

        # 3. Execution Loop
        self.sig_status_updated.emit("Executing system call DAG...")
        step_map = {100 + i: step for i, step in enumerate(ordered_steps)}
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

            if req.ring == PrivilegeRing.RING_0:
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

        self._worker: Optional[SupervisorWorker] = None
        self._telemetry_daemon = TelemetryDaemon(interval_sec=1.0)

        self.setWindowTitle("AgentOS - Cognitive User-Space Micro-Supervisor")
        self.resize(1180, 760)
        self.setMinimumSize(850, 560)

        self._init_ui()
        self._init_telemetry_timer()

    def _init_ui(self) -> None:
        """Constructs layout, widgets, and connections."""
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #18181b;
            }
            QWidget {
                color: #e4e4e7;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }
            QSplitter::handle {
                background-color: #27272a;
                width: 2px;
                height: 2px;
            }
            """
        )

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 6)
        main_layout.setSpacing(10)

        # 1. Top Header & Prompt Input Bar
        top_frame = QFrame()
        top_frame.setStyleSheet(
            """
            QFrame {
                background-color: #1f1f23;
                border: 1px solid #27272a;
                border-radius: 8px;
                padding: 10px;
            }
            """
        )
        top_layout = QVBoxLayout(top_frame)
        top_layout.setContentsMargins(8, 8, 8, 8)
        top_layout.setSpacing(10)

        # App Title Row
        app_title_row = QHBoxLayout()
        logo_label = QLabel("⚡ <b>AgentOS</b>")
        logo_label.setStyleSheet("font-size: 15px; color: #f4f4f5;")
        app_title_row.addWidget(logo_label)

        version_badge = QLabel("v0.5.0 • Ring 3 / Ring 0 Supervisor")
        version_badge.setStyleSheet(
            """
            background-color: #27272a;
            color: #38bdf8;
            font-size: 10px;
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 4px;
            """
        )
        app_title_row.addWidget(version_badge)

        app_title_row.addStretch()

        policy_label = QLabel("Scheduling Policy:")
        policy_label.setStyleSheet("font-size: 11px; color: #a1a1aa;")
        app_title_row.addWidget(policy_label)

        self.policy_combo = QComboBox()
        self.policy_combo.addItems(["FCFS", "Priority", "SJF"])
        self.policy_combo.setStyleSheet(
            """
            QComboBox {
                background-color: #27272a;
                color: #f4f4f5;
                border: 1px solid #3f3f46;
                border-radius: 4px;
                padding: 3px 8px;
                font-size: 11px;
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
                background-color: #121216;
                color: #f4f4f5;
                border: 1px solid #3f3f46;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #6366f1;
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
                border-radius: 6px;
                padding: 8px 18px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #6366f1;
            }
            QPushButton:pressed {
                background-color: #4338ca;
            }
            QPushButton:disabled {
                background-color: #27272a;
                color: #71717a;
            }
            """
        )
        self.execute_btn.clicked.connect(self.on_execute_clicked)
        prompt_row.addWidget(self.execute_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #e11d48;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 18px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #f43f5e;
            }
            QPushButton:pressed {
                background-color: #be123c;
            }
            QPushButton:disabled {
                background-color: #27272a;
                color: #71717a;
            }
            """
        )
        self.stop_btn.clicked.connect(self.on_stop_clicked)
        prompt_row.addWidget(self.stop_btn)

        top_layout.addLayout(prompt_row)
        main_layout.addWidget(top_frame)

        # 2. Center Splitter: PCB Table (Left) + Console (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.pcb_table = PcbTableWidget()
        splitter.addWidget(self.pcb_table)

        self.terminal = TerminalWidget()
        splitter.addWidget(self.terminal)

        splitter.setSizes([540, 600])
        main_layout.addWidget(splitter, 1)

        # 3. Bottom Hardware Telemetry Bar
        self.telemetry_widget = TelemetryWidget()
        main_layout.addWidget(self.telemetry_widget)

        # 4. Status Bar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet(
            "QStatusBar { color: #a1a1aa; font-size: 11px; background-color: #121216; }"
        )
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready. Enter an instruction to compile and execute.")

        # Welcome message in terminal
        self.terminal.append_line("=== AgentOS Micro-Supervisor Shell Initialized ===", "audit")
        self.terminal.append_line("Kernel status: Online | Privilege Ring Gating: Active", "system")
        self.terminal.append_line("Type an instruction above or select a scheduling policy.\n", "stdout")

    def _init_telemetry_timer(self) -> None:
        """Starts 1 Hz timer to sample psutil metrics and update telemetry widget."""
        self._telemetry_timer = QTimer(self)
        self._telemetry_timer.setInterval(1000)
        self._telemetry_timer.timeout.connect(self._on_telemetry_tick)
        self._telemetry_timer.start()

        # Initial sample
        self._on_telemetry_tick()

    def _on_telemetry_tick(self) -> None:
        """Samples hardware telemetry and pushes to widget."""
        metrics = self._telemetry_daemon.sample()
        self.telemetry_widget.update_telemetry(metrics)

    def on_execute_clicked(self) -> None:
        """Handles Execution trigger from button or Return key."""
        prompt = self.prompt_input.text().strip()
        if not prompt:
            QMessageBox.information(
                self, "Empty Instruction", "Please enter a natural language instruction."
            )
            return

        policy_str = self.policy_combo.currentText()
        policy = SchedulingPolicy(policy_str)

        # Update UI state
        self.execute_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.prompt_input.setEnabled(False)
        self.policy_combo.setEnabled(False)
        self.status_bar.showMessage("Initializing supervisor worker...")

        # Spawn Worker Thread
        self._worker = SupervisorWorker(
            prompt=prompt,
            policy=policy,
            planner=self.planner,
            dispatcher=self.dispatcher,
            scheduler=self.scheduler,
            pcb_table=self.pcb_table_data,
            parent=self,
        )

        self._worker.sig_pcb_updated.connect(self.pcb_table.update_pcb)
        self._worker.sig_console_stream.connect(self.terminal.append_stream)
        self._worker.sig_privilege_request.connect(self._handle_elevation_request)
        self._worker.sig_status_updated.connect(self.status_bar.showMessage)
        self._worker.sig_execution_finished.connect(self._on_execution_finished)

        self._worker.start()

    def on_stop_clicked(self) -> None:
        """Handles Stop / Abort button click."""
        if self._worker is not None and self._worker.isRunning():
            self.status_bar.showMessage("Aborting execution...")
            self._worker.cancel()
            self.stop_btn.setEnabled(False)

    def _handle_elevation_request(self, bridge: ElevationBridge) -> None:
        """Opens ElevationDialog on GUI thread and sets result in synchronization bridge."""
        approved = ElevationDialog.prompt_elevation(bridge.request, parent=self)
        bridge.approved = approved
        bridge.event.set()

    def _on_execution_finished(self, success: bool, message: str) -> None:
        """Restores UI controls when worker completes."""
        self.execute_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.prompt_input.setEnabled(True)
        self.policy_combo.setEnabled(True)
        self.status_bar.showMessage(f"Status: {message}")
        self._worker = None

    def closeEvent(self, event: Any) -> None:
        """Clean teardown on application exit."""
        if self._telemetry_timer.isActive():
            self._telemetry_timer.stop()
        if self._telemetry_daemon.is_running:
            self._telemetry_daemon.stop()
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(1500)
        super().closeEvent(event)
