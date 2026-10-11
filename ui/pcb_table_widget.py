"""Live Process Control Block (PCB) Table Widget.

Renders real-time process lifecycle status badges, execution priorities,
runtime CPU time, and peak memory utilization for all active and completed tasks.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from kernel.pcb import ProcessState, TaskPCB


# State Badge Color Configuration (Background, Foreground)
STATE_COLORS: dict[ProcessState, tuple[str, str]] = {
    ProcessState.NEW: ("#374151", "#d1d5db"),          # Gray
    ProcessState.READY: ("#1e3a8a", "#93c5fd"),        # Blue
    ProcessState.RUNNING: ("#78350f", "#fde68a"),      # Amber
    ProcessState.WAITING: ("#4c1d95", "#c4b5fd"),      # Purple
    ProcessState.TERMINATED: ("#064e3b", "#a7f3d0"),   # Green
}

TERMINATED_ERROR_COLORS = ("#7f1d1d", "#fca5a5")       # Red (non-zero exit)


class PcbTableWidget(QWidget):
    """Table widget presenting live Process Control Blocks tracked by the supervisor."""

    COLUMNS = [
        "PID",
        "Task Name",
        "State",
        "Priority",
        "Est. (s)",
        "CPU Time",
        "Peak RAM",
        "Exit Code",
    ]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._pid_to_row: dict[int, int] = {}
        self._pcb_cache: dict[int, TaskPCB] = {}

        self._init_ui()

    def _init_ui(self) -> None:
        """Configures widget layout, table headers, and styling."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 1. Header Toolbar with Status Counters
        header_bar = QHBoxLayout()
        header_bar.setContentsMargins(4, 4, 4, 4)

        title = QLabel("Process Control Block (PCB) Registry")
        title.setStyleSheet("font-size: 13px; font-weight: bold; color: #f4f4f5;")
        header_bar.addWidget(title)

        header_bar.addStretch()

        self.count_badge = QLabel("Tasks: 0 | Running: 0 | Terminated: 0")
        self.count_badge.setStyleSheet(
            """
            background-color: #27272a;
            color: #a1a1aa;
            font-size: 11px;
            font-weight: 500;
            padding: 3px 8px;
            border-radius: 4px;
            """
        )
        header_bar.addWidget(self.count_badge)
        layout.addLayout(header_bar)

        # 2. Main QTableWidget
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)

        # Column widths & resize modes
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # PID
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)           # Task Name
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # State
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Priority
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Est.
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # CPU Time
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Peak RAM
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Exit Code

        self.table.setStyleSheet(
            """
            QTableWidget {
                background-color: #18181b;
                alternate-background-color: #202024;
                color: #e4e4e7;
                border: 1px solid #27272a;
                border-radius: 6px;
                gridline-color: transparent;
            }
            QTableWidget::item {
                padding: 6px 8px;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #312e81;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #1e1e24;
                color: #a1a1aa;
                padding: 6px 8px;
                font-weight: 600;
                font-size: 11px;
                border: none;
                border-bottom: 1px solid #3f3f46;
            }
            """
        )
        layout.addWidget(self.table)

    def update_pcb(self, pcb: TaskPCB) -> None:
        """Updates or inserts a TaskPCB entry into the live table.

        Args:
            pcb: TaskPCB instance with current status and metrics.
        """
        pid = pcb.pid
        self._pcb_cache[pid] = pcb

        if pid in self._pid_to_row:
            row = self._pid_to_row[pid]
        else:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._pid_to_row[pid] = row

        # 0. PID
        pid_item = QTableWidgetItem(f"#{pcb.pid}")
        pid_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        pid_item.setFont(QFont("Consolas", 10))
        self.table.setItem(row, 0, pid_item)

        # 1. Task Name
        name_item = QTableWidgetItem(pcb.name)
        if pcb.error_msg:
            name_item.setToolTip(f"Error: {pcb.error_msg}")
        self.table.setItem(row, 1, name_item)

        # 2. State Badge
        badge_widget = self._create_state_badge(pcb)
        self.table.setCellWidget(row, 2, badge_widget)

        # 3. Priority
        prio_item = QTableWidgetItem(str(pcb.priority))
        prio_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 3, prio_item)

        # 4. Est. Duration
        est_item = QTableWidgetItem(f"{pcb.estimated_duration:.1f}s")
        est_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 4, est_item)

        # 5. CPU Time
        cpu_str = f"{pcb.cpu_time:.3f}s" if pcb.cpu_time > 0 else "—"
        cpu_item = QTableWidgetItem(cpu_str)
        cpu_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 5, cpu_item)

        # 6. Peak RAM
        mem_str = f"{pcb.peak_memory_mb:.1f} MB" if pcb.peak_memory_mb > 0 else "—"
        mem_item = QTableWidgetItem(mem_str)
        mem_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 6, mem_item)

        # 7. Exit Code
        if pcb.exit_code is not None:
            if pcb.exit_code == 0:
                exit_str = "0 (OK)"
            else:
                exit_str = f"{pcb.exit_code} (ERR)"
        else:
            exit_str = "—"
        exit_item = QTableWidgetItem(exit_str)
        exit_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if pcb.exit_code is not None and pcb.exit_code != 0:
            exit_item.setForeground(QColor("#f87171"))
        self.table.setItem(row, 7, exit_item)

        self._update_counter_badge()

    def _create_state_badge(self, pcb: TaskPCB) -> QWidget:
        """Builds a styled state badge container widget for a table cell."""
        container = QWidget()
        h_layout = QHBoxLayout(container)
        h_layout.setContentsMargins(4, 2, 4, 2)
        h_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        label = QLabel(pcb.state.value)
        label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))

        if pcb.state == ProcessState.TERMINATED and pcb.exit_code is not None and pcb.exit_code != 0:
            bg_color, fg_color = TERMINATED_ERROR_COLORS
        else:
            bg_color, fg_color = STATE_COLORS.get(pcb.state, ("#374151", "#d1d5db"))

        label.setStyleSheet(
            f"""
            background-color: {bg_color};
            color: {fg_color};
            padding: 3px 10px;
            border-radius: 4px;
            """
        )
        h_layout.addWidget(label)
        return container

    def _update_counter_badge(self) -> None:
        """Recalculates and updates the summary badge count."""
        total = len(self._pcb_cache)
        running = sum(1 for p in self._pcb_cache.values() if p.state == ProcessState.RUNNING)
        terminated = sum(1 for p in self._pcb_cache.values() if p.state == ProcessState.TERMINATED)
        self.count_badge.setText(
            f"Tasks: {total} | Running: {running} | Terminated: {terminated}"
        )

    def clear(self) -> None:
        """Clears all table rows and resets internal caches."""
        self.table.setRowCount(0)
        self._pid_to_row.clear()
        self._pcb_cache.clear()
        self._update_counter_badge()
