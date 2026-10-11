"""Streaming Terminal and Kernel Audit Console Widget.

Provides real-time terminal output rendering for subprocess stdout/stderr,
supervisor system notices, privilege elevation logs, and execution traces.
"""

from __future__ import annotations

import html
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


CHANNEL_COLORS: dict[str, str] = {
    "stdout": "#e2e8f0",    # Clean off-white
    "stderr": "#f87171",    # Soft red
    "system": "#38bdf8",    # Kernel sky-blue
    "success": "#4ade80",   # Emerald green
    "warning": "#fbbf24",   # Amber warning
    "audit": "#a78bfa",     # Violet audit tag
}


class TerminalWidget(QWidget):
    """Monospace streaming terminal console with colored channels and audit logging."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.auto_scroll: bool = True

        self._init_ui()

    def _init_ui(self) -> None:
        """Configures console layout, controls, and visual styling."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # 1. Header Toolbar
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(4, 4, 4, 4)

        title = QLabel("Supervisor Audit Console & Stream")
        title.setStyleSheet("font-size: 13px; font-weight: bold; color: #f4f4f5;")
        toolbar.addWidget(title)

        toolbar.addStretch()

        self.scroll_check = QCheckBox("Auto-scroll")
        self.scroll_check.setChecked(True)
        self.scroll_check.setStyleSheet("color: #a1a1aa; font-size: 11px;")
        self.scroll_check.toggled.connect(self._toggle_auto_scroll)
        toolbar.addWidget(self.scroll_check)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #27272a;
                color: #e4e4e7;
                border: 1px solid #3f3f46;
                border-radius: 4px;
                padding: 3px 8px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3f3f46;
                color: #ffffff;
            }
            """
        )
        self.copy_btn.clicked.connect(self.copy_console)
        toolbar.addWidget(self.copy_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #27272a;
                color: #e4e4e7;
                border: 1px solid #3f3f46;
                border-radius: 4px;
                padding: 3px 8px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3f3f46;
                color: #ffffff;
            }
            """
        )
        self.clear_btn.clicked.connect(self.clear_console)
        toolbar.addWidget(self.clear_btn)

        layout.addLayout(toolbar)

        # 2. Main Console Text Area
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setMaximumBlockCount(10000)
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)

        self.editor.setStyleSheet(
            """
            QPlainTextEdit {
                background-color: #0f1117;
                color: #e2e8f0;
                border: 1px solid #27272a;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #312e81;
                selection-color: #ffffff;
            }
            """
        )
        layout.addWidget(self.editor)

    def _toggle_auto_scroll(self, enabled: bool) -> None:
        self.auto_scroll = enabled

    def append_stream(self, text: str, channel: str = "stdout") -> None:
        """Appends streaming text with color coding based on channel.

        Args:
            text: Text to display.
            channel: Target channel ('stdout', 'stderr', 'system', 'success', 'warning', 'audit').
        """
        if not text:
            return

        color = CHANNEL_COLORS.get(channel.lower(), "#e2e8f0")
        escaped = html.escape(text).replace("\n", "<br>")

        formatted_html = f"<span style='color: {color}; font-family: Consolas, monospace;'>{escaped}</span>"

        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertHtml(formatted_html)

        if self.auto_scroll:
            self.editor.moveCursor(QTextCursor.MoveOperation.End)

    def append_line(self, line: str, channel: str = "stdout") -> None:
        """Appends a discrete line terminated with a newline."""
        self.append_stream(f"{line}\n", channel=channel)

    def clear_console(self) -> None:
        """Clears the console buffer."""
        self.editor.clear()

    def copy_console(self) -> None:
        """Copies all console content to system clipboard."""
        self.editor.selectAll()
        self.editor.copy()
        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.editor.setTextCursor(cursor)
