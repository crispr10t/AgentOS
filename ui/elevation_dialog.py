"""Privilege Elevation Modal Dialog for Ring 0 System Calls.

Displays an interactive approval prompt when the Cognitive Shell attempts
a privileged or destructive operation (Ring 0), showing command details,
target files, and security implications before granting execution permission.
"""

from __future__ import annotations

import json
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from kernel.syscalls import PrivilegeRing, SyscallRequest, SyscallType


class ElevationDialog(QDialog):
    """Modal authorization dialog gating Ring 0 supervisor execution."""

    def __init__(
        self,
        request: SyscallRequest,
        parent: Optional[QWidget] = None,
    ):
        """Initializes the elevation dialog with the target SyscallRequest.

        Args:
            request: The SyscallRequest requiring Ring 0 confirmation.
            parent: Optional parent QWidget.
        """
        super().__init__(parent)
        self.request = request

        self.setWindowTitle("Ring 0 Privilege Elevation")
        self.setModal(True)
        self.setMinimumWidth(540)
        self.setMinimumHeight(420)

        self._init_ui()

    def _init_ui(self) -> None:
        """Builds dialog layout and styling."""
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # 1. Header with Warning / Shield Banner
        header_frame = QFrame()
        header_frame.setObjectName("elevationHeader")
        header_frame.setStyleSheet(
            """
            #elevationHeader {
                background-color: #2e1015;
                border: 1px solid #e11d48;
                border-radius: 8px;
                padding: 12px;
            }
            """
        )
        h_box = QHBoxLayout(header_frame)
        h_box.setContentsMargins(8, 8, 8, 8)

        icon_label = QLabel("🛡️")
        icon_label.setStyleSheet("font-size: 28px;")
        h_box.addWidget(icon_label)

        title_vbox = QVBoxLayout()
        title_label = QLabel("Privilege Elevation Required")
        title_label.setStyleSheet(
            "font-size: 15px; font-weight: bold; color: #fda4af;"
        )
        subtitle_label = QLabel(
            "The cognitive shell requested a Ring 0 supervisor operation.\n"
            "Execution is suspended pending your explicit authorization."
        )
        subtitle_label.setStyleSheet("font-size: 12px; color: #fecdd3;")
        subtitle_label.setWordWrap(True)

        title_vbox.addWidget(title_label)
        title_vbox.addWidget(subtitle_label)
        h_box.addLayout(title_vbox)
        layout.addWidget(header_frame)

        # 2. Syscall Summary Card
        card_frame = QFrame()
        card_frame.setStyleSheet(
            """
            QFrame {
                background-color: #1e1e24;
                border: 1px solid #3f3f46;
                border-radius: 8px;
                padding: 10px;
            }
            """
        )
        card_layout = QVBoxLayout(card_frame)
        card_layout.setSpacing(8)

        # Top row: Syscall Type + Ring badge
        badge_row = QHBoxLayout()
        sc_label = QLabel(f"System Call:  <b>{self.request.syscall.value}</b>")
        sc_label.setStyleSheet("font-size: 13px; color: #f4f4f5;")
        badge_row.addWidget(sc_label)

        badge_row.addStretch()

        ring_badge = QLabel("RING 0 (PRIVILEGED)")
        ring_badge.setStyleSheet(
            """
            background-color: #b91c1c;
            color: #ffffff;
            font-size: 10px;
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 4px;
            """
        )
        badge_row.addWidget(ring_badge)
        card_layout.addLayout(badge_row)

        # Specific operation highlights
        highlight_text = self._build_highlight_text()
        if highlight_text:
            op_label = QLabel(highlight_text)
            op_label.setStyleSheet(
                "font-size: 12px; color: #38bdf8; font-weight: 500;"
            )
            op_label.setWordWrap(True)
            card_layout.addWidget(op_label)

        layout.addWidget(card_frame)

        # 3. Parameter Inspector (JSON / Details)
        params_title = QLabel("System Call Parameters & Payload:")
        params_title.setStyleSheet("font-size: 12px; color: #a1a1aa; font-weight: 600;")
        layout.addWidget(params_title)

        self.params_view = QTextEdit()
        self.params_view.setReadOnly(True)
        self.params_view.setFont(QFont("Consolas", 10))
        self.params_view.setStyleSheet(
            """
            QTextEdit {
                background-color: #121216;
                color: #e4e4e7;
                border: 1px solid #27272a;
                border-radius: 6px;
                padding: 8px;
            }
            """
        )
        formatted_json = json.dumps(self.request.params, indent=2, default=str)
        self.params_view.setPlainText(formatted_json)
        layout.addWidget(self.params_view)

        # 4. Action Buttons (Approve vs Reject)
        btn_box = QHBoxLayout()
        btn_box.setSpacing(12)

        self.reject_btn = QPushButton("Reject (Deny Operation)")
        self.reject_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reject_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #27272a;
                color: #e4e4e7;
                border: 1px solid #3f3f46;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #3f3f46;
                color: #ffffff;
            }
            """
        )
        self.reject_btn.clicked.connect(self.reject)
        btn_box.addWidget(self.reject_btn)

        btn_box.addStretch()

        self.approve_btn = QPushButton("Approve (Elevate to Ring 0)")
        self.approve_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.approve_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #e11d48;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f43f5e;
            }
            QPushButton:pressed {
                background-color: #be123c;
            }
            """
        )
        self.approve_btn.clicked.connect(self.accept)
        btn_box.addWidget(self.approve_btn)

        layout.addLayout(btn_box)

    def _build_highlight_text(self) -> str:
        """Constructs a human-readable summary of the dangerous parameters."""
        params = self.request.params or {}
        sc = self.request.syscall

        if sc == SyscallType.PROC_SPAWN:
            cmd = params.get("cmd", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            return f"Spawn Process: <code>{cmd_str}</code>"
        elif sc == SyscallType.FILE_DELETE:
            path = params.get("path", "")
            quarantine = params.get("quarantine", True)
            action = "Quarantine Delete" if quarantine else "Permanent Delete"
            return f"{action}: <code>{path}</code>"
        elif sc == SyscallType.FILE_WRITE:
            path = params.get("path", "")
            mode = params.get("mode", "w")
            return f"Write File ({mode}): <code>{path}</code>"
        elif sc == SyscallType.FILE_MOVE:
            src = params.get("src", "")
            dest = params.get("dest", "")
            return f"Move File: <code>{src}</code> &rarr; <code>{dest}</code>"
        elif sc == SyscallType.PROC_KILL:
            pid = params.get("pid", "")
            return f"Terminate Process PID: <code>{pid}</code>"

        return ""

    @classmethod
    def prompt_elevation(
        cls,
        request: SyscallRequest,
        parent: Optional[QWidget] = None,
    ) -> bool:
        """Static helper to prompt for elevation and return user decision.

        Args:
            request: SyscallRequest to authorize.
            parent: Optional parent widget.

        Returns:
            True if user approved elevation, False if rejected.
        """
        dialog = cls(request, parent=parent)
        result = dialog.exec()
        return result == QDialog.DialogCode.Accepted
