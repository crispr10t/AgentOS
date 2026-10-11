"""Hardware Telemetry Bar Widget.

Displays real-time host CPU aggregate load, per-core utilization meters,
and system virtual memory gauges refreshed at 1 Hz intervals.
"""

from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


def get_progress_bar_color(percent: float) -> str:
    """Returns dynamic color based on utilization threshold."""
    if percent >= 85.0:
        return "#ef4444"  # Red
    elif percent >= 65.0:
        return "#f59e0b"  # Amber
    return "#10b981"      # Emerald green


class TelemetryWidget(QWidget):
    """Bottom hardware telemetry bar showing CPU per-core and RAM utilization."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._core_bars: list[QProgressBar] = []
        self._init_ui()

    def _init_ui(self) -> None:
        """Configures bar layout, progress meters, and per-core container."""
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(10, 6, 10, 6)
        main_layout.setSpacing(16)

        self.setStyleSheet(
            """
            TelemetryWidget {
                background-color: #121216;
                border-top: 1px solid #27272a;
            }
            """
        )

        # 1. Total CPU Gauge
        cpu_box = QHBoxLayout()
        cpu_box.setSpacing(8)

        self.cpu_label = QLabel("CPU: 0.0%")
        self.cpu_label.setStyleSheet(
            "font-size: 11px; font-weight: bold; color: #f4f4f5; min-width: 68px;"
        )
        cpu_box.addWidget(self.cpu_label)

        self.cpu_bar = QProgressBar()
        self.cpu_bar.setRange(0, 100)
        self.cpu_bar.setValue(0)
        self.cpu_bar.setTextVisible(False)
        self.cpu_bar.setFixedWidth(100)
        self.cpu_bar.setFixedHeight(12)
        self.cpu_bar.setStyleSheet(self._progress_bar_qss("#10b981"))
        cpu_box.addWidget(self.cpu_bar)

        main_layout.addLayout(cpu_box)

        # 2. Per-Core CPU Mini Meters
        cores_box = QHBoxLayout()
        cores_box.setSpacing(6)

        cores_title = QLabel("Cores:")
        cores_title.setStyleSheet("font-size: 11px; color: #a1a1aa;")
        cores_box.addWidget(cores_title)

        self.cores_container = QWidget()
        self.cores_layout = QHBoxLayout(self.cores_container)
        self.cores_layout.setContentsMargins(0, 0, 0, 0)
        self.cores_layout.setSpacing(3)

        cores_scroll = QScrollArea()
        cores_scroll.setWidgetResizable(True)
        cores_scroll.setWidget(self.cores_container)
        cores_scroll.setFixedHeight(24)
        cores_scroll.setMaximumWidth(280)
        cores_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        cores_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        cores_scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )
        cores_box.addWidget(cores_scroll)

        main_layout.addLayout(cores_box)

        main_layout.addStretch()

        # 3. RAM Gauge
        ram_box = QHBoxLayout()
        ram_box.setSpacing(8)

        self.ram_label = QLabel("RAM: 0.0% (0.0 / 0.0 GB)")
        self.ram_label.setStyleSheet(
            "font-size: 11px; font-weight: bold; color: #f4f4f5; min-width: 150px;"
        )
        ram_box.addWidget(self.ram_label)

        self.ram_bar = QProgressBar()
        self.ram_bar.setRange(0, 100)
        self.ram_bar.setValue(0)
        self.ram_bar.setTextVisible(False)
        self.ram_bar.setFixedWidth(100)
        self.ram_bar.setFixedHeight(12)
        self.ram_bar.setStyleSheet(self._progress_bar_qss("#38bdf8"))
        ram_box.addWidget(self.ram_bar)

        main_layout.addLayout(ram_box)

        # 4. Status indicator badge
        self.pulse_label = QLabel("● Live")
        self.pulse_label.setStyleSheet("font-size: 11px; color: #10b981; font-weight: bold;")
        main_layout.addWidget(self.pulse_label)

    def _progress_bar_qss(self, fill_color: str) -> str:
        """Generates stylesheet for styled rounded progress bars."""
        return f"""
        QProgressBar {{
            background-color: #27272a;
            border-radius: 4px;
            border: none;
        }}
        QProgressBar::chunk {{
            background-color: {fill_color};
            border-radius: 4px;
        }}
        """

    def update_telemetry(self, data: dict[str, Any]) -> None:
        """Updates hardware telemetry meters from a metrics dictionary.

        Args:
            data: Dictionary containing 'cpu_total', 'cpu_per_core', 'ram_percent',
                  'ram_used_gb', and 'ram_total_gb'.
        """
        if not data:
            return

        # 1. Update CPU Total
        cpu_total = float(data.get("cpu_total", 0.0))
        self.cpu_label.setText(f"CPU: {cpu_total:.1f}%")
        self.cpu_bar.setValue(int(cpu_total))
        cpu_color = get_progress_bar_color(cpu_total)
        self.cpu_bar.setStyleSheet(self._progress_bar_qss(cpu_color))

        # 2. Update Per-Core Meters
        cores = data.get("cpu_per_core", [])
        num_cores = len(cores)

        # Dynamically build core bars if count differs
        if len(self._core_bars) != num_cores:
            # Clear existing bars
            while self.cores_layout.count():
                item = self.cores_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            self._core_bars.clear()

            for i in range(num_cores):
                bar = QProgressBar()
                bar.setOrientation(Qt.Orientation.Vertical)
                bar.setRange(0, 100)
                bar.setValue(0)
                bar.setTextVisible(False)
                bar.setFixedWidth(8)
                bar.setFixedHeight(18)
                bar.setStyleSheet(self._progress_bar_qss("#10b981"))
                bar.setToolTip(f"Core {i}")
                self.cores_layout.addWidget(bar)
                self._core_bars.append(bar)

        for i, (bar, val) in enumerate(zip(self._core_bars, cores)):
            v = int(val)
            bar.setValue(v)
            bar.setToolTip(f"Core {i}: {val:.1f}%")
            bar.setStyleSheet(self._progress_bar_qss(get_progress_bar_color(val)))

        # 3. Update RAM
        ram_percent = float(data.get("ram_percent", 0.0))
        ram_used = float(data.get("ram_used_gb", 0.0))
        ram_total = float(data.get("ram_total_gb", 0.0))

        self.ram_label.setText(f"RAM: {ram_percent:.1f}% ({ram_used:.1f} / {ram_total:.1f} GB)")
        self.ram_bar.setValue(int(ram_percent))
        ram_color = get_progress_bar_color(ram_percent)
        self.ram_bar.setStyleSheet(self._progress_bar_qss(ram_color))
