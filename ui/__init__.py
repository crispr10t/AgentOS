"""AgentOS PyQt6 Desktop Graphical Shell.

Provides real-time visualization of process control blocks, streaming console logs,
hardware telemetry, and interactive privilege elevation dialogs.
"""

from ui.elevation_dialog import ElevationDialog
from ui.main_window import MainWindow, SupervisorWorker
from ui.pcb_table_widget import PcbTableWidget
from ui.telemetry_widget import TelemetryWidget
from ui.terminal_widget import TerminalWidget

__all__ = [
    "MainWindow",
    "SupervisorWorker",
    "PcbTableWidget",
    "TerminalWidget",
    "TelemetryWidget",
    "ElevationDialog",
]
