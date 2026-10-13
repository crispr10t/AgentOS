"""Application bootstrap and Qt event loop for AgentOS.

Launches the PyQt6 Desktop Graphical Shell, configures application metadata,
signal handling, and initializes the Micro-Supervisor runtime.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys

from dotenv import load_dotenv
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from agent.llm_client import LLMClient, LLMConfig, LLMProvider
from agent.planner import AgentPlanner
from kernel.syscalls import SyscallDispatcher
from ui.main_window import MainWindow

# Load environment configuration from .env
load_dotenv()


def parse_args() -> argparse.Namespace:
    """Parses command-line arguments for application launch."""
    parser = argparse.ArgumentParser(
        description="AgentOS - Cognitive User-Space Micro-Supervisor Desktop Interface"
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use a no-op mock provider; instructions are not interpreted or executed.",
    )
    parser.add_argument(
        "--offscreen",
        action="store_true",
        help="Run Qt in offscreen mode (useful for headless testing and automation).",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Pre-populate natural language instruction prompt on launch.",
    )
    return parser.parse_args()


def main() -> None:
    """Bootstrap entry point."""
    args = parse_args()

    if args.offscreen:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    # Initialize QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("AgentOS")
    app.setApplicationDisplayName("AgentOS")
    app.setOrganizationName("AgentOS")
    app.setApplicationVersion("0.5.0")

    # Connect POSIX/Windows SIGINT (Ctrl+C) to allow clean termination
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sig_timer = QTimer()
    sig_timer.start(500)
    sig_timer.timeout.connect(lambda: None)

    # Initialize LLM Client
    if args.mock_llm:
        config = LLMConfig(provider=LLMProvider.MOCK)
        llm_client = LLMClient(config=config)
    else:
        llm_client = LLMClient()

    planner = AgentPlanner(llm_client=llm_client)
    dispatcher = SyscallDispatcher()

    # Launch Main Window
    window = MainWindow(planner=planner, dispatcher=dispatcher)

    if args.prompt:
        window.prompt_input.setText(args.prompt)

    window.show()

    # Enter Qt Event Loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
