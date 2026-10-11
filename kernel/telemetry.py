"""Hardware Telemetry Daemon and Resource Monitor.

Continuously samples host CPU per-core utilization and system RAM metrics
using psutil, dispatching live telemetry packets to registered observers
and Qt signal pipelines without blocking supervisor execution.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

import psutil

logger = logging.getLogger(__name__)


class TelemetryDaemon:
    """Background hardware telemetry monitor running on a dedicated daemon thread.

    Samples per-core CPU utilization, aggregate CPU usage, and virtual memory
    consumption at periodic intervals (default 1000ms), notifying subscribed
    observers with structured telemetry metrics.
    """

    def __init__(
        self,
        interval_sec: float = 1.0,
        callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ):
        """Initializes the TelemetryDaemon.

        Args:
            interval_sec: Polling interval in seconds (default 1.0s).
            callback: Optional initial callback invoked on each sampling tick.
        """
        self.interval_sec = max(0.1, float(interval_sec))
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        if callback is not None:
            self._listeners.append(callback)

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sample: dict[str, Any] = {}

        # Prime psutil CPU counters so the first tick does not return 0.0
        try:
            psutil.cpu_percent(interval=None, percpu=True)
            psutil.cpu_percent(interval=None)
        except Exception as exc:
            logger.warning("Failed to prime psutil CPU counters: %s", exc)

    def subscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Registers a telemetry observer callback.

        Args:
            callback: Function taking the metrics dictionary.
        """
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def unsubscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Removes a registered telemetry observer callback."""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def sample(self) -> dict[str, Any]:
        """Performs a single synchronous hardware telemetry sample.

        Returns:
            Dictionary containing CPU per-core, total CPU, and RAM metrics.
        """
        try:
            cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
            cpu_total = psutil.cpu_percent(interval=None)
        except Exception as exc:
            logger.warning("Failed to read CPU metrics: %s", exc)
            cpu_per_core = [0.0]
            cpu_total = 0.0

        try:
            vmem = psutil.virtual_memory()
            ram_percent = float(vmem.percent)
            ram_used_gb = round(vmem.used / (1024**3), 2)
            ram_total_gb = round(vmem.total / (1024**3), 2)
        except Exception as exc:
            logger.warning("Failed to read RAM metrics: %s", exc)
            ram_percent = 0.0
            ram_used_gb = 0.0
            ram_total_gb = 0.0

        metrics = {
            "cpu_total": float(cpu_total),
            "cpu_per_core": [float(c) for c in cpu_per_core],
            "ram_percent": ram_percent,
            "ram_used_gb": ram_used_gb,
            "ram_total_gb": ram_total_gb,
            "timestamp": time.time(),
        }

        with self._lock:
            self._last_sample = metrics

        return metrics

    def get_last_sample(self) -> dict[str, Any]:
        """Returns the most recent sample without polling."""
        with self._lock:
            if not self._last_sample:
                return self.sample()
            return dict(self._last_sample)

    def _run(self) -> None:
        """Daemon worker loop executing in the background thread."""
        while not self._stop_event.is_set():
            metrics = self.sample()

            # Dispatch to listeners safely
            with self._lock:
                listeners = list(self._listeners)

            for cb in listeners:
                try:
                    cb(metrics)
                except Exception as exc:
                    logger.debug("Telemetry listener error: %s", exc)

            # Wait for next interval or stop event
            self._stop_event.wait(timeout=self.interval_sec)

    def start(self) -> None:
        """Starts the background telemetry polling thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="AgentOS-TelemetryDaemon",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Stops the background polling thread and waits for termination.

        Args:
            timeout: Maximum seconds to wait for thread join.
        """
        with self._lock:
            self._stop_event.set()
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=timeout)
                self._thread = None

    @property
    def is_running(self) -> bool:
        """Returns True if the background daemon thread is active."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()
