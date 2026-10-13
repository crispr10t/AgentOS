"""Dedicated unit tests for kernel/telemetry.py: TelemetryDaemon hardware monitoring."""

import time
import pytest

from kernel.telemetry import TelemetryDaemon


def test_telemetry_interval_clamping():
    """Verify polling interval is clamped to a safe minimum of 0.1s."""
    d_zero = TelemetryDaemon(interval_sec=0.0)
    assert d_zero.interval_sec == 0.1

    d_neg = TelemetryDaemon(interval_sec=-5.0)
    assert d_neg.interval_sec == 0.1

    d_custom = TelemetryDaemon(interval_sec=2.5)
    assert d_custom.interval_sec == 2.5


def test_telemetry_sample_metrics_structure():
    """Verify synchronous hardware telemetry sample contains all required fields with valid types."""
    daemon = TelemetryDaemon(interval_sec=0.5)
    metrics = daemon.sample()

    assert "cpu_total" in metrics
    assert "cpu_per_core" in metrics
    assert "ram_percent" in metrics
    assert "ram_used_gb" in metrics
    assert "ram_total_gb" in metrics
    assert "timestamp" in metrics

    assert isinstance(metrics["cpu_total"], float)
    assert isinstance(metrics["cpu_per_core"], list)
    assert isinstance(metrics["ram_percent"], float)
    assert isinstance(metrics["ram_used_gb"], float)
    assert isinstance(metrics["ram_total_gb"], float)

    # Sanity checks on range
    assert 0.0 <= metrics["cpu_total"] <= 100.0
    assert 0.0 <= metrics["ram_percent"] <= 100.0
    assert metrics["ram_total_gb"] > 0.0


def test_telemetry_get_last_sample_caching():
    """Verify get_last_sample returns cached metrics without requiring a new poll."""
    daemon = TelemetryDaemon()
    sample1 = daemon.sample()
    last = daemon.get_last_sample()

    assert last["timestamp"] == sample1["timestamp"]
    assert last["cpu_total"] == sample1["cpu_total"]


def test_telemetry_subscription_and_unsubscription():
    """Verify listeners can be registered and removed cleanly."""
    daemon = TelemetryDaemon(interval_sec=0.1)
    received: list[dict] = []

    def listener(m: dict):
        received.append(m)

    daemon.subscribe(listener)
    assert listener in daemon._listeners

    daemon.unsubscribe(listener)
    assert listener not in daemon._listeners

    # Unsubscribing non-existent listener is safe no-op
    daemon.unsubscribe(listener)


def test_telemetry_daemon_thread_lifecycle():
    """Verify daemon thread starts, reports is_running, dispatches metrics, and stops."""
    received = []
    daemon = TelemetryDaemon(interval_sec=0.1, callback=lambda m: received.append(m))
    assert daemon.is_running is False

    daemon.start()
    assert daemon.is_running is True

    # Duplicate start is idempotent
    daemon.start()
    assert daemon.is_running is True

    # Allow daemon to tick once or twice
    time.sleep(0.25)
    daemon.stop(timeout=1.0)
    assert daemon.is_running is False

    assert len(received) >= 1

    # Duplicate stop is idempotent
    daemon.stop(timeout=1.0)
    assert daemon.is_running is False


def test_telemetry_listener_exception_isolation():
    """Verify exceptions in listeners do not crash the background daemon thread."""
    def buggy_listener(m: dict):
        raise RuntimeError("Simulated listener crash")

    daemon = TelemetryDaemon(interval_sec=0.1, callback=buggy_listener)
    daemon.start()
    time.sleep(0.2)
    # Daemon should still be running despite listener error
    assert daemon.is_running is True
    daemon.stop(timeout=1.0)
    assert daemon.is_running is False
