"""Demonstration script: Configurable synthetic CPU worker.

Accepts duration in seconds as argument and simulates workload.
Used in Viva Demo 1 & Demo 5 for scheduling order verification.
"""

import sys
import time

duration = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0
task_name = sys.argv[2] if len(sys.argv) > 2 else "worker_task"

print(f"[WORKER] Starting task '{task_name}' (target duration: {duration:.2f}s)...", flush=True)
start = time.time()
time.sleep(duration)
elapsed = time.time() - start

print(f"[WORKER] Task '{task_name}' completed successfully in {elapsed:.2f}s.", flush=True)
sys.exit(0)
