"""Demonstration script: Runaway infinite loop.

Used in Viva Demo 2 to demonstrate the AgentOS Process Watchdog
intercepting hung execution and recursively terminating the process tree.
"""

import time
import sys

print("[INFINITE_LOOP] Process started. Entering non-terminating busy loop...", flush=True)

try:
    counter = 0
    while True:
        time.sleep(0.1)
        counter += 1
        if counter % 50 == 0:
            print(f"[INFINITE_LOOP] Still running at iteration {counter}...", flush=True)
except KeyboardInterrupt:
    print("[INFINITE_LOOP] Interrupted by supervisor signal.", flush=True)
    sys.exit(0)
