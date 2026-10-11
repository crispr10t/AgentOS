"""Scheduler Benchmarking Script for AgentOS Viva Demonstration.

Compares Turnaround Time and Waiting Time across FCFS, Priority, and SJF
scheduling policies on synthetic workloads to illustrate core OS scheduling principles.
"""

from kernel.pcb import TaskPCB
from kernel.scheduler import SchedulingPolicy, TaskScheduler


def run_benchmark():
    # 5 synthetic tasks with diverse priorities and estimated burst durations
    tasks = [
        TaskPCB(pid=1, name="heavy_compile", priority=1, estimated_duration=12.0),
        TaskPCB(pid=2, name="quick_lint", priority=5, estimated_duration=1.5),
        TaskPCB(pid=3, name="unit_tests", priority=8, estimated_duration=4.0),
        TaskPCB(pid=4, name="clean_cache", priority=2, estimated_duration=0.5),
        TaskPCB(pid=5, name="security_audit", priority=10, estimated_duration=3.0),
    ]

    print("=" * 72)
    print(" AgentOS Task Scheduler Benchmark — Viva Demonstration")
    print("=" * 72)
    print(f"{'PID':<5} {'Task Name':<16} {'Priority':<10} {'Est Duration (s)':<18}")
    print("-" * 72)
    for t in tasks:
        print(f"{t.pid:<5} {t.name:<16} {t.priority:<10} {t.estimated_duration:<18.1f}")
    print("=" * 72)

    policies = [
        SchedulingPolicy.FCFS,
        SchedulingPolicy.PRIORITY,
        SchedulingPolicy.SJF,
    ]

    print(f"{'Policy':<12} {'Dispatch Order':<36} {'Avg Wait':<10} {'Avg Turnaround':<14}")
    print("-" * 72)

    for pol in policies:
        completed, metrics = TaskScheduler.simulate_batch(tasks, policy=pol)
        order_str = " -> ".join([t.name for t in completed])
        avg_wait = f"{metrics['avg_waiting_time']:.2f}s"
        avg_turn = f"{metrics['avg_turnaround_time']:.2f}s"
        print(f"{pol.value:<12} {order_str:<36} {avg_wait:<10} {avg_turn:<14}")

    print("=" * 72)
    print("Observation:")
    print(" - SJF achieves the lowest Average Waiting Time (optimal for non-preemptive batches).")
    print(" - Priority ensures critical operations (e.g. security_audit) run immediately.")
    print(" - FCFS suffers from the Convoy Effect due to the leading heavy_compile task.")
    print("=" * 72)


if __name__ == "__main__":
    run_benchmark()
