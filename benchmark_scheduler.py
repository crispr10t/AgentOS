"""Scheduler Benchmarking & Comparative Evaluation Tool for AgentOS.

Demonstrates and verifies fundamental OS scheduling principles:
1. First-Come, First-Served (FCFS) & the Convoy Effect.
2. Non-preemptive Priority Scheduling.
3. Shortest Job First (SJF) and its optimality for minimizing Average Waiting Time.

Supports tabular console output, GitHub-flavored Markdown for academic reports,
and JSON data export for automated verification pipelines.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Optional

from kernel.pcb import TaskPCB
from kernel.scheduler import SchedulingPolicy, TaskScheduler


def generate_benchmark_tasks() -> list[TaskPCB]:
    """Generates standard 5 synthetic benchmark tasks with varied priorities and burst durations."""
    return [
        TaskPCB(pid=1, name="heavy_compile", priority=1, estimated_duration=12.0),
        TaskPCB(pid=2, name="quick_lint", priority=5, estimated_duration=1.5),
        TaskPCB(pid=3, name="unit_tests", priority=8, estimated_duration=4.0),
        TaskPCB(pid=4, name="clean_cache", priority=2, estimated_duration=0.5),
        TaskPCB(pid=5, name="security_audit", priority=10, estimated_duration=3.0),
    ]


def run_benchmark(tasks: Optional[list[TaskPCB]] = None) -> dict[str, Any]:
    """Runs simulation for FCFS, Priority, and SJF scheduling policies.

    Args:
        tasks: Optional list of TaskPCBs. If None, default benchmark set is used.

    Returns:
        Dictionary containing raw tasks, policy results, and comparative metrics.
    """
    if tasks is None:
        tasks = generate_benchmark_tasks()

    policies = [
        SchedulingPolicy.FCFS,
        SchedulingPolicy.PRIORITY,
        SchedulingPolicy.SJF,
    ]

    results: dict[str, Any] = {
        "workload": [
            {
                "pid": t.pid,
                "name": t.name,
                "priority": t.priority,
                "estimated_duration": t.estimated_duration,
            }
            for t in tasks
        ],
        "policies": {},
    }

    for pol in policies:
        completed, metrics = TaskScheduler.simulate_batch(tasks, policy=pol)
        order_names = [t.name for t in completed]
        order_pids = [t.pid for t in completed]
        total_exec = sum(t.estimated_duration for t in completed)

        results["policies"][pol.value] = {
            "policy": pol.value,
            "dispatch_order": order_names,
            "dispatch_pids": order_pids,
            "avg_waiting_time": round(metrics["avg_waiting_time"], 2),
            "avg_turnaround_time": round(metrics["avg_turnaround_time"], 2),
            "total_execution_time": round(total_exec, 2),
            "tasks_completed": len(completed),
            "detailed_tasks": [
                {
                    "pid": t.pid,
                    "name": t.name,
                    "waiting_time": round(t.waiting_time or 0.0, 2),
                    "turnaround_time": round(t.turnaround_time or 0.0, 2),
                }
                for t in completed
            ],
        }

    # Comparative Analysis
    fcfs_wait = results["policies"][SchedulingPolicy.FCFS.value]["avg_waiting_time"]
    sjf_wait = results["policies"][SchedulingPolicy.SJF.value]["avg_waiting_time"]
    priority_wait = results["policies"][SchedulingPolicy.PRIORITY.value]["avg_waiting_time"]

    convoy_ratio = round(fcfs_wait / sjf_wait, 2) if sjf_wait > 0 else 0.0
    wait_reduction_pct = round(((fcfs_wait - sjf_wait) / fcfs_wait) * 100, 1) if fcfs_wait > 0 else 0.0

    results["analysis"] = {
        "convoy_effect_ratio": convoy_ratio,
        "sjf_wait_reduction_percent": wait_reduction_pct,
        "sjf_optimal": sjf_wait <= fcfs_wait and sjf_wait <= priority_wait,
    }

    return results


def format_table(results: dict[str, Any]) -> str:
    """Formats benchmark results as a CLI ASCII table."""
    lines: list[str] = []
    lines.append("=" * 80)
    lines.append(" AgentOS Task Scheduler Benchmark — Quantitative Performance Evaluation")
    lines.append("=" * 80)
    lines.append(f"{'PID':<5} {'Task Name':<18} {'Priority':<10} {'Est Duration (s)':<18}")
    lines.append("-" * 80)
    for t in results["workload"]:
        lines.append(f"{t['pid']:<5} {t['name']:<18} {t['priority']:<10} {t['estimated_duration']:<18.1f}")
    lines.append("=" * 80)

    lines.append(f"{'Policy':<12} {'Avg Wait':<12} {'Avg Turnaround':<16} {'Dispatch Order':<38}")
    lines.append("-" * 80)
    for pol_name, data in results["policies"].items():
        order_str = " -> ".join(data["dispatch_order"])
        lines.append(
            f"{pol_name:<12} {data['avg_waiting_time']:<12.2f} {data['avg_turnaround_time']:<16.2f} {order_str:<38}"
        )
    lines.append("=" * 80)

    analysis = results["analysis"]
    lines.append("Theoretical Operating System Observations:")
    lines.append(
        f" - SJF achieves minimal Average Waiting Time, reducing latency by "
        f"{analysis['sjf_wait_reduction_percent']}% over FCFS."
    )
    lines.append(
        f" - FCFS suffers from the Convoy Effect (Convoy Penalty Ratio: {analysis['convoy_effect_ratio']}x) "
        "because short tasks wait behind 'heavy_compile'."
    )
    lines.append(" - Priority scheduling prioritizes critical operations regardless of burst duration.")
    lines.append("=" * 80)

    return "\n".join(lines)


def format_markdown(results: dict[str, Any]) -> str:
    """Formats benchmark results as a GitHub Flavored Markdown table for academic reports."""
    lines: list[str] = []
    lines.append("### Empirical Scheduler Benchmark Results\n")
    lines.append("#### Synthetic Workload Profile\n")
    lines.append("| PID | Task Name | Priority (1-10) | Estimated Duration (s) |")
    lines.append("|---|---|---|---|")
    for t in results["workload"]:
        lines.append(f"| {t['pid']} | `{t['name']}` | {t['priority']} | {t['estimated_duration']:.1f}s |")

    lines.append("\n#### Comparative Performance Evaluation\n")
    lines.append("| Scheduling Policy | Average Waiting Time ($T_{wait}$) | Average Turnaround Time ($T_{turnaround}$) | Dispatch Sequence |")
    lines.append("|---|---|---|---|")
    for pol_name, data in results["policies"].items():
        order_code = " &rarr; ".join([f"`{name}`" for name in data["dispatch_order"]])
        lines.append(
            f"| **{pol_name}** | **{data['avg_waiting_time']:.2f}s** | **{data['avg_turnaround_time']:.2f}s** | {order_code} |"
        )

    analysis = results["analysis"]
    lines.append("\n#### Quantitative Analysis")
    lines.append(
        f"- **Convoy Effect Penalty**: Under FCFS, tasks suffer a **{analysis['convoy_effect_ratio']}x** higher average waiting time compared to SJF."
    )
    lines.append(
        f"- **SJF Latency Optimization**: Shortest Job First yields a **{analysis['sjf_wait_reduction_percent']}% reduction** in average wait time."
    )
    lines.append(
        "- **Priority Responsiveness**: Critical tasks (`security_audit`) achieve immediate CPU dispatch ($W=0.00s$)."
    )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="AgentOS Task Scheduler Benchmark & Comparative Evaluation."
    )
    parser.add_argument(
        "--format",
        choices=["table", "markdown", "json"],
        default="table",
        help="Output format (table, markdown, or json).",
    )
    parser.add_argument(
        "--export",
        type=str,
        default=None,
        help="Optional file path to write results to.",
    )

    args = parser.parse_args()
    results = run_benchmark()

    if args.format == "json":
        output = json.dumps(results, indent=2)
    elif args.format == "markdown":
        output = format_markdown(results)
    else:
        output = format_table(results)

    if args.export:
        out_path = Path(args.export)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"[BENCHMARK] Exported benchmark results to '{out_path}'.")
    else:
        print(output)


if __name__ == "__main__":
    main()
