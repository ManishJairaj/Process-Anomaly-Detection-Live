#!/usr/bin/env python3
"""
demo_workload.py — Safe, Non-Destructive Live Demonstration Workload Generator (Stage 25)

Process Anomaly Detection Using System Calls with eBPF

Purpose:
  Simulates realistic Linux system call sequences and streams them into the CSV
  dataset (default: syscall_dataset.csv) in the exact format produced by the live
  eBPF detector. This enables complete end-to-end evaluation and live demonstration
  of:
    - Real-time event ingestion and dynamic throughput charts
    - Live anomaly detection feed (NORMAL vs SUSPICIOUS)
    - Full range of explainable rule-based severities: CRITICAL, HIGH, MEDIUM, LOW
    - Process-wise monitoring, per-PID sliding windows, and behavioral timelines
    - Persistent SQLite alert history, incident management, and triage notes
  without requiring kernel root/eBPF privileges.

CSV Format:
  monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label

Usage:
  python3 tools/demo_workload.py [options]

Options:
  --output, -o <path>    Path to output CSV (default: syscall_dataset.csv)
  --rate, -r <float>     Events per second (default: 4.0)
  --count, -n <int>      Total number of events to emit (default: 0 = continuous)
  --duration, -d <sec>   Stop after this many seconds (default: 0 = infinite)
  --batch <int>          Emit a quick diverse batch of N events and exit
  --clean                Reinitialize the CSV with header before streaming
  --quiet, -q            Suppress stdout logging
"""

import os
import sys
import time
import random
import argparse
from typing import List, Tuple, Dict, Any

# ==============================================================================
# Workload Scenario Definitions
# ==============================================================================

# Normal routine sequences (Score < 0.80, Label: NORMAL)
BENIGN_WORKLOADS = [
    {
        "proc": "nginx",
        "pid": 1024,
        "sequences": [
            (232, 288, 40, 0.0042),   # epoll_wait -> accept4 -> sendfile
            (0, 1, 3, 0.0018),         # read -> write -> close
            (7, 0, 1, 0.0031),         # poll -> read -> write
            (232, 0, 1, 0.0025),       # epoll_wait -> read -> write
        ]
    },
    {
        "proc": "systemd-journal",
        "pid": 412,
        "sequences": [
            (0, 20, 232, 0.0012),      # read -> writev -> epoll_wait
            (232, 0, 202, 0.0028),     # epoll_wait -> read -> futex
            (202, 0, 20, 0.0019),      # futex -> read -> writev
        ]
    },
    {
        "proc": "python3",
        "pid": 2840,
        "sequences": [
            (202, 0, 1, 0.0021),       # futex -> read -> write
            (0, 1, 202, 0.0035),       # read -> write -> futex
            (9, 11, 202, 0.0150),      # mmap -> munmap -> futex
            (12, 0, 1, 0.0080),        # brk -> read -> write
        ]
    },
    {
        "proc": "bash",
        "pid": 3150,
        "sequences": [
            (0, 1, 3, 0.0045),         # read -> write -> close
            (14, 0, 1, 0.0062),        # rt_sigprocmask -> read -> write
            (61, 14, 0, 0.0120),       # wait4 -> rt_sigprocmask -> read
        ]
    },
    {
        "proc": "postgres",
        "pid": 1820,
        "sequences": [
            (23, 0, 1, 0.0033),        # select -> read -> write
            (74, 23, 0, 0.0041),       # fsync -> select -> read
            (202, 23, 74, 0.0029),     # futex -> select -> fsync
        ]
    }
]

# Deviant sequences categorized by expected triage severity level
DEVIANT_WORKLOADS = [
    # --------------------------------------------------------------------------
    # CRITICAL SEVERITY (Privilege escalation, shell with net, code injection)
    # --------------------------------------------------------------------------
    {
        "severity": "CRITICAL",
        "proc": "reverse-shell",
        "pid": 8840,
        "seq": (41, 42, 59),           # socket -> connect -> execve
        "score": 1.0000,
        "description": "Remote shell delivery (execve coupled with network connect)"
    },
    {
        "severity": "CRITICAL",
        "proc": "priv-esc-tool",
        "pid": 9120,
        "seq": (102, 105, 126),        # getuid -> setuid -> capset
        "score": 1.0000,
        "description": "Privilege escalation (setuid + capset capability manipulation)"
    },
    {
        "severity": "CRITICAL",
        "proc": "mem-injector",
        "pid": 9450,
        "seq": (101, 9, 10),           # ptrace -> mmap -> mprotect
        "score": 1.0000,
        "description": "Process injection (ptrace combined with memory protection alteration)"
    },
    {
        "severity": "CRITICAL",
        "proc": "container-escape",
        "pid": 9610,
        "seq": (165, 161, 155),        # mount -> chroot -> pivot_root
        "score": 1.0000,
        "description": "Namespace / root pivot (chroot + pivot_root container breakout primitive)"
    },

    # --------------------------------------------------------------------------
    # HIGH SEVERITY (Execution, network socketing, permission changes)
    # --------------------------------------------------------------------------
    {
        "severity": "HIGH",
        "proc": "spawn-agent",
        "pid": 7210,
        "seq": (57, 56, 59),           # fork -> clone -> execve
        "score": 1.0000,
        "description": "Process execution primitive (fork -> clone -> execve)"
    },
    {
        "severity": "HIGH",
        "proc": "recon-scanner",
        "pid": 7340,
        "seq": (41, 49, 50),           # socket -> bind -> listen
        "score": 1.0000,
        "description": "Network primitive (socket -> bind -> listen port binding)"
    },
    {
        "severity": "HIGH",
        "proc": "perm-tamper",
        "pid": 7560,
        "seq": (2, 90, 92),            # open -> chmod -> chown
        "score": 1.0000,
        "description": "Permission alteration (chmod -> chown access modification)"
    },
    {
        "severity": "HIGH",
        "proc": "proc-terminator",
        "pid": 7890,
        "seq": (62, 200, 234),         # kill -> tkill -> tgkill
        "score": 1.0000,
        "description": "Process termination signaling (kill -> tkill -> tgkill)"
    },

    # --------------------------------------------------------------------------
    # MEDIUM SEVERITY (Filesystem mutation, unseen sequences, statistical dev)
    # --------------------------------------------------------------------------
    {
        "severity": "MEDIUM",
        "proc": "dir-wiper",
        "pid": 6120,
        "seq": (83, 84, 87),           # mkdir -> rmdir -> unlink
        "score": 1.0000,
        "description": "Filesystem mutation (mkdir -> rmdir -> unlink)"
    },
    {
        "severity": "MEDIUM",
        "proc": "novel-service",
        "pid": 6340,
        "seq": (28, 158, 202),         # madvise -> arch_prctl -> futex
        "score": 1.0000,
        "description": "Novel unseen 3-gram sequence never observed during baseline training"
    },
    {
        "severity": "MEDIUM",
        "proc": "stats-deviant",
        "pid": 6550,
        "seq": (217, 72, 73),          # getdents64 -> fcntl -> flock
        "score": 0.8850,
        "description": "Statistically deviant sequence above 0.80 anomaly threshold"
    },

    # --------------------------------------------------------------------------
    # LOW SEVERITY (Marginal score consisting purely of routine I/O primitives)
    # --------------------------------------------------------------------------
    {
        "severity": "LOW",
        "proc": "cron-poller",
        "pid": 5110,
        "seq": (201, 4, 3),            # time -> stat -> close
        "score": 0.8350,
        "description": "Marginal routine I/O deviation (score near threshold: 0.8350)"
    },
    {
        "severity": "LOW",
        "proc": "rsync-stat",
        "pid": 5220,
        "seq": (5, 8, 3),              # fstat -> lseek -> close
        "score": 0.8420,
        "description": "Marginal filesystem probing routine (score: 0.8420)"
    }
]

# Header matching detector output exactly
CSV_HEADER = "monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n"

# ==============================================================================
# Helper Functions
# ==============================================================================

def get_current_timestamp_ns() -> int:
    """Returns monotonic or epoch-aligned nanoseconds for timestamps."""
    return time.time_ns()


def format_csv_line(ts: int, pid: int, proc: str, s1: int, s2: int, s3: int, score: float, label: str) -> str:
    """Formats an event tuple as a CSV line."""
    return f"{ts},{pid},{proc},{s1},{s2},{s3},{score:.4f},{label}\n"


def init_csv(csv_path: str, force_clean: bool = False):
    """Initializes CSV file if it does not exist or if clean is requested."""
    out_dir = os.path.dirname(csv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    if force_clean or not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(CSV_HEADER)
            f.flush()


def emit_event(csv_path: str, pid: int, proc: str, s1: int, s2: int, s3: int, score: float, label: str) -> str:
    """Appends an event to the CSV dataset."""
    ts = get_current_timestamp_ns()
    line = format_csv_line(ts, pid, proc, s1, s2, s3, score, label)
    with open(csv_path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    return line


# ==============================================================================
# Generator Modes
# ==============================================================================

def run_batch(csv_path: str, count: int, quiet: bool = False):
    """Emits a diverse batch of benign and deviant events across all severities."""
    init_csv(csv_path, force_clean=False)
    if not quiet:
        print(f"[DEMO] Emitting batch of {count} diverse events to: {csv_path}")

    # Emit benign events
    benign_count = max(count // 2, 1)
    deviant_count = max(count - benign_count, len(DEVIANT_WORKLOADS))

    emitted = 0
    # 1. Benign stream
    for _ in range(benign_count):
        worker = random.choice(BENIGN_WORKLOADS)
        seq_info = random.choice(worker["sequences"])
        s1, s2, s3, score = seq_info
        emit_event(csv_path, worker["pid"], worker["proc"], s1, s2, s3, score, "NORMAL")
        emitted += 1

    # 2. All deviant anomalies covering CRITICAL, HIGH, MEDIUM, LOW
    for dev in DEVIANT_WORKLOADS:
        s1, s2, s3 = dev["seq"]
        emit_event(csv_path, dev["pid"], dev["proc"], s1, s2, s3, dev["score"], "SUSPICIOUS")
        emitted += 1
        if not quiet:
            print(f"  -> Injected {dev['severity']:<8} Alert: {dev['proc']} (PID {dev['pid']}) -- {dev['description']}")

    if not quiet:
        print(f"[DEMO] Successfully wrote {emitted} events to {csv_path}.")


def run_stream(csv_path: str, rate: float, total_count: int, duration: float, quiet: bool = False):
    """Continuously streams events into CSV at given rate."""
    init_csv(csv_path, force_clean=False)
    interval = 1.0 / max(rate, 0.1)

    if not quiet:
        print("=" * 65)
        print(" Process Anomaly Detection — Live Demo Workload Stream")
        print("=" * 65)
        print(f" Target CSV      : {csv_path}")
        print(f" Event Rate      : {rate:.1f} events/sec")
        print(f" Anomaly Mix     : ~20% Deviant (Spanning CRITICAL, HIGH, MEDIUM, LOW)")
        print(f" Total Limit     : {total_count if total_count > 0 else 'Unlimited'} events")
        print(f" Duration Limit  : {duration if duration > 0 else 'Unlimited'} seconds")
        print(" Press Ctrl+C to stop stream cleanly.")
        print("=" * 65)

    start_time = time.time()
    events_sent = 0
    anomalies_sent = 0
    deviant_idx = 0

    try:
        while True:
            now = time.time()
            if duration > 0 and (now - start_time) >= duration:
                if not quiet:
                    print(f"\n[DEMO] Duration limit ({duration}s) reached.")
                break
            if total_count > 0 and events_sent >= total_count:
                if not quiet:
                    print(f"\n[DEMO] Event count limit ({total_count}) reached.")
                break

            # 80% benign background, 20% security anomaly
            is_anomaly = (random.random() < 0.22) or (events_sent % 6 == 0 and anomalies_sent < len(DEVIANT_WORKLOADS))

            if is_anomaly:
                dev = DEVIANT_WORKLOADS[deviant_idx % len(DEVIANT_WORKLOADS)]
                deviant_idx += 1
                s1, s2, s3 = dev["seq"]
                emit_event(csv_path, dev["pid"], dev["proc"], s1, s2, s3, dev["score"], "SUSPICIOUS")
                events_sent += 1
                anomalies_sent += 1
                if not quiet:
                    print(f"[{time.strftime('%H:%M:%S')}] [ALERT] {dev['severity']:<8} PID={dev['pid']:<5} {dev['proc']:<16} Seq=({s1},{s2},{s3}) Score={dev['score']:.4f}")
            else:
                worker = random.choice(BENIGN_WORKLOADS)
                seq_info = random.choice(worker["sequences"])
                s1, s2, s3, score = seq_info
                emit_event(csv_path, worker["pid"], worker["proc"], s1, s2, s3, score, "NORMAL")
                events_sent += 1
                if not quiet and events_sent % 10 == 0:
                    print(f"[{time.strftime('%H:%M:%S')}] [NORMAL] Stream active — Total: {events_sent} | Anomalies: {anomalies_sent}")

            time.sleep(interval)

    except KeyboardInterrupt:
        if not quiet:
            print("\n[DEMO] Stream stopped by user (Ctrl+C).")

    if not quiet:
        elapsed = time.time() - start_time
        print(f"[DEMO] Completed: {events_sent} events ({anomalies_sent} alerts) written in {elapsed:.1f}s.")


def run_interactive(csv_path: str):
    """Step-by-step guided demonstration for viva and technical presentations."""
    init_csv(csv_path, force_clean=False)
    print("=" * 68)
    print(" Process Anomaly Detection — Step-by-Step Viva Demonstration")
    print("=" * 68)
    print(" This mode guides the presenter through the 12 demonstration actions.")
    print(" Keep your web dashboard open at http://127.0.0.1:5000/")
    print("=" * 68)

    steps = [
        ("Step 1: Normal Baseline Workload", 
         "Generating benign web server and database routine system calls...",
         lambda: [
             emit_event(csv_path, 1024, "nginx", 232, 288, 40, 0.0042, "NORMAL"),
             emit_event(csv_path, 1024, "nginx", 0, 1, 3, 0.0018, "NORMAL"),
             emit_event(csv_path, 1820, "postgres", 23, 0, 1, 0.0033, "NORMAL"),
             emit_event(csv_path, 2840, "python3", 202, 0, 1, 0.0021, "NORMAL"),
         ]),
        ("Step 2: Low-Severity Routine I/O Deviation (LOW)",
         "Generating low-risk time/stat polling sequence (score 0.8350)...",
         lambda: [
             emit_event(csv_path, 5110, "cron-poller", 201, 4, 3, 0.8350, "SUSPICIOUS")
         ]),
        ("Step 3: Medium-Severity Filesystem Mutation (MEDIUM)",
         "Generating filesystem directory tampering sequence (mkdir -> rmdir -> unlink)...",
         lambda: [
             emit_event(csv_path, 6120, "dir-wiper", 83, 84, 87, 1.0000, "SUSPICIOUS")
         ]),
        ("Step 4: High-Severity Process Execution (HIGH)",
         "Generating process spawning sequence (fork -> clone -> execve)...",
         lambda: [
             emit_event(csv_path, 7210, "spawn-agent", 57, 56, 59, 1.0000, "SUSPICIOUS")
         ]),
        ("Step 5: High-Severity Port Listening / Persistence (HIGH)",
         "Generating network listener socket sequence (socket -> bind -> listen)...",
         lambda: [
             emit_event(csv_path, 7340, "recon-scanner", 41, 49, 50, 1.0000, "SUSPICIOUS")
         ]),
        ("Step 6: Critical-Severity Remote Shell Delivery (CRITICAL)",
         "Generating remote connection coupled with execve execution (socket -> connect -> execve)...",
         lambda: [
             emit_event(csv_path, 8840, "reverse-shell", 41, 42, 59, 1.0000, "SUSPICIOUS")
         ]),
        ("Step 7: Critical-Severity Privilege Escalation (CRITICAL)",
         "Generating user ID and capability tampering sequence (getuid -> setuid -> capset)...",
         lambda: [
             emit_event(csv_path, 9120, "priv-esc-tool", 102, 105, 126, 1.0000, "SUSPICIOUS")
         ]),
    ]

    for title, desc, action in steps:
        print(f"\n>>> {title}")
        print(f"    {desc}")
        input("    [Press Enter to emit events and verify on Dashboard...]")
        action()
        print("    -> Events emitted! Check the Dashboard Live Feed & Security Triage table.")

    print("\n" + "=" * 68)
    print(" Demonstration sequence complete!")
    print(" Presenters can now proceed to Alert History, edit Incident Status,")
    print(" record Investigation Notes, and demonstrate persistent SQLite storage.")
    print("=" * 68)


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Safe Demo Workload Generator for Process Anomaly Detection (Stage 25)"
    )
    parser.add_argument("--output", "-o", default="syscall_dataset.csv",
                        help="Path to CSV dataset output (default: syscall_dataset.csv)")
    parser.add_argument("--rate", "-r", type=float, default=4.0,
                        help="Events per second in streaming mode (default: 4.0)")
    parser.add_argument("--count", "-n", type=int, default=0,
                        help="Total number of events to emit (default: 0 = unlimited)")
    parser.add_argument("--duration", "-d", type=float, default=0,
                        help="Duration to run in seconds (default: 0 = unlimited)")
    parser.add_argument("--batch", type=int, default=0,
                        help="Emit a quick batch of N events and exit immediately")
    parser.add_argument("--clean", action="store_true",
                        help="Reinitialize the CSV with header before running")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Run interactive step-by-step presentation mode")
    parser.add_argument("--stream", action="store_true",
                        help="Run in continuous streaming mode (default if no batch/interactive)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress stdout messages")

    args = parser.parse_args()

    # Resolve output path
    csv_path = os.path.abspath(args.output)

    if args.clean:
        init_csv(csv_path, force_clean=True)
        if not args.quiet:
            print(f"[DEMO] Initialized clean CSV at: {csv_path}")

    if args.interactive:
        run_interactive(csv_path)
    elif args.batch > 0:
        run_batch(csv_path, args.batch, quiet=args.quiet)
    else:
        # Default mode is streaming
        run_stream(csv_path, args.rate, args.count, args.duration, quiet=args.quiet)


if __name__ == "__main__":
    main()
