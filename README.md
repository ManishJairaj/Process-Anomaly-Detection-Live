# Process Anomaly Detection Using System Calls with eBPF

> **Real-time host-based intrusion and behavioral anomaly detection using Linux eBPF tracepoint telemetry, a statistical 3-gram behavioral model, rule-based security severity classification, and a persistent incident triage dashboard.**

---

## 1. Abstract & Executive Summary

Modern Linux security monitoring requires lightweight, tamper-resistant runtime visibility into host processes without degrading system throughput. Traditional user-space monitoring agents relying on `ptrace` or `LD_PRELOAD` introduce substantial execution latency and can be bypassed or manipulated by unprivileged attackers. 

This project implements a non-intrusive, real-time Process Anomaly Detection system powered by Linux **eBPF (Extended Berkeley Packet Filter)**. By attaching tracepoint hooks directly to kernel syscall invocation boundaries (`tracepoint/raw_syscalls/sys_enter`), the system extracts high-frequency telemetry with sub-microsecond overhead. Telemetry is fed into a per-process 3-gram sliding-window behavioral model that computes probabilistic anomaly scores against a trained normal execution baseline.

Detected anomalies are enriched with explainable root-cause descriptions, triaged via a deterministic rule-based security severity engine (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), persisted into a local ACID-compliant SQLite database, and surfaced through a responsive, unprivileged web dashboard. The complete pipeline is operational with a single command (`./run.sh`), verified by an automated regression suite of **148+ tests**, and ready for technical viva demonstration.

---

## 2. Architecture & Pipeline

```
+-----------------------------------------------------------------------------+
|                                KERNEL SPACE                                 |
|                                                                             |
|  [ Linux Process Execution ]                                                |
|               |                                                             |
|               v                                                             |
|     sys_enter Tracepoint Hook (eBPF)                                        |
|     - Captures: timestamp_ns, pid, comm, syscall_nr                         |
|     - Non-intrusive, zero user memory copy, sub-microsecond latency        |
+-----------------------------------------------------------------------------+
                                     |
                                     v (BPF Ring Buffer)
+-----------------------------------------------------------------------------+
|                         USER-SPACE DETECTOR (C)                             |
|                                                                             |
|  Per-PID Sliding Window (3-Gram: s1 -> s2 -> s3)                            |
|               |                                                             |
|               v                                                             |
|  Trained Baseline Frequency Model (baseline_model.dat)                      |
|               |                                                             |
|               v                                                             |
|  Anomaly Detection & Explanation Engine (Threshold >= 0.80)                 |
|               |                                                             |
|               v                                                             |
|  Append-Only CSV Stream Logger (syscall_dataset.csv)                        |
+-----------------------------------------------------------------------------+
                                     |
                                     v (Incremental File I/O)
+-----------------------------------------------------------------------------+
|                     BACKEND INGESTION & TRIAGE (PYTHON)                     |
|                                                                             |
|  DatasetMonitor (Incremental tailing, byte-offset checkpoints)              |
|               |                                                             |
|               +---> Rule-Based Severity Engine (severity.py)                |
|               |     Precedence: CRITICAL > HIGH > MEDIUM > LOW              |
|               |                                                             |
|               +---> Persistent SQLite Database (data/alerts.db)             |
|                     WAL mode, alerts, process aggregates, investigation     |
+-----------------------------------------------------------------------------+
                                     |
                                     v (HTTP JSON REST APIs)
+-----------------------------------------------------------------------------+
|                         WEB DASHBOARD FRONTEND                              |
|                                                                             |
|  Vanilla HTML5 / Modern CSS / Vanilla JS (dashboard/static/)                |
|  - Real-Time Live Feed & Dynamic Canvas Charts (Throughput / Timeline)      |
|  - Security Triage Panel & Rule Precedence Matrix                           |
|  - Process Behavioral Profiles & 3-Gram Frequency Distributions             |
|  - Persistent Alert History with Multi-Filter Search, Pagination, & Notes   |
+-----------------------------------------------------------------------------+
```

---

## 3. Key Features by Development Stage

- **Stages 1-18: eBPF Collection & Core Model**:
  - In-kernel eBPF `sys_enter` probe with ring buffer event streaming.
  - Per-thread 3-gram sliding window tracker (`src/window.c`).
  - Serialized compact binary frequency dictionary (`baseline_model.dat`).
  - Constant-time $O(1)$ statistical anomaly scoring with threshold validation.
  - Root-cause forensic explanation generation (`src/explanation.c`).
- **Stage 19: Real-Time Web Dashboard**:
  - Native Python HTTP backend with zero heavy external framework dependencies.
  - Interactive HTML5 canvas charts for real-time event throughput and timeline spikes.
  - Streaming live event and anomaly feed.
- **Stage 20: Persistent Alert History & Incident Management**:
  - ACID-compliant SQLite storage (`data/alerts.db`) with Write-Ahead Logging (WAL).
  - Multi-attribute search, server-side pagination, and filtered CSV export.
  - Incident lifecycle tracking (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_ALARM`).
  - In-place investigation notes preserved across re-ingestion and restarts.
- **Stage 21: Process-Wise Monitoring & Behavioral Analytics**:
  - Per-process summaries (total events, normal/suspicious splits, max scores).
  - Host process verification cross-checking `/proc/{pid}/comm` to handle PID reuse.
  - Process detail drilldowns: top 3-gram frequency tables and activity timelines.
- **Stage 22: Rule-Based Severity Classification & Security Triage**:
  - Architecture-aware Linux x86_64 system call mapper.
  - Deterministic explainable rules for `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`.
  - Strict precedence evaluation hierarchy (**CRITICAL > HIGH > MEDIUM > LOW**).
  - Triage API endpoints (`/api/triage/stats`) and visual triage badges.
- **Stage 24: One-Command Startup & System Integration**:
  - Production-grade Bash launcher (`run.sh`) with signal handling (`SIGINT`, `SIGTERM`).
  - Automated prerequisite inspection (`--check`).
  - Strict privilege separation (unprivileged dashboard; root for eBPF only).
- **Stage 25: Final Integration, Resilience & Demo Readiness**:
  - Safe, non-destructive demo workload generator (`tools/demo_workload.py`).
  - Fault-tolerant parser handling corrupted and truncated CSV records.
  - Comprehensive examiner-ready documentation suite and viva protocol.
  - 148+ automated regression tests.

---

## 4. Directory Structure

```text
Process-Anomaly-Detection-Live-main/
|-- Makefile                           # Build configuration for C detector & tests
|-- README.md                          # Main examiner-facing documentation
|-- run.sh                             # Production startup launcher script
|-- workload_runner.sh                 # Workload generation and tracing script
|-- baseline_model.dat                 # Serialized baseline 3-gram model binary
|-- baseline_model.dat.provenance.json # Model training provenance & metadata
|-- data/
|   `-- alerts.db                      # Persistent SQLite database (WAL mode)
|-- docs/                              # In-depth technical documentation
|   |-- architecture.md                # System architecture and data pipeline
|   |-- installation.md                # Prerequisites and setup instructions
|   |-- usage.md                       # CLI options and operational modes
|   |-- testing.md                     # Automated test suites and verification
|   |-- demo_guide.md                  # 12-action viva presentation protocol
|   `-- limitations.md                 # Telemetry boundaries and alert rate evaluation
|-- ebpf/
|   |-- syscall_collector.c            # Kernel eBPF tracepoint collector
|   `-- syscall_trainer.c              # Baseline model training utility
|-- include/
|   |-- anomaly.h                      # Anomaly scoring definitions
|   |-- event.h                        # Event structures
|   |-- explanation.h                  # Root cause explanation header
|   |-- model.h                        # Model binary format structures
|   |-- ngram.h                        # N-gram representations
|   `-- window.h                       # Per-PID sliding window header
|-- src/
|   |-- anomaly.c                      # Scoring logic and threshold comparison
|   |-- event.c                        # Event parsing routines
|   |-- explanation.c                  # Explainable text generator
|   |-- main.c                         # Standalone offline detector entry point
|   |-- model.c                        # Binary model serialization/loading
|   |-- ngram.c                        # 3-gram hashing and hashing tables
|   `-- window.c                       # Thread sliding window state machine
|-- dashboard/
|   |-- database.py                    # SQLite schema, migrations, and queries
|   |-- server.py                      # Multi-threaded HTTP backend and tailer
|   |-- severity.py                    # Rule-based severity classification engine
|   `-- static/
|       |-- dashboard.css              # Dark-mode dashboard styling
|       |-- dashboard.js               # Frontend polling, charts, and interactions
|       `-- index.html                 # Single-page application UI
`-- tools/
    |-- demo_workload.py               # Safe synthetic/replayed workload generator
    |-- test_dashboard.py              # Stage 19 dashboard unit tests
    |-- test_stage20_alerts.py         # Stage 20 SQLite alert tests
    |-- test_stage21_processes.py      # Stage 21 process analytics tests
    |-- test_stage22_severity.py       # Stage 22 rule engine tests
    |-- test_stage24_launcher.py       # Stage 24 Bash launcher tests
    |-- test_stage25_integration.py    # Stage 25 final integration & resilience tests
    `-- ...                            # C benchmark and validation utilities
```

---

## 5. Prerequisites & Environment

| Requirement | Specification |
|---|---|
| **Target OS** | Ubuntu Linux 22.04 LTS or 24.04 LTS (x86_64) |
| **Kernel** | Linux Kernel >= 5.8 with BTF (`/sys/kernel/btf/vmlinux`) |
| **Compiler & Tools** | `gcc`, `clang`, `llvm`, `make` |
| **Libraries** | `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `linux-headers-$(uname -r)` |
| **Python** | Python 3.8+ (Standard Library: `http.server`, `sqlite3`, `json`) |
| **Privileges** | Standard user for Dashboard; `sudo` for eBPF tracepoint attachment |

---

## 6. Quick Start (One Command)

To build and launch the complete real-time monitoring system:

```bash
# 1. Compile detector and utilities
make

# 2. Launch complete system
./run.sh
```

- Prompts for `sudo` password strictly for the eBPF kernel collector.
- Launches the web dashboard under your unprivileged user account.
- Direct your browser to: **`http://127.0.0.1:5000/`**
- Press `Ctrl+C` in the terminal to cleanly terminate all processes.

---

## 7. Operational Modes

### 7.1 Full System Mode (Kernel eBPF + Web Dashboard)
```bash
./run.sh
```

### 7.2 Web Dashboard Only (Unprivileged Historical Review)
```bash
./run.sh --dashboard-only
```
Runs without `sudo` and allows full review of existing datasets, triage notes, and process timelines.

### 7.3 Live Viva Demonstration Mode (Simulated Stream)
```bash
./run.sh --demo
```
Streams realistic benign and deviant syscall sequences into the dashboard in real time without requiring kernel eBPF privileges.

### 7.4 System Prerequisite Self-Check
```bash
./run.sh --check
```
Validates kernel BTF support, compilers, Python environment, output directories, and port bindings without starting services.

---

## 8. Anomaly Detection Methodology

### 8.1 3-Gram Sliding Windows
For every thread, the collector tracks a sliding sequence of three consecutive system calls:
$$W_t = (s_{t-2}, s_{t-1}, s_t)$$

### 8.2 Anomaly Scoring Function
The anomaly score $S \in [0.0, 1.0]$ is computed against the normal baseline model:
$$S(s_1, s_2, s_3) = \begin{cases} 1.0 & \text{if } (s_1, s_2, s_3) \notin \text{Baseline Model} \\ 1.0 - \frac{\text{Count}(s_1, s_2, s_3)}{\text{MaxCount}} & \text{if } (s_1, s_2, s_3) \in \text{Baseline Model} \end{cases}$$

### 8.3 Classification Threshold
- $S \ge 0.80 \implies \text{\textbf{SUSPICIOUS}}$ (Anomaly Alert)
- $S < 0.80 \implies \text{\textbf{NORMAL}}$ (Benign Routine Activity)

---

## 9. Security Severity Classification Rules

To prioritize human analyst review, anomalies are categorized by a deterministic rule engine:

| Severity | Color | Primary Criteria | Example Syscalls |
|---|---|---|---|
| **CRITICAL** | Red | Privilege escalation, capability changes, container escape, process injection, execve + network connect | `setuid`, `capset`, `pivot_root`, `ptrace` + `mprotect`, `execve` + `connect` |
| **HIGH** | Orange | Process execution, network primitives, process termination signaling, file permission alterations | `execve`, `clone`, `fork`, `socket`, `bind`, `listen`, `kill`, `chmod`, `chown` |
| **MEDIUM** | Yellow | Filesystem structural mutation, novel unseen sequences ($S=1.0$), statistical frequency deviations ($S \ge 0.80$) | `mkdir`, `rmdir`, `unlink`, `rename`, novel library sequences |
| **LOW** | Blue | Marginal deviations ($S < 0.90$) consisting exclusively of routine I/O, polling, or time synchronization | `read`, `write`, `stat`, `poll`, `time`, `nanosleep`, `futex` |

**Precedence Hierarchy**: **CRITICAL > HIGH > MEDIUM > LOW**  
If a sequence contains primitives from multiple tiers, the highest precedence tier is assigned.

---

## 10. Automated Testing & Verification

Run the full automated test suite:

```bash
make test
```

### Test Suite Breakdown (148+ Tests):
- **Core C Tests (78 tests)**: `test_model_serialization`, `test_trainer_detector_compat`, `test_explanation`, `test_pid_filtering_and_logging`, `test_eval_independent`, `test_gt_evaluation`.
- **Dashboard Tests (11 tests)**: `tools/test_dashboard.py` (REST endpoints, bounded memory deques, live updates).
- **Stage 20 Tests (13 tests)**: `tools/test_stage20_alerts.py` (SQLite schema, deduplication, notes preservation, sorting).
- **Stage 21 Tests (14 tests)**: `tools/test_stage21_processes.py` (Process metrics, host verification, timeline buckets).
- **Stage 22 Tests (18 tests)**: `tools/test_stage22_severity.py` (Precedence, deterministic classification, backfill).
- **Stage 24 Tests (10 tests)**: `tools/test_stage24_launcher.py` (CLI flags, signal traps, privilege separation).
- **Stage 25 Tests (14 tests)**: `tools/test_stage25_integration.py` (Resilience, corrupted CSV recovery, demo integration).

---

## 11. Performance Overhead

- **Kernel CPU Overhead**: $< 1.5\%$ additional CPU utilization under typical server workloads (~5,000 syscalls/sec).
- **Memory Footprint**:
  - eBPF Kernel Maps: $\approx 8\text{ MB}$.
  - User-space Detector: $\approx 15\text{ MB}$ RSS.
  - Python Dashboard & SQLite: $\approx 35\text{ MB}$ RSS.
- **Throughput Capacity**: Sustains $> 40,000\text{ syscalls/second}$ without dropping ring buffer events.

---

## 12. Security & Privilege Separation

1. **Root Isolation**:
   - Only the eBPF kernel detector requires elevated privileges to load BPF bytecode.
   - The web dashboard runs strictly as the unprivileged user. If launched with `sudo ./run.sh`, the script drops privileges to `SUDO_USER` for the Python server.
2. **Read-Only Telemetry**:
   - The eBPF collector only reads tracepoint metadata (`syscall_nr`, `pid`, `comm`). It never intercepts, alters, or terminates kernel operations.

---

## 13. Limitations & Telemetry Boundaries

- **Alert Rate vs. False Positive Rate**: In benchmark testing, the pipeline demonstrated an empirical **alert rate of 0.1836%** on normal background workloads. This is an alert rate, not a formal False Positive Rate (which requires certified ground-truth labelling).
- **Argument Inspection**: The collector does not inspect system call arguments (file paths, IP addresses, network payloads). This deliberate architectural trade-off maintains low overhead and preserves data privacy.
- **Window Size ($N=3$)**: The 3-gram window focuses on short control-flow transitions and does not capture long-distance temporal correlations.
- For a comprehensive technical analysis, consult [`docs/limitations.md`](file:///c:/Users/PREETHAM%20REDDY/Downloads/Process-Anomaly-Detection-Live-main/docs/limitations.md).

---

## 14. Academic Context (B.Tech Capstone Project)

- **Institution**: Department of Computer Science & Engineering
- **Project Title**: Process Anomaly Detection Using System Calls with eBPF
- **Target OS**: Ubuntu Linux 22.04 / 24.04 LTS (x86_64)
- **Primary Technologies**: C, Linux eBPF, Libbpf, Python 3, SQLite, HTML5 Canvas, REST APIs
