# Architecture & Pipeline Design

**Process Anomaly Detection Using System Calls with eBPF**  
*B.Tech Capstone Project -- System Architecture Documentation*

---

## 1. Executive Architectural Overview

The system monitors Linux process execution at runtime to identify statistically deviant behavior without relying on static signature matching. The architecture is organized as a decoupled, multi-tier data pipeline with strict privilege separation:

1. **Kernel-Space Telemetry**: An eBPF program hooks the Linux `sys_enter` tracepoint to capture raw system call invocations in real time with minimal CPU and memory overhead.
2. **User-Space Collector & Feature Extraction**: A C user-space agent drains ring-buffer events, maintains per-process 3-gram sliding windows, evaluates anomaly scores against an in-memory frequency model, and extracts root-cause explanations.
3. **Structured Event Stream**: Real-time events and anomaly records are appended to an append-only CSV stream (`syscall_dataset.csv`) using monotonic timestamps.
4. **Ingestion & Classification Engine**: A multi-threaded Python backend incrementally tails the CSV, evaluates deterministic rule-based security severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), maintains bounded memory ring buffers, and transactionally synchronizes with an SQLite database.
5. **Persistent Storage & Incident Management**: A durable SQLite database (`data/alerts.db`) tracks anomaly alerts, forensic details, triaged incident statuses (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_ALARM`), analyst investigation notes, and process aggregates.
6. **Live Presentation Dashboard**: A vanilla HTML5/CSS3/JavaScript frontend visualizes real-time throughput metrics, sliding anomaly feeds, interactive process timelines, security triage tables, and forensic inspection modals.

---

## 2. End-to-End Data Pipeline Diagram

```
+-----------------------------------------------------------------------------+
|                                KERNEL SPACE                                 |
|                                                                             |
|  [ Linux Kernel Process Execution ]                                         |
|                 |                                                           |
|                 v                                                           |
|       sys_enter Tracepoint                                                  |
|                 |                                                           |
|                 v                                                           |
|       eBPF Syscall Hook (syscall_collector.c)                               |
|        - Captures: timestamp_ns, pid, comm, syscall_nr                      |
|        - Emits to: Perf / BPF Ring Buffer                                   |
+-----------------------------------------------------------------------------+
                                      |
                                      v (BPF Ring Buffer)
+-----------------------------------------------------------------------------+
|                         USER-SPACE DETECTOR (C)                             |
|                                                                             |
|  Ring Buffer Consumer                                                       |
|        |                                                                    |
|        v                                                                    |
|  Per-PID Sliding Window (window.c)                                          |
|        - Window size: N=3 (3-gram sliding sequence)                         |
|        |                                                                    |
|        v                                                                    |
|  Trained Baseline Frequency Model (baseline_model.dat)                      |
|        - Lookup 3-gram: (s1, s2, s3)                                        |
|        - Frequency-to-probability mapping                                   |
|        |                                                                    |
|        v                                                                    |
|  Anomaly Detection & Explanation Engine (anomaly.c, explanation.c)          |
|        - Scoring Formula: S = 1.0 - (count / max_count)                     |
|        - Threshold: S >= 0.80  --> SUSPICIOUS                               |
|        - Generates human-readable sequence explanation                      |
|        |                                                                    |
|        v                                                                    |
|  Append-Only CSV Logger (syscall_dataset.csv)                               |
+-----------------------------------------------------------------------------+
                                      |
                                      v (Incremental File I/O)
+-----------------------------------------------------------------------------+
|                      BACKEND INGESTION & TRIAGE (PYTHON)                    |
|                                                                             |
|  DatasetMonitor (server.py)                                                 |
|        - Incremental byte-offset tailing with inode tracking                |
|        - Memory-safe bounded deques (max 1,000 events, 200 alerts)          |
|        |                                                                    |
|        +---> Rule-Based Severity Engine (severity.py)                       |
|        |        - Precedence: CRITICAL > HIGH > MEDIUM > LOW                |
|        |        - Classifies based on collected syscall primitive semantics |
|        |                                                                    |
|        +---> Durable SQLite Ingestion (database.py)                         |
|                 - Alerts table (19 columns, indexed, deduplicated)          |
|                 - Ingestion checkpoints (byte offsets, file signatures)     |
|                 - Process summary & timeline aggregation (Stage 21)         |
+-----------------------------------------------------------------------------+
                                      |
                                      v (HTTP JSON REST APIs)
+-----------------------------------------------------------------------------+
|                         WEB DASHBOARD FRONTEND                              |
|                                                                             |
|  Vanilla HTML5 / Modern CSS / ES6 JavaScript (dashboard/static/)            |
|        - Real-Time Live Feed & Dynamic Canvas Charts (Throughput / Timeline)|
|        - Security Triage Panel & Rule Precedence Matrix                     |
|        - Process-Wise Behavioral Profiles & 3-Gram Frequency Distributions  |
|        - Alert History with Multi-Filter Search, Pagination, & CSV Export   |
|        - Incident Lifecycle Management & In-Place Investigation Notes       |
+-----------------------------------------------------------------------------+
```

---

## 3. Subsystem Breakdown

### 3.1 Kernel Telemetry (`ebpf/syscall_collector.c`)
- **Hook Mechanism**: Attaches to `tracepoint/raw_syscalls/sys_enter` using `libbpf`.
- **Payload Extraction**: Collects:
  - `monotonic_timestamp_ns`: Kernel monotonic nanoseconds from `bpf_ktime_get_ns()`.
  - `pid`: Process identifier via `bpf_get_current_pid_tgid() >> 32`.
  - `process_name`: Comm string via `bpf_get_current_comm()`.
  - `syscall_nr`: Integer ID of the active system call from the architecture ABI.
- **Overhead Control**: Zero copying of user buffers, network packets, or file content; purely extracts the integer system call ID and process identity.

### 3.2 User-Space Anomaly Detection (`src/`)
- **Sliding Window Tracking (`src/window.c`)**: Maintains a per-PID state table mapping active threads to their last two syscalls: `[s_{t-2}, s_{t-1}, s_t]`.
- **Trained Model Binary (`baseline_model.dat`)**: Serialized 3-gram dictionary generated by `ebpf/syscall_trainer.c`. Contains $N$-grams observed during benign workload training.
- **Scoring Function (`src/anomaly.c`)**:
  $$\text{Score}(s_1, s_2, s_3) = \begin{cases} 1.0 & \text{if } (s_1, s_2, s_3) \notin \text{Model} \\ 1.0 - \frac{\text{Count}(s_1, s_2, s_3)}{\text{MaxCount}} & \text{if } (s_1, s_2, s_3) \in \text{Model} \end{cases}$$
- **Threshold**: Sequences with $\text{Score} \ge 0.80$ are flagged as `SUSPICIOUS`; otherwise `NORMAL`.
- **Root Cause Explanation (`src/explanation.c`)**: Generates contextual text describing whether an alert was triggered by an entirely novel sequence or an extreme statistical frequency anomaly.

### 3.3 Rule-Based Security Triage Engine (`dashboard/severity.py`)
- Evaluates detected anomalies to assign priority to alert feeds.
- Operates under strict precedence: **CRITICAL > HIGH > MEDIUM > LOW**.
- Based strictly on verified telemetry recorded by the collector.
- Does not modify or override anomaly detection scores or thresholds.

### 3.4 Persistent SQLite Database (`dashboard/database.py`)
- Located at project-local `data/alerts.db`.
- WAL (Write-Ahead Logging) mode enabled for high concurrent read/write throughput.
- Full schema with 6 tables:
  1. `alerts`: Core persistent alerts with severity, notes, status, and syscalls.
  2. `ingestion_checkpoints`: Byte-level tailing markers guaranteeing zero data loss or duplicates.
  3. `process_summary`: Aggregate metrics per process (total, normal, suspicious, max score).
  4. `process_ngrams`: Observed 3-gram frequencies per process.
  5. `process_timeline`: 5-second bucketed activity slices for timeline graphs.
  6. `process_recent_events`: Ring-buffer of recent sequences for granular drilldown.

### 3.5 Real-Time HTTP Dashboard Server (`dashboard/server.py`)
- Built using Python's standard `http.server` module without heavyweight external web frameworks.
- Runs unprivileged under standard user accounts.
- Provides 12 REST endpoints for live events, alert history, triage metrics, and process analytics.
