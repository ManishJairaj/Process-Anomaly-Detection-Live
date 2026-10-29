# Stage 19: Ground-Truth Evaluation of Real-Time Syscall Anomaly Detection Report

## Executive Summary

Stage 19 establishes an empirical, ground-truth evaluation pipeline for the eBPF syscall 3-gram anomaly detection system. It introduces a reproducible workload collection framework, an experiment manifest with independent ground-truth labeling, a multi-level evaluation tool, latency profiling, and a side-by-side comparison of `baseline_model.dat` and `experimental_normal_only_model.dat`.

All existing models, provenance records, anomaly thresholds ($0.80$), and previous test suites were strictly preserved. All **57 automated tests** (45 existing + 12 new Stage 19 tests) pass with zero errors.

---

## 1. System Inspection & Architecture Overview

Before making any additions, the existing system components were verified:
- **eBPF Collector & Live Detector** (`ebpf/syscall_collector.c`): Traces `sys_enter`, records 64-bit monotonic timestamps, filters own/launcher PIDs, feeds a 3-gram sliding window, and emits CSV logs.
- **Scoring Engine** (`src/anomaly.c`, `include/anomaly.h`): Computes frequency score $S = \frac{1}{1 + \text{count}}$ for seen 3-grams, returns $1.0$ for unseen 3-grams, and flags an alert when $S \ge 0.80$.
- **Model Storage & Provenance** (`src/model.c`, `baseline_model.dat.provenance.json`): Verified SHA-256 hashes (`13b5b2...` and `775bc0...`) remained unmodified.
- **Previous Test Suite**: 45 unit and integration tests covering serialization, compat, explanations, PID filtering, label filtering, and independent evaluation.

---

## 2. Workload Collection Framework

A safe Linux workload collection framework was developed in `tools/workload_runner.sh` and `tools/strace_collector.py`. Experiments run strictly inside isolated temporary workspaces (`/tmp/gt_workloads_$$`) with zero persistence and zero modification to host configuration or user documents.

### Workload Suite Breakdown

| ID | Category | Ground Truth | Description | 3-Gram Events |
| :--- | :--- | :--- | :--- | :--- |
| **B1_file_read** | Benign | `benign` | Sequential read of `/etc/hostname`, `/etc/os-release`, `/proc/version` | 408 |
| **B2_file_write** | Benign | `benign` | Sequential line writes and appends to temporary files | 465 |
| **B3_dir_traverse** | Benign | `benign` | Recursive directory traversal of `/usr/share/doc` | 2,752 |
| **B4_compression** | Benign | `benign` | Random data generation, gzip compression, and decompression | 764 |
| **B5_compile** | Benign | `benign` | Compilation and execution of a C hello-world binary | 3,292 |
| **B6_process_exec** | Benign | `benign` | Standard local process invocations (`ls`, `uname`, `date`, `id`, `whoami`) | 833 |
| **B7_file_copy** | Benign | `benign` | File copy and rename sequence inside temporary workspace | 462 |
| **B8_proc_info** | Benign | `benign` | Process inspection (`/proc/self/status`, `maps`, `cpuinfo`) | 481 |
| **S1_failed_access** | Security-Relevant | `suspicious` | 50 repeated access attempts to inaccessible/missing files | 10,167 |
| **S2_protected_files**| Security-Relevant | `suspicious` | Unauthorized read attempts to `/etc/shadow`, `/etc/sudoers`, `/root/.bashrc` | 3,108 |
| **S3_rapid_fork** | Security-Relevant | `suspicious` | Bounded rapid subshell process creation burst | 1,677 |
| **S4_rapid_modify** | Security-Relevant | `suspicious` | High-frequency creation, read, and teardown of 50 files | 5,655 |
| **S5_enumeration** | Security-Relevant | `suspicious` | Reading `/proc/[0-9]*/cmdline` and scanning `/proc/net/tcp` | 1,087 |

**Total Collected Dataset**: **31,151 3-gram events** across 13 distinct workloads logged into `gt_eval_dataset.csv`.

---

## 3. Ground-Truth Experiment Manifest

The experiment manifest is recorded in `gt_manifest.json`. Ground-truth labels are decoupled from the detector's `predicted_label` column to prevent self-referential bias.

Timestamp matching relies on `CLOCK_MONOTONIC` in nanoseconds. Primary PID matching identifies root workload processes, while window containment `[start_timestamp_ns, end_timestamp_ns]` reliably correlates child processes spawned during compilation and script execution.

---

## 4. Evaluation Tool & Empirical Results

The evaluation binary `tools/gt_evaluate` re-scores every row using `anomaly_score()` and computes metrics across three distinct aggregation levels:

### 1. Per-3-Gram Evaluation
Evaluates individual syscall 3-gram transitions:
- **Total Evaluated**: 31,151 3-grams
- **True Positives (TP)**: 3,677
- **False Positives (FP)**: 3,994
- **True Negatives (TN)**: 5,463
- **False Negatives (FN)**: 18,017
- **Precision**: 0.4793
- **Recall**: 0.1695
- **F1-Score**: 0.2504
- **False Positive Rate (FPR)**: 0.4223
- **False Negative Rate (FNR)**: 0.8305

### 2. Per-Process Evaluation
Aggregates by process ID (a process is flagged if ANY 3-gram exceeds $0.80$):
- **Unique Processes Evaluated**: 261
- **True Positives (TP)**: 229
- **False Positives (FP)**: 32
- **True Negatives (TN)**: 0
- **False Negatives (FN)**: 0
- **Precision**: 0.8774
- **Recall**: 1.0000
- **F1-Score**: 0.9347
- **False Positive Rate (FPR)**: 1.0000

### 3. Per-Workload Evaluation
Aggregates by workload boundary (workload is flagged if ANY event exceeds $0.80$):
- **Total Workloads**: 13
- **True Positives (TP)**: 5 (All 5 security-relevant workloads flagged)
- **False Positives (FP)**: 8 (All 8 benign workloads flagged)
- **True Negatives (TN)**: 0
- **False Negatives (FN)**: 0
- **Precision**: 0.3846
- **Recall**: 1.0000
- **F1-Score**: 0.5556
- **False Positive Rate (FPR)**: 1.0000

---

## 5. Detection Latency Analysis

Detection latency was profiled using a unified `CLOCK_MONOTONIC` clock, measuring the time from workload initiation to the first emitted alert:
- **Mean Detection Latency for Suspicious Workloads**: **12.89 ms** from process start (and $< 1.0\text{ ms}$ from the first intercepted system call).
- **In-Memory Scoring Latency vs Detection Delay**: In-memory hash lookup scoring completes in $< 20\text{ ns}$ per 3-gram. The $10\text{--}18\text{ ms}$ detection delay is dominated by OS process spawn (`fork`/`execve`) and dynamic loader (`ld.so`) initialization.

---

## 6. Baseline vs Experimental Model Comparison

Both models were evaluated on the identical 31,151 events and 13 workloads using `tools/gt_model_compare`:

| Metric | Model A (`baseline_model.dat`) | Model B (`experimental_normal_only_model.dat`) |
| :--- | :--- | :--- |
| **Training Filter** | All rows (NORMAL + SUSPICIOUS) | NORMAL rows only |
| **Unique 3-Grams** | 7,456 | 5,665 |
| **Total Training 3-Grams** | 1,456,768 | 7,152,582 |
| **Model Binary Size** | 238,616 bytes | 181,304 bytes |
| **Evaluated Events** | 31,151 | 31,151 |
| **3-Gram Alert Rate** | 24.6252% | 24.7119% |
| **Per-3-Gram TP / FP** | 3,677 / 3,994 | 3,683 / 4,015 |
| **Per-3-Gram TN / FN** | 5,463 / 18,017 | 5,442 / 18,011 |
| **Per-3-Gram Precision** | 0.4793 | 0.4784 |
| **Per-3-Gram Recall** | 0.1695 | 0.1698 |
| **Per-3-Gram F1-Score** | 0.2504 | 0.2506 |
| **Per-3-Gram FPR** | 0.4223 | 0.4246 |
| **Workload TP / FP** | 5 / 8 | 5 / 8 |
| **Workload Precision / Recall**| 0.3846 / 1.0000 | 0.3846 / 1.0000 |
| **Mean Detection Latency**| 12.89 ms | 12.89 ms |

---

## 7. Automated Test Suite & Validation

The test suite in `tools/test_gt_evaluation.c` exercises all Stage 19 logic:
All 12 unit tests passed.

Running `make test` executes all project test suites in sequence:
- Serialization Unit Tests: 6 passed
- Trainer-to-Detector Compatibility Tests: 7 passed
- Explainable Anomaly Detection Unit Tests: 7 passed
- Explainable Anomaly Detection Integration Tests: 2 passed
- PID Filtering & Dataset Logging Tests: 3 passed
- Stage 17 Label Filtering Tests: 10 passed
- Stage 18 Independent Evaluation Tests: 10 passed
- Stage 19 Ground-Truth Evaluation Tests: 12 passed
- **Total: 57 / 57 tests PASSED (100%)**
