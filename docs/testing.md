# Automated Testing & Verification Guide

**Process Anomaly Detection Using System Calls with eBPF**  
*Comprehensive Regression & Integration Test Suite*

---

## 1. Overview of Test Suites

The project incorporates 6 specialized test suites spanning unit models, integration pipelines, database persistence, process analytics, security triage, and launcher lifecycle management.

| Test Suite | File | Focus Area | Test Count |
|---|---|---|---|
| **Core C Benchmarks & Tests** | `tools/test_*.c`, `tools/eval_*.c` | 3-gram model, sliding window, serialization, explanations | 78 tests |
| **Real-Time Dashboard** | `tools/test_dashboard.py` | HTTP server, static assets, live tailing, bounded memory | 11 tests |
| **Alert History & Incidents** | `tools/test_stage20_alerts.py` | SQLite schema, deduplication, incident lifecycle, notes | 13 tests |
| **Process-Wise Analytics** | `tools/test_stage21_processes.py` | Per-PID tracking, host state cross-check, timelines | 14 tests |
| **Security Severity Triage** | `tools/test_stage22_severity.py` | Rule precedence, syscall mapping, triage stats, backfill | 18 tests |
| **Stage 24 System Launcher** | `tools/test_stage24_launcher.py` | CLI flags, privilege separation, signal traps (Ubuntu target) | 10 tests |
| **Stage 25 Final Integration** | `tools/test_stage25_integration.py` | End-to-end pipeline, corrupted line recovery, resilience | 14 tests |
| **Total Automated Tests** | | | **148+ tests** |

---

## 2. Running the Complete Test Suite

To run all automated tests on an Ubuntu Linux target system:

```bash
make test
```

This compiles all benchmark targets and executes each Python test suite sequentially.

---

## 3. Running Individual Test Suites

### 3.1 Real-Time Dashboard (Stage 19)
Verifies static asset serving, REST JSON endpoints, incremental CSV tailing, and bounded memory behavior:
```bash
python3 tools/test_dashboard.py
```

### 3.2 Persistent SQLite Alerts & Incidents (Stage 20)
Verifies schema constraints, WAL mode concurrency, deduplication across re-ingestion, status transitions, notes preservation, and filtered pagination:
```bash
python3 tools/test_stage20_alerts.py
```

### 3.3 Process-Wise Monitoring & Profiling (Stage 21)
Verifies per-PID sliding windows, top 3-gram frequencies, timeline bucket aggregation, and host `/proc` active status verification:
```bash
python3 tools/test_stage21_processes.py
```

### 3.4 Rule-Based Severity Classification (Stage 22)
Verifies deterministic rules for `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` severities, rule precedence hierarchy, historical database backfill, and security triage APIs:
```bash
python3 tools/test_stage22_severity.py
```

### 3.5 System Integration & Resilience (Stage 25)
Verifies end-to-end event-to-SQLite pipeline, corrupted line recovery, missing file handling, demo workload compatibility, and API schemas:
```bash
python3 tools/test_stage25_integration.py
```

---

## 4. Specific Regression Scenarios Tested

### 4.1 Deduplication & Idempotent Checkpoint Handling
- When the server restarts or re-reads an existing CSV, alerts already in SQLite are identified by `(record_offset, file_signature, event_timestamp)` and are never duplicated.
- Ingestion checkpoints store byte positions to avoid scanning gigabytes of previously ingested data.

### 4.2 Analyst Notes Preservation
- When an analyst changes an incident status (e.g. to `RESOLVED`) or types an investigation note, Subsequent CSV tailing passes or server restarts never overwrite user edits.

### 4.3 Malformed and Corrupted Record Recovery
- If the collector or logger writes a partial line, missing comma, non-numeric PID, or corrupted floating-point score, the parser safely discards the malformed entry and resumes at the next valid newline without throwing unhandled exceptions or halting the tail loop.

### 4.4 Bounded Memory Safety
- In-memory event deques maintain strict maximum sizes (`MAX_EVENT_HISTORY = 1000`, `MAX_ALERT_HISTORY = 200`).
- Process timeline ring buffers are pruned periodically to ensure the dashboard memory footprint remains bounded under long-running stress workloads.
