# Stage 20: Persistent Alert History and Incident Management Report

## Executive Summary

Stage 20 expands the eBPF process anomaly detection platform by adding persistent SQLite storage, an interactive Alert History page, and full incident lifecycle management. All suspicious events flagged by the 3-gram behavioral model ($\text{score} \ge 0.80$) are automatically and durably ingested into a project-local SQLite database (`data/alerts.db`), decoupled from transient in-memory buffers.

Analysts can now track incidents across four distinct lifecycle states (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_ALARM`), record investigation notes with audit timestamps, filter records by multiple dimensions, perform server-side pagination, and export filtered results to CSV.

All existing components—including model scoring, the 0.80 anomaly threshold, real-time live event streaming, the Stage 24 launcher (`./run.sh`), and previous automated test suites—have been strictly preserved.

---

## 1. System Architecture & Component Additions

```
+-------------------------------------------------------------------------------+
|                             Kernel / Collector Space                          |
|                                                                               |
|  [ eBPF Tracepoints ] -> [ 3-Gram Sliding Window ] -> [ Anomaly Scorer >=0.80 ]|
+-------------------------------------------------------------------------------+
                                      |
                                      v Appends rows
                           [ syscall_dataset.csv ]
                                      |
                                      v Incremental tailing
+-------------------------------------------------------------------------------+
|                       Dashboard Server (dashboard/server.py)                  |
|                                                                               |
|  +--------------------+   Live Stream   +----------------------------------+  |
|  | DatasetMonitor     | --------------> | In-Memory Deque (Recent 2000)    |  |
|  | (Incremental tail) |                 +----------------------------------+  |
|  +--------------------+                                                       |
|            |                                                                  |
|            | Ingest suspicious events (Transaction + Checkpoint)              |
|            v                                                                  |
|  +--------------------+                 +----------------------------------+  |
|  | AlertDatabase      | --------------> | SQLite Storage (data/alerts.db)  |  |
|  | (WAL mode, Thread) |                 | (alerts, ingestion_checkpoints)  |  |
|  +--------------------+                 +----------------------------------+  |
|            |                                              |                   |
|            +----------------------+-----------------------+                   |
|                                   v                                           |
|                     REST API (/api/alert_history/*)                           |
+-------------------------------------------------------------------------------+
                                      |
                                      v HTTP JSON / HTML / Canvas
+-------------------------------------------------------------------------------+
|                            Frontend Browser Client                            |
|                                                                               |
|  - Live Events Table & Canvas Charts (Overview)                               |
|  - Dedicated Incident Stats Cards (Total, New, Investigating, Resolved, False)|
|  - Alert History Table (Process Search, PID, Status, Score, Date/Time Filters)|
|  - Server-Side Pagination & Bidirectional Sorting (Newest / Oldest)           |
|  - Modal Detail View, Status Dropdown & Investigation Notes Editor            |
|  - Filtered CSV Export Stream                                                 |
+-------------------------------------------------------------------------------+
```

---

## 2. SQLite Database Schema & Design

The database resides in the project-local `data/alerts.db` directory and is initialized automatically on first run. It uses Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and parameterized queries for thread safety and SQL-injection prevention.

### `alerts` Table
```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_timestamp INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    syscall_1 INTEGER NOT NULL,
    syscall_2 INTEGER NOT NULL,
    syscall_3 INTEGER NOT NULL,
    anomaly_score REAL NOT NULL,
    explanation TEXT NOT NULL,
    incident_status TEXT NOT NULL DEFAULT 'NEW'
        CHECK (incident_status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_ALARM')),
    investigation_notes TEXT NOT NULL DEFAULT '',
    source_dataset TEXT NOT NULL,
    record_offset INTEGER DEFAULT NULL,
    file_signature TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    CONSTRAINT unq_alert_file_offset UNIQUE (source_dataset, file_signature, record_offset)
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(incident_status);
CREATE INDEX IF NOT EXISTS idx_alerts_pid ON alerts(pid);
CREATE INDEX IF NOT EXISTS idx_alerts_process ON alerts(process_name);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_dataset);
```

### `ingestion_checkpoints` Table
```sql
CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
    source_dataset TEXT PRIMARY KEY,
    file_signature TEXT NOT NULL DEFAULT '',
    last_byte_offset INTEGER NOT NULL DEFAULT 0,
    last_line_number INTEGER NOT NULL DEFAULT 0,
    last_event_timestamp INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
```

### Key Schema Properties:
- **Durable Identity & Deduplication**: Each record is identified by `(source_dataset, file_signature, record_offset)`. Re-reading the CSV upon dashboard restart will never insert duplicate rows.
- **Distinct Event Preservation**: Two events from the same process with the exact same 3-gram sequence occurring at different file offsets are both preserved.
- **Notes Preservation**: User investigation notes and incident statuses are never overwritten during CSV re-ingestion.
- **Normal Events Excluded**: Normal events (`predicted_label == 'NORMAL'` and `score < 0.80`) are never written to the alert history table.

---

## 3. Incident Lifecycle Management

Each alert is initialized with status `NEW`. Users can transition alerts between the following states:

| Status | Meaning | Typical Action |
| :--- | :--- | :--- |
| `NEW` | Unacknowledged alert | Awaiting initial security analyst review |
| `INVESTIGATING` | Active incident triage | Analyst verifying process tree, cmdline, network connections |
| `RESOLVED` | Confirmed anomaly remediated | Threat neutralized or confirmed authorized operation |
| `FALSE_ALARM` | Benign system deviation | Legitimate benign pattern not present in baseline model |

Every status transition and notes update modifies the `last_updated` audit timestamp.

---

## 4. Backend REST API Endpoints

All endpoints use parameterized SQL queries, validate input types, and enforce safety boundaries:

| Method | Endpoint | Query / Body Parameters | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/alert_history` | `page`, `limit`, `process`, `pid`, `status`, `min_score`, `max_score`, `start_time`, `end_time`, `order` | Returns server-side paginated alerts and metadata |
| `GET` | `/api/alert_history/detail` | `id` | Returns complete alert details by `alert_id` |
| `GET` | `/api/alert_history/stats` | None | Returns aggregate counts for `total`, `new`, `investigating`, `resolved`, `false_alarm` |
| `GET` | `/api/alert_history/export` | `process`, `pid`, `status`, `min_score`, `order` | Streams filtered alert history as a CSV file attachment |
| `POST` | `/api/alert_history/update_status` | `{"alert_id": <int>, "status": "<STATUS>"}` | Updates incident status and audit timestamp |
| `POST` | `/api/alert_history/update_notes` | `{"alert_id": <int>, "notes": "<str>"}` | Updates investigation notes and audit timestamp |

---

## 5. Frontend UI Integration

The frontend was augmented within the existing dark cybersecurity theme:

1. **Sidebar Navigation**: Added `📜 Alert History` link navigating to the persistent alert management view.
2. **Incident Management Statistics Cards**: Five top-level summary cards showing `Total Stored Alerts`, `New Alerts`, `Investigating`, `Resolved`, and `False Alarms`.
3. **Filter and Search Bar**: Real-time filtering by process substring, PID, incident status dropdown, anomaly score threshold, date/time range, newest/oldest sorting, and page size selection.
4. **Alert History Table**: Displays Alert ID, timestamp, PID, process name, 3-gram sequence with names and numbers, anomaly score, incident status badge, root cause explanation, and `🔍 Details` action button.
5. **Server-Side Pagination Bar**: Displays current range (`Showing X - Y of Z alerts`) and allows navigation across pages (`First`, `Prev`, `Page X of Y`, `Next`, `Last`).
6. **Incident Investigation Modal Dialog**: Slide-out modal displaying complete alert metadata, status dropdown selector, investigation notes editor with auto-scroll, and instant save feedback.
7. **CSV Export**: One-click download button exporting filtered alert history with escaped values.

---

## 6. Integration with Stage 24 Launcher (`./run.sh`)

The system launcher integrates with the persistent SQLite database:
- `--db <path>` option added to `run.sh` (defaulting to `data/alerts.db`).
- SQLite data directory is verified and created during launcher startup.
- Unprivileged user permissions preserved (`server.py` runs as standard user, never root).
- Both `--dashboard-only` and full eBPF live monitoring modes fully support persistent alert history.
- Clean shutdown on `Ctrl+C` preserves all SQLite transactions and checkpoints without file corruption.

---

## 7. Automated Test Suite Results

A comprehensive automated test suite `tools/test_stage20_alerts.py` was implemented, covering all Stage 20 requirements:

```
=================================================================
 Stage 20: Persistent Alert History & Incident Management Tests
=================================================================
[TEST  1: SQLite Database Initialization & Schema] ... PASSED
[TEST  2: Anomaly Alert Insertion & Explanations] ... PASSED
[TEST  3: Duplicate Prevention & Event Preservation] ... PASSED
[TEST  4: Persistence Across Application Restarts] ... PASSED
[TEST  5: Incident Status Lifecycle Transitions] ... PASSED
[TEST  6: Investigation Notes Preservation on Reingest] ... PASSED
[TEST  7: Multi-Criteria Search & Filtering] ... PASSED
[TEST  8: Server-Side Pagination & Sorting] ... PASSED
[TEST  9: Filtered Incident CSV Export] ... PASSED
[TEST 10: Fault-Tolerant Malformed CSV Ingestion] ... PASSED
[TEST 11: Concurrent Multi-Thread Ingestion & WAL] ... PASSED
[TEST 12: Dashboard REST API Endpoints Integration] ... PASSED
[TEST 13: Launcher Compatibility & CLI Options] ... PASSED
=================================================================
STAGE 20 TESTS: 13/13 PASSED
=================================================================
```

### Cumulative Test Count
- 57 Pre-existing C Model & Evaluation Tests
- 10 Stage 24 Launcher Tests
- 11 Stage 19 Real-Time Dashboard Tests
- **13 New Stage 20 Persistent Alert History Tests**
- **Total: 91 Automated Tests Passing** (Zero Regressions)

---

## 8. Summary of Files Created and Modified

### Files Created:
- `dashboard/database.py`: Core SQLite manager, transactions, pagination, and incident management.
- `tools/test_stage20_alerts.py`: 13 comprehensive unit and integration tests for Stage 20.
- `stage20_completion_report.md`: Stage 20 implementation report and documentation.

### Files Modified:
- `dashboard/server.py`: Integrated `AlertDatabase`, ingestion checkpoints, and `/api/alert_history/*` routes.
- `dashboard/static/index.html`: Added Alert History section, stats grid, table, pagination, and modal.
- `dashboard/static/dashboard.css`: Added styles for status badges, stats cards, filters, and investigation modal.
- `dashboard/static/dashboard.js`: Added frontend controller for alert history, pagination, filters, and notes editor.
- `run.sh`: Added `--db` option, database directory preparation, and server parameter passing.
- `Makefile`: Added `test_stage20_alerts.py` to the `test` target.
