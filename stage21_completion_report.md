# STAGE 21 IMPLEMENTATION REPORT: PROCESS-WISE MONITORING AND BEHAVIORAL ANALYSIS

**Project**: Process Anomaly Detection Using System Calls with eBPF  
**Stage**: Stage 21 — Process-Wise Monitoring and Behavioral Analysis  
**Status**: COMPLETED  
**Automated Test Status**: 105 / 105 Tests Passing (78 baseline + 13 Stage 20 + 14 Stage 21)

---

## 1. Executive Summary

Stage 21 introduces process-centric monitoring and behavioral inspection to the eBPF System Call Anomaly Detection dashboard. System operators and security analysts can now inspect the behavioral profile of individual Linux processes, view syscall n-gram activity timelines, analyze deviation distributions, review top recurring 3-gram patterns, examine process anomaly feeds with root cause explanations, and navigate bidirectionally between process details and Stage 20 Alert History.

The implementation strictly satisfies all project constraints:
1. **Model Parameter Preservation**: The trained 3-gram model, binary serialization, and anomaly threshold ($0.80$) were unmodified.
2. **Framework Independence**: Built using Python's standard library (`http.server`, `sqlite3`, `urllib.parse`), vanilla CSS, and vanilla ES6 JavaScript with pure HTML5 Canvas (zero external CDN or runtime npm dependencies).
3. **Data & Memory Safety**: Implemented bounded memory rings and incremental SQLite aggregations so datasets with millions of records are safely ingested and queried without high memory usage.
4. **PID Reuse & Identity Segregation**: Linux process ID reuse is handled by segregating process summary and sequence tables across `(pid, process_name, source_dataset)` and verifying active execution state against `/proc/{pid}/comm` and `cmdline`.
5. **Launcher & Backward Compatibility**: Fully integrated with `./run.sh`, `./run.sh --dashboard-only`, `./run.sh --check`, and all Stage 20 persistent alert history and incident notes.

---

## 2. Architecture & File Modifications

| File | Type | Description |
|---|---|---|
| `dashboard/database.py` | Python (Modified) | Added Stage 21 SQLite schema tables (`process_summary`, `process_ngrams`, `process_timeline`, `process_recent_events`), composite indexes, `/proc` PID verification, batch incremental ingestion, and aggregation query APIs. |
| `dashboard/server.py` | Python (Modified) | Wired incremental process batching into the background reader and implemented 6 REST API endpoints: `/api/processes`, `/api/processes/detail`, `/api/processes/events`, `/api/processes/alerts`, `/api/processes/timeline`, and `/api/processes/top_ngrams`. |
| `dashboard/static/index.html` | HTML (Modified) | Added sidebar navigation item `Processes` and the complete `#section-processes` containing View 1 (Process Overview list, filters, table, pagination) and View 2 (Process Details header, metric cards, 4 canvas charts, recent sequences table, and anomaly feed). |
| `dashboard/static/dashboard.css` | CSS (Modified) | Added dark cybersecurity styles for process overview grids, process detail views, active/historical status badges, `.proc-link` hover styling, and responsive split layouts. |
| `dashboard/static/dashboard.js` | JavaScript (Modified) | Linked process names in Live Events and Alert History tables to Process Details; implemented process overview controller, server-side pagination, sorting, search/filter, and pure HTML5 Canvas chart renderers. |
| `tools/test_stage21_processes.py` | Python (Created) | Automated test suite verifying 14 unit and integration test scenarios covering aggregation, sorting, search, pagination, PID reuse, memory safety, and API contracts. |
| `Makefile` | Build Script (Modified) | Integrated `python3 tools/test_stage21_processes.py` into the `test` build target. |

---

## 3. Database Schema Extensions (`data/alerts.db`)

Four relational tables were added to the persistent SQLite database, preserving existing Stage 20 `anomaly_alerts` and `ingestion_checkpoints` tables:

```sql
-- 1. Process Summary Aggregate Table
CREATE TABLE IF NOT EXISTS process_summary (
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    source_dataset TEXT NOT NULL,
    total_events INTEGER DEFAULT 0,
    normal_events INTEGER DEFAULT 0,
    suspicious_events INTEGER DEFAULT 0,
    anomaly_percentage REAL DEFAULT 0.0,
    first_timestamp INTEGER NOT NULL,
    last_timestamp INTEGER NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pid, process_name, source_dataset)
);
CREATE INDEX IF NOT EXISTS idx_proc_sum_lookup ON process_summary(process_name, pid);
CREATE INDEX IF NOT EXISTS idx_proc_sum_score ON process_summary(suspicious_events, anomaly_percentage);

-- 2. Process Syscall 3-Gram Frequency Profile
CREATE TABLE IF NOT EXISTS process_ngrams (
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    source_dataset TEXT NOT NULL,
    syscall_1 INTEGER NOT NULL,
    syscall_2 INTEGER NOT NULL,
    syscall_3 INTEGER NOT NULL,
    sequence_str TEXT NOT NULL,
    occurrence_count INTEGER DEFAULT 0,
    last_seen_timestamp INTEGER NOT NULL,
    PRIMARY KEY (pid, process_name, source_dataset, syscall_1, syscall_2, syscall_3)
);
CREATE INDEX IF NOT EXISTS idx_proc_ngrams_count ON process_ngrams(pid, process_name, occurrence_count DESC);

-- 3. Process Activity & Anomaly Time Buckets
CREATE TABLE IF NOT EXISTS process_timeline (
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    source_dataset TEXT NOT NULL,
    time_bucket INTEGER NOT NULL,
    total_events INTEGER DEFAULT 0,
    normal_events INTEGER DEFAULT 0,
    suspicious_events INTEGER DEFAULT 0,
    PRIMARY KEY (pid, process_name, source_dataset, time_bucket)
);
CREATE INDEX IF NOT EXISTS idx_proc_timeline_bucket ON process_timeline(pid, process_name, time_bucket ASC);

-- 4. Bounded Ring Buffer of Recent Events (At most 100 per process)
CREATE TABLE IF NOT EXISTS process_recent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    source_dataset TEXT NOT NULL,
    syscall_1 INTEGER NOT NULL,
    syscall_2 INTEGER NOT NULL,
    syscall_3 INTEGER NOT NULL,
    sequence_str TEXT NOT NULL,
    anomaly_score REAL NOT NULL,
    is_suspicious INTEGER NOT NULL,
    event_timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proc_recent_lookup ON process_recent_events(pid, process_name, event_timestamp DESC);
```

---

## 4. REST API Specifications

### 1. `GET /api/processes`
- **Query Parameters**:
  - `page` (int, default `1`): Page number.
  - `limit` (int, default `25`): Processes per page (10, 25, 50, 100).
  - `name` (string, optional): Case-insensitive process name substring filter.
  - `pid` (int, optional): Exact PID filter.
  - `sort_by` (string, default `'total'`): One of `'total'`, `'anomalies'`, `'anomaly_pct'`, `'latest'`.
  - `order` (string, default `'desc'`): `'desc'` or `'asc'`.
- **Response**:
  ```json
  {
    "processes": [
      {
        "pid": 4120,
        "process_name": "curl",
        "total_events": 1420,
        "normal_events": 1395,
        "suspicious_events": 25,
        "anomaly_percentage": 1.76,
        "first_timestamp": 1729837100123456,
        "last_timestamp": 1729837110987654,
        "is_running": false,
        "status": "TERMINATED"
      }
    ],
    "total": 1,
    "page": 1,
    "limit": 25,
    "total_pages": 1
  }
  ```

### 2. `GET /api/processes/detail`
- **Query Parameters**: `pid` (int, required), `name` (string, optional).
- **Response**: Process summary object including verified host execution state (`is_running`).

### 3. `GET /api/processes/events`
- **Query Parameters**: `pid` (int, required), `name` (string, optional), `limit` (int, default `50`).
- **Response**: List of recent syscall 3-gram transitions for the process.

### 4. `GET /api/processes/alerts`
- **Query Parameters**: `pid` (int, required), `name` (string, optional), `limit` (int, default `50`).
- **Response**: List of anomaly alerts associated with this process, including Stage 20 `incident_status` (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_ALARM`), investigation notes, and root cause explanations.

### 5. `GET /api/processes/timeline`
- **Query Parameters**: `pid` (int, required), `name` (string, optional).
- **Response**: Time-bucketed array of `{ time_bucket, total_events, normal_events, suspicious_events }`.

### 6. `GET /api/processes/top_ngrams`
- **Query Parameters**: `pid` (int, required), `name` (string, optional), `limit` (int, default `10`).
- **Response**: Top observed syscall 3-grams sorted descending by occurrence count.

---

## 5. Behavioral Visualizations (Pure HTML5 Canvas)

All visualizations run client-side using pure HTML5 2D Canvas contexts matching the cybersecurity dark aesthetic:

1. **Process Activity Timeline** (`#canvasProcTimeline`):
   Renders syscall event throughput over time with a cyan filled area chart, dynamic Y-axis scaling, and timestamp markers.
2. **Normal vs. Suspicious Distribution** (`#canvasProcDist`):
   Renders a doughnut chart displaying the proportion of benign sequences (green `#10b981`) versus anomalies (red `#ef4444`) with formatted legend counts.
3. **Most Frequent Syscall Sequences** (`#canvasProcTopNgrams`):
   Renders a horizontal bar chart displaying the top 3-gram behavioral profile with exact syscall names (e.g. `rt_sigprocmask -> ioctl -> read`) and execution frequencies.
4. **Process Anomaly Timeline** (`#canvasProcAnomalyTimeline`):
   Renders suspicious event bursts and anomaly spikes over time in alert red (`#ef4444`).
5. **Cross-Navigation**:
   Clicking any process name in the Live Event Stream or Alert History immediately opens the Process Details view. The "View Alerts in History" button pre-filters Alert History by PID and process name and navigates to the incident records.

---

## 6. Process Identity and PID Reuse Handling

In Linux systems, process IDs are routinely recycled:
- The backend identifies unique process lifecycles via the composite key `(pid, process_name, source_dataset)`.
- When an analyst inspects a process, `is_process_running_on_host(pid, process_name)` inspects `/proc/{pid}/comm` and `/proc/{pid}/cmdline`.
- If a PID exists on the host but the executable name differs (e.g., historical PID `1337` was `python3`, but PID `1337` is now `sshd`), it is flagged as `HISTORICAL / TERMINATED`, preventing false active badges on recycled PIDs.

---

## 7. Verification & Automated Test Results

The automated test suite verifies all stages of the project:

### Stage 21 Tests (`tools/test_stage21_processes.py`):
```text
=================================================================
 Stage 21: Process-Wise Monitoring & Analytics Tests
=================================================================
[TEST  1: Process Aggregation & Metrics] ... PASSED
[TEST  2: Process Name Substring Search] ... PASSED
[TEST  3: Exact PID Filtering] ... PASSED
[TEST  4: Multi-Attribute Sorting] ... PASSED
[TEST  5: Server-Side Pagination] ... PASSED
[TEST  6: Process Detail Retrieval] ... PASSED
[TEST  7: Incremental Event Count Tracking] ... PASSED
[TEST  8: Alert Retrieval & Incident Status Preservation] ... PASSED
[TEST  9: Activity Timeline Generation] ... PASSED
[TEST 10: Top Syscall 3-Grams Aggregation] ... PASSED
[TEST 11: PID Reuse & Identity Segregation] ... PASSED
[TEST 12: Large Dataset Memory Safety & Ring Buffer] ... PASSED
[TEST 13: Stage 20 Database Coexistence] ... PASSED
[TEST 14: Stage 24 Launcher Compatibility] ... PASSED
=================================================================
STAGE 21 TESTS: 14/14 PASSED
=================================================================
```

### Regression Verification:
- **Stage 20 Persistent Alert History** (`tools/test_stage20_alerts.py`): **13/13 PASSED**
- **Stage 19 Dashboard Endpoints** (`tools/test_dashboard.py`): **11/11 PASSED**
- **Total Automated Tests**: **105 PASSED**

---

## 8. Launch Instructions

To launch the complete integrated application with live process monitoring:

```bash
# 1. Full integrated startup (eBPF detector + Web Dashboard)
./run.sh

# 2. Launch dashboard server only on custom port
./run.sh --dashboard-only --port 8080

# 3. Verify environment prerequisites and database
./run.sh --check

# 4. Run automated test suite
make test
```
Access the dashboard in any browser at `http://localhost:8080` (or `8000`) and select the **Processes** tab.
