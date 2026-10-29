# STAGE 22 IMPLEMENTATION REPORT: RULE-BASED ALERT SEVERITY CLASSIFICATION AND SECURITY TRIAGE

**Project**: Process Anomaly Detection Using System Calls with eBPF  
**Stage**: Stage 22 — Rule-Based Alert Severity Classification and Security Triage  
**Status**: COMPLETED  
**Automated Test Status**: 123 / 123 Tests Passing (78 baseline + 13 Stage 20 + 14 Stage 21 + 18 Stage 22)

---

## 1. Executive Summary

Stage 22 implements an explainable, deterministic rule-based security classification system and security triage workflow for system call 3-gram anomalies. While the existing eBPF statistical model and anomaly threshold ($0.80$) determine *whether* a transition sequence deviates from the trained benign baseline, the Stage 22 Severity Engine evaluates *how urgently* a suspicious event should be prioritized for review by security analysts.

Key principles adhered to throughout Stage 22:
1. **Separation of Scoring from Triage**: Anomaly scores remain purely statistical. Normal transitions are never classified as alerts merely because they contain security-relevant syscalls.
2. **Model Integrity**: The trained 3-gram model, binary files, and $0.80$ threshold were preserved without any retraining or modification.
3. **Architecture-Aware Syscall Mapping**: System call IDs are resolved against the verified standard Linux x86_64 ABI without silent fallbacks or cross-architecture numbering confusion.
4. **Transparent, Explainable Rules**: Every classification generates explicit metadata containing the severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), triggered rule ID, rule description, relevant syscall names, explainable reasoning, and rule version.
5. **Zero Data Destruction**: Database migration idempotently upgraded existing alerts to populate severity without overwriting incident statuses, investigation notes, scores, or timestamps.

---

## 2. Architecture & File Modifications

| File | Type | Description |
|---|---|---|
| `dashboard/severity.py` | Python (Created) | Architecture-aware x86_64 syscall mapper, syscall category sets, explainable rule registry, precedence engine, and `classify_severity()` function. |
| `dashboard/database.py` | Python (Modified) | Added `severity`, `severity_rule`, `severity_reason`, `severity_rule_version` columns, indexes, schema migration, idempotent historical backfilling, severity filtering, sorting, and `get_triage_stats()`. |
| `dashboard/server.py` | Python (Modified) | Connected live alert parsing to `classify_severity()`, added `GET /api/triage/stats` endpoint, and enhanced `/api/alert_history` and CSV export with severity filtering and fields. |
| `dashboard/static/index.html` | HTML (Modified) | Added Security Triage Threat Prioritization section, Severity filter dropdown, Severity table column, and modal severity inspection fields. |
| `dashboard/static/dashboard.css` | CSS (Modified) | Added dark cybersecurity visual styling for severity badges (`.severity-critical`, `.severity-high`, `.severity-medium`, `.severity-low`) and triage panel grids. |
| `dashboard/static/dashboard.js` | JavaScript (Modified) | Integrated severity badge rendering, triage statistics polling, severity filtering and sorting in Alert History, live feed severity tags, and modal triage inspection. |
| `tools/test_stage22_severity.py` | Python (Created) | Comprehensive 18-test automated test suite verifying mapping, rules, precedence, determinism, migrations, backfill, filtering, triage stats, CSV export, and launcher compatibility. |
| `Makefile` | Build Script (Modified) | Integrated `python3 tools/test_stage22_severity.py` into the `test` build target. |

---

## 3. Architecture-Aware Syscall Mapping & ABI

The eBPF collector captures system call identifiers from `tracepoint/raw_syscalls/sys_enter` (`ctx->id`). On Linux x86_64, these IDs conform to the 64-bit ABI defined in `/usr/include/asm/unistd_64.h`:

- **Complete Table**: `dashboard/severity.py` maintains an exhaustive, verified map of 333+ standard x86_64 system call numbers matching the C detector's `src/explanation.c`.
- **Unknown Syscall Handling**: Out-of-range or unrecognized numbers are mapped to `unknown(<id>)` safely without raising exceptions or silently substituting incorrect names.
- **Strict Distinction**: Avoids mixing 32-bit x86 (`__NR_execve = 11`) and 64-bit x86_64 (`__NR_execve = 59`).

---

## 4. Explainable Severity Rules & Precedence

Severity classification evaluates anomalous sequences using a strict precedence order:  
$$\text{CRITICAL} \succ \text{HIGH} \succ \text{MEDIUM} \succ \text{LOW}$$

### Level 1: CRITICAL
Reserved for strongly corroborated security-sensitive behavior:
- `CRITICAL_PRIVILEGE_OR_CAPABILITY`: Sequence contains user ID or capability modifications (`setuid`, `setgid`, `setreuid`, `setresuid`, `capset`).
- `CRITICAL_NAMESPACE_OR_ROOT_PIVOT`: Sequence contains container boundary or root pivots (`pivot_root`, `chroot`, `setns`, `unshare`).
- `CRITICAL_KERNEL_MODIFICATION`: Sequence contains kernel module insertion, `kexec`, or raw BPF loading (`init_module`, `finit_module`, `delete_module`, `kexec_load`, `bpf`).
- `CRITICAL_EXEC_WITH_NETWORK`: Sequence couples process execution (`execve`, `execveat`) with network connection primitives (`connect`, `accept`, `accept4`) within the same 3-gram window.
- `CRITICAL_TRACING_WITH_MEMORY_MOD`: Sequence couples process debugging (`ptrace`) with memory protection modification (`mprotect`, `pkey_mprotect`).

### Level 2: HIGH
Anomalous sequences containing security-sensitive primitives:
- `HIGH_PROCESS_EXECUTION`: Sequence contains process execution (`execve`, `execveat`).
- `HIGH_PROCESS_TRACING`: Sequence contains process tracing or inspection (`ptrace`).
- `HIGH_NETWORK_ACTIVITY`: Sequence contains socket creation or communication (`socket`, `connect`, `accept`, `bind`, `listen`).
- `HIGH_PROCESS_MANIPULATION`: Sequence contains signal transmission or process termination (`kill`, `tkill`, `tgkill`).
- `HIGH_PERMISSION_CHANGE`: Sequence contains file mode alterations (`chmod`, `fchmod`, `fchmodat`).

### Level 3: LOW (Precedence before default MEDIUM)
- `LOW_ROUTINE_IO_DEVIATION`: Marginal anomaly score ($0.80 \le \text{score} < 0.90$) consisting exclusively of routine I/O, polling, or synchronization primitives (`read`, `write`, `close`, `poll`, `select`, `epoll_wait`, `nanosleep`, `clock_gettime`, `futex`).

### Level 4: MEDIUM
- `MEDIUM_FILESYSTEM_MUTATION`: Suspicious sequence contains file/directory creation or deletion (`openat`, `unlink`, `unlinkat`, `mkdir`, `mkdirat`, `rename`, `renameat`) without execution or network primitives.
- `MEDIUM_UNSEEN_SEQUENCE`: Unseen 3-gram ($\text{score} = 1.0000$) never observed in baseline training, lacking high-risk primitives.
- `MEDIUM_STATISTICAL_DEVIATION`: General statistical anomaly ($\text{score} \ge 0.80$) without matching specific high-risk categories.

---

## 5. Database Schema & Migration (`data/alerts.db`)

### Schema Migration
The `alerts` table was extended with 4 columns and dedicated triage indexes:
```sql
ALTER TABLE alerts ADD COLUMN severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'));
ALTER TABLE alerts ADD COLUMN severity_rule TEXT NOT NULL DEFAULT 'DEFAULT_CLASSIFICATION';
ALTER TABLE alerts ADD COLUMN severity_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN severity_rule_version TEXT NOT NULL DEFAULT '1.0.0';

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_triage ON alerts(severity, incident_status);
```

### Idempotent Historical Backfill
`AlertDatabase._backfill_severity()` queries alerts where `severity_reason = ''` or `severity_rule = 'DEFAULT_CLASSIFICATION'`, evaluates each sequence through `classify_severity()`, and updates the triage columns. It guarantees that existing `incident_status`, `investigation_notes`, `created_at`, `last_updated`, and `anomaly_score` are never overwritten.

---

## 6. REST API Endpoints

### 1. `GET /api/triage/stats`
Returns security triage metrics:
```json
{
  "total_alerts": 18,
  "critical_alerts": 0,
  "high_alerts": 12,
  "medium_alerts": 6,
  "low_alerts": 0,
  "unresolved_high_priority": 12,
  "top_flagged_processes": [
    {
      "process_name": "bash",
      "unresolved_count": 6,
      "critical_count": 0,
      "high_count": 6
    },
    {
      "process_name": "malproc",
      "unresolved_count": 6,
      "critical_count": 0,
      "high_count": 6
    }
  ]
}
```

### 2. `GET /api/alert_history`
Supports query parameters:
- `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- `sort_by=severity` (Orders by priority: CRITICAL > HIGH > MEDIUM > LOW)
- `sort_by=score` (Orders by anomaly score)
- Combined with `status`, `process`, `pid`, `min_score`, and date ranges.

### 3. `GET /api/alert_history/export`
Exports filtered records as CSV with complete triage columns:  
`alert_id,event_timestamp,pid,process_name,syscall_1,syscall_2,syscall_3,sequence,anomaly_score,severity,severity_rule,severity_reason,incident_status,investigation_notes,source_dataset,created_at,last_updated,explanation`

---

## 7. Dashboard User Interface

- **Security Triage Panel**: Prominently displays counts for CRITICAL, HIGH, MEDIUM, and LOW alerts, an active badge for Unresolved High-Priority incidents, and a process breakdown of top flagged executables.
- **Visual Severity Badges**: Distinct high-contrast badges with accessible text:
  - `[CRITICAL]`: Dark red `#f87171` (`rgba(185, 28, 28, 0.22)`)
  - `[HIGH]`: Orange-red `#fb923c` (`rgba(234, 88, 12, 0.2)`)
  - `[MEDIUM]`: Amber `#fbbf24` (`rgba(217, 119, 6, 0.2)`)
  - `[LOW]`: Sky blue `#38bdf8` (`rgba(2, 132, 199, 0.2)`)
- **Alert History Filtering & Sorting**: Dedicated severity dropdown filter and severity-priority sort option.
- **Incident Investigation Modal**: Displays Severity tier, Rule ID, Engine Version, and detailed Classification Reason alongside original anomaly score and investigation notes editor.
- **Live Event & Process Alert Feeds**: Updated to display severity badges and triage rationales in real time.

---

## 8. Automated Test Results

The Stage 22 automated test suite (`tools/test_stage22_severity.py`) verifies all 18 required scenarios:

```text
=================================================================
 Stage 22: Rule-Based Severity Classification & Triage Tests
=================================================================
[TEST  1: Syscall Mapping] ... PASSED
[TEST  2: Architecture Handling] ... PASSED
[TEST  3: Unknown Syscall Handling] ... PASSED
[TEST  4: HIGH Severity Rules] ... PASSED
[TEST  5: MEDIUM Severity Rules] ... PASSED
[TEST  6: LOW Severity Rules] ... PASSED
[TEST  7: CRITICAL Severity Rules] ... PASSED
[TEST  8: Rule Precedence] ... PASSED
[TEST  9: Deterministic Classification] ... PASSED
[TEST 10: Database Migration] ... PASSED
[TEST 11: Historical Backfill] ... PASSED
[TEST 12: Live Alert Ingestion] ... PASSED
[TEST 13: Severity Filtering] ... PASSED
[TEST 14: Severity Statistics] ... PASSED
[TEST 15: Severity-Aware CSV Export] ... PASSED
[TEST 16: Notes Preservation] ... PASSED
[TEST 17: Stage 21 Integration] ... PASSED
[TEST 18: Stage 24 Launcher Compatibility] ... PASSED
=================================================================
STAGE 22 TESTS: 18/18 PASSED
=================================================================
```

### Full Regression Suite:
- **Stage 21 Process Monitoring** (`tools/test_stage21_processes.py`): **14/14 PASSED**
- **Stage 20 Alert History & Notes** (`tools/test_stage20_alerts.py`): **13/13 PASSED**
- **Stage 19 Dashboard Endpoints** (`tools/test_dashboard.py`): **11/11 PASSED**
- **Total Automated Tests Passing**: **123 PASSED**

---

## 9. Launch Instructions

```bash
# 1. Full integrated startup (eBPF detector + Web Dashboard)
./run.sh

# 2. Launch web dashboard only (e.g. port 8080)
./run.sh --dashboard-only --port 8080

# 3. Environment and prerequisite verification
./run.sh --check

# 4. Run automated test suite
make test
```
Navigate to `http://localhost:8080` and select the **Alert History** tab to view the Security Triage section and severity controls.
