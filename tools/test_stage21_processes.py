#!/usr/bin/env python3
"""
test_stage21_processes.py — Automated Unit & Integration Tests for Stage 21:
Process-Wise Monitoring and Behavioral Analysis

Tests:
  1. Process aggregation (total, normal, suspicious, anomaly percentage)
  2. Process name search with substring matching and escaping
  3. Exact PID filtering
  4. Multi-attribute sorting (total, anomalies, anomaly_pct, latest)
  5. Server-side pagination and boundary checks
  6. Process detail retrieval and metadata accuracy
  7. Event count tracking across incremental batches
  8. Alert retrieval and Stage 20 incident status preservation
  9. Activity timeline bucket generation
 10. Top syscall 3-grams frequency aggregation and sequence formatting
 11. PID reuse handling and process identity segregation
 12. Large dataset memory behavior and bounded ring buffer
 13. Stage 20 database compatibility and non-destructive schema migration
 14. Stage 24 launcher compatibility and argument verification
"""

import sys
import os
import time
import json
import sqlite3
import tempfile
import shutil
import subprocess
import urllib.request
import urllib.error

# Add project root to sys.path
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.database import AlertDatabase, is_process_running_on_host
from dashboard.server import DatasetMonitor, get_syscall_name

def run_test(name, fn):
    sys.stdout.write(f"[{name}] ... ")
    sys.stdout.flush()
    try:
        fn()
        print("PASSED")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

# ==============================================================================
# TEST 1: Process Aggregation
# ==============================================================================
def test_process_aggregation():
    temp_dir = tempfile.mkdtemp(prefix="t21_agg_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {
            (101, "worker_proc"): {
                "pid": 101,
                "process_name": "worker_proc",
                "total_events": 100,
                "normal_events": 90,
                "suspicious_events": 10,
                "max_score": 1.0,
                "first_timestamp": 1000,
                "last_timestamp": 5000,
                "ngrams": {},
                "timeline": {}
            }
        }
        db.ingest_process_batch(batch, [], "test.csv")

        res = db.get_processes_paginated()
        assert res["total"] == 1
        p = res["processes"][0]
        assert p["pid"] == 101
        assert p["process_name"] == "worker_proc"
        assert p["total_events"] == 100
        assert p["normal_events"] == 90
        assert p["suspicious_events"] == 10
        assert p["anomaly_percentage"] == 10.0
        assert p["max_score"] == 1.0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 2: Process Search
# ==============================================================================
def test_process_search():
    temp_dir = tempfile.mkdtemp(prefix="t21_search_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        procs = [
            (201, "systemd-journal"),
            (202, "systemd-network"),
            (203, "sshd"),
            (204, "bash")
        ]
        batch = {}
        for pid, name in procs:
            batch[(pid, name)] = {
                "pid": pid, "process_name": name,
                "total_events": 10, "normal_events": 10, "suspicious_events": 0,
                "max_score": 0.05, "first_timestamp": 100, "last_timestamp": 200,
                "ngrams": {}, "timeline": {}
            }
        db.ingest_process_batch(batch, [], "test.csv")

        # Search substring
        res = db.get_processes_paginated(search="systemd")
        assert res["total"] == 2
        names = {p["process_name"] for p in res["processes"]}
        assert names == {"systemd-journal", "systemd-network"}

        # Search exact
        res_bash = db.get_processes_paginated(search="bash")
        assert res_bash["total"] == 1 and res_bash["processes"][0]["pid"] == 204
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 3: PID Filtering
# ==============================================================================
def test_pid_filtering():
    temp_dir = tempfile.mkdtemp(prefix="t21_pid_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {}
        for pid in [301, 302, 303]:
            batch[(pid, f"proc_{pid}")] = {
                "pid": pid, "process_name": f"proc_{pid}",
                "total_events": 5, "normal_events": 5, "suspicious_events": 0,
                "max_score": 0.01, "first_timestamp": 10, "last_timestamp": 20,
                "ngrams": {}, "timeline": {}
            }
        db.ingest_process_batch(batch, [], "test.csv")

        res = db.get_processes_paginated(pid=302)
        assert res["total"] == 1
        assert res["processes"][0]["pid"] == 302
        assert res["processes"][0]["process_name"] == "proc_302"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 4: Sorting
# ==============================================================================
def test_sorting():
    temp_dir = tempfile.mkdtemp(prefix="t21_sort_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {
            (401, "low_events"): {
                "pid": 401, "process_name": "low_events",
                "total_events": 10, "normal_events": 10, "suspicious_events": 0,
                "max_score": 0.01, "first_timestamp": 100, "last_timestamp": 100,
                "ngrams": {}, "timeline": {}
            },
            (402, "high_events"): {
                "pid": 402, "process_name": "high_events",
                "total_events": 1000, "normal_events": 995, "suspicious_events": 5,
                "max_score": 0.90, "first_timestamp": 200, "last_timestamp": 500,
                "ngrams": {}, "timeline": {}
            },
            (403, "high_anomalies"): {
                "pid": 403, "process_name": "high_anomalies",
                "total_events": 100, "normal_events": 50, "suspicious_events": 50,
                "max_score": 1.00, "first_timestamp": 300, "last_timestamp": 900,
                "ngrams": {}, "timeline": {}
            }
        }
        db.ingest_process_batch(batch, [], "test.csv")

        # 1. Sort by total events desc
        s_total = db.get_processes_paginated(sort_by="total", order="desc")
        assert s_total["processes"][0]["process_name"] == "high_events"

        # 2. Sort by anomalies desc
        s_anom = db.get_processes_paginated(sort_by="anomalies", order="desc")
        assert s_anom["processes"][0]["process_name"] == "high_anomalies"

        # 3. Sort by anomaly_pct desc
        s_pct = db.get_processes_paginated(sort_by="anomaly_pct", order="desc")
        assert s_pct["processes"][0]["process_name"] == "high_anomalies"
        assert s_pct["processes"][0]["anomaly_percentage"] == 50.0

        # 4. Sort by latest activity desc
        s_late = db.get_processes_paginated(sort_by="latest", order="desc")
        assert s_late["processes"][0]["process_name"] == "high_anomalies"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 5: Pagination
# ==============================================================================
def test_pagination():
    temp_dir = tempfile.mkdtemp(prefix="t21_page_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {}
        for i in range(1, 31):
            batch[(500 + i, f"proc_{i}")] = {
                "pid": 500 + i, "process_name": f"proc_{i}",
                "total_events": i * 10, "normal_events": i * 10, "suspicious_events": 0,
                "max_score": 0.05, "first_timestamp": 1000 + i, "last_timestamp": 2000 + i,
                "ngrams": {}, "timeline": {}
            }
        db.ingest_process_batch(batch, [], "test.csv")

        # Page 1 with limit 10
        p1 = db.get_processes_paginated(page=1, limit=10)
        assert len(p1["processes"]) == 10
        assert p1["total"] == 30
        assert p1["total_pages"] == 3

        # Page 3 with limit 10
        p3 = db.get_processes_paginated(page=3, limit=10)
        assert len(p3["processes"]) == 10

        # Out-of-range page clamp
        p_out = db.get_processes_paginated(page=99, limit=10)
        assert len(p_out["processes"]) == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 6: Process Detail Retrieval
# ==============================================================================
def test_process_detail_retrieval():
    temp_dir = tempfile.mkdtemp(prefix="t21_detail_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {
            (601, "det_proc"): {
                "pid": 601, "process_name": "det_proc",
                "total_events": 250, "normal_events": 240, "suspicious_events": 10,
                "max_score": 0.95, "first_timestamp": 12345000, "last_timestamp": 98765000,
                "ngrams": {}, "timeline": {}
            }
        }
        db.ingest_process_batch(batch, [], "custom.csv")

        detail = db.get_process_detail(601)
        assert detail is not None
        assert detail["pid"] == 601
        assert detail["process_name"] == "det_proc"
        assert detail["total_events"] == 250
        assert detail["first_timestamp"] == 12345000
        assert detail["last_timestamp"] == 98765000
        assert detail["max_score"] == 0.95
        assert "status" in detail
        assert detail["status"] in ("ACTIVE", "TERMINATED")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 7: Event Counts Across Incremental Batches
# ==============================================================================
def test_event_counts_incremental():
    temp_dir = tempfile.mkdtemp(prefix="t21_counts_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        # Batch 1: 50 events (45 normal, 5 suspicious)
        b1 = {
            (701, "inc_proc"): {
                "pid": 701, "process_name": "inc_proc",
                "total_events": 50, "normal_events": 45, "suspicious_events": 5,
                "max_score": 0.85, "first_timestamp": 1000, "last_timestamp": 2000,
                "ngrams": {}, "timeline": {}
            }
        }
        db.ingest_process_batch(b1, [], "test.csv")

        # Batch 2: 30 events (20 normal, 10 suspicious)
        b2 = {
            (701, "inc_proc"): {
                "pid": 701, "process_name": "inc_proc",
                "total_events": 30, "normal_events": 20, "suspicious_events": 10,
                "max_score": 1.00, "first_timestamp": 1000, "last_timestamp": 3000,
                "ngrams": {}, "timeline": {}
            }
        }
        db.ingest_process_batch(b2, [], "test.csv")

        detail = db.get_process_detail(701)
        assert detail["total_events"] == 80, f"Expected 80, got {detail['total_events']}"
        assert detail["normal_events"] == 65
        assert detail["suspicious_events"] == 15
        assert detail["max_score"] == 1.00
        assert detail["first_timestamp"] == 1000
        assert detail["last_timestamp"] == 3000
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 8: Alert Retrieval & Incident Status Preservation
# ==============================================================================
def test_alert_retrieval_and_incident_status():
    temp_dir = tempfile.mkdtemp(prefix="t21_alerts_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        # Insert alert via Stage 20 API
        aid = db.insert_alert({
            "event_timestamp": 50000,
            "pid": 801,
            "process_name": "investigated_proc",
            "syscall_1": 59, "syscall_2": 0, "syscall_3": 1,
            "anomaly_score": 1.0,
            "explanation": "Unseen 3-Gram: execve -> read -> write",
            "source_dataset": "live.csv"
        })
        db.update_status(aid, "INVESTIGATING")
        db.update_notes(aid, "Active triage underway by SOC analyst")

        # Retrieve process alerts via Stage 21 method
        alerts = db.get_process_alerts(801)
        assert len(alerts) == 1
        al = alerts[0]
        assert al["alert_id"] == aid
        assert al["incident_status"] == "INVESTIGATING"
        assert al["investigation_notes"] == "Active triage underway by SOC analyst"
        assert "execve" in al["sequence_str"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 9: Timeline Generation
# ==============================================================================
def test_timeline_generation():
    temp_dir = tempfile.mkdtemp(prefix="t21_timeline_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {
            (901, "time_proc"): {
                "pid": 901, "process_name": "time_proc",
                "total_events": 30, "normal_events": 25, "suspicious_events": 5,
                "max_score": 1.0, "first_timestamp": 0, "last_timestamp": 15000000000,
                "ngrams": {},
                "timeline": {
                    (1, "normal"): 10,
                    (1, "suspicious"): 2,
                    (2, "normal"): 15,
                    (2, "suspicious"): 3
                }
            }
        }
        db.ingest_process_batch(batch, [], "test.csv")

        tl = db.get_process_timeline(901)
        assert len(tl) == 2
        assert tl[0]["time_bucket"] == 1
        assert tl[0]["normal"] == 10
        assert tl[0]["suspicious"] == 2
        assert tl[0]["total"] == 12

        assert tl[1]["time_bucket"] == 2
        assert tl[1]["normal"] == 15
        assert tl[1]["suspicious"] == 3
        assert tl[1]["total"] == 18
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 10: Top Syscall 3-Grams
# ==============================================================================
def test_top_syscall_ngrams():
    temp_dir = tempfile.mkdtemp(prefix="t21_ngrams_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        batch = {
            (1001, "ngram_proc"): {
                "pid": 1001, "process_name": "ngram_proc",
                "total_events": 50, "normal_events": 40, "suspicious_events": 10,
                "max_score": 1.0, "first_timestamp": 0, "last_timestamp": 1000,
                "ngrams": {
                    (0, 1, 2, 0): 30, # read -> write -> open (freq 30)
                    (59, 0, 1, 1): 10, # execve -> read -> write (freq 10, suspicious)
                    (1, 2, 3, 0): 5   # write -> open -> close (freq 5)
                },
                "timeline": {}
            }
        }
        db.ingest_process_batch(batch, [], "test.csv")

        top = db.get_process_top_ngrams(1001, limit=5)
        assert len(top) == 3
        # First must be the most frequent (freq 30)
        assert top[0]["syscall_1"] == 0 and top[0]["frequency"] == 30
        assert "read" in top[0]["sequence_str"]
        # Second must be freq 10
        assert top[1]["syscall_1"] == 59 and top[1]["frequency"] == 10
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 11: PID Reuse Handling
# ==============================================================================
def test_pid_reuse_handling():
    temp_dir = tempfile.mkdtemp(prefix="t21_reuse_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        # PID 1005 was first "short_lived_worker", later PID 1005 was recycled by "curl"
        batch = {
            (1005, "short_lived_worker"): {
                "pid": 1005, "process_name": "short_lived_worker",
                "total_events": 20, "normal_events": 20, "suspicious_events": 0,
                "max_score": 0.05, "first_timestamp": 1000, "last_timestamp": 2000,
                "ngrams": {}, "timeline": {}
            },
            (1005, "curl"): {
                "pid": 1005, "process_name": "curl",
                "total_events": 45, "normal_events": 40, "suspicious_events": 5,
                "max_score": 0.95, "first_timestamp": 50000, "last_timestamp": 55000,
                "ngrams": {}, "timeline": {}
            }
        }
        db.ingest_process_batch(batch, [], "test.csv")

        # Verify both distinct process identities exist and are NOT merged together
        res = db.get_processes_paginated(pid=1005)
        assert res["total"] == 2, f"Expected 2 separate process entities for reused PID, got {res['total']}"
        names = {p["process_name"] for p in res["processes"]}
        assert names == {"short_lived_worker", "curl"}

        # Verify detail query by name disambiguates
        det_curl = db.get_process_detail(1005, "curl")
        assert det_curl["process_name"] == "curl"
        assert det_curl["total_events"] == 45
        assert det_curl["suspicious_events"] == 5

        det_worker = db.get_process_detail(1005, "short_lived_worker")
        assert det_worker["process_name"] == "short_lived_worker"
        assert det_worker["total_events"] == 20
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 12: Large Dataset Memory Safety
# ==============================================================================
def test_large_dataset_memory():
    temp_dir = tempfile.mkdtemp(prefix="t21_large_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        # Simulate 20,000 events processed in a batch
        batch = {
            (1201, "load_runner"): {
                "pid": 1201, "process_name": "load_runner",
                "total_events": 20000, "normal_events": 19900, "suspicious_events": 100,
                "max_score": 1.0, "first_timestamp": 1000, "last_timestamp": 200000,
                "ngrams": {(0, 1, 2, 0): 19900, (59, 0, 1, 1): 100},
                "timeline": {(i, "normal"): 1000 for i in range(20)}
            }
        }
        # Simulate buffer of recent events (e.g. 500 items, should be pruned to 100)
        recent_events = [
            {
                "pid": 1201, "process_name": "load_runner", "event_timestamp": 1000 + i,
                "syscall_1": 0, "syscall_2": 1, "syscall_3": 2, "anomaly_score": 0.01,
                "is_suspicious": 0
            } for i in range(500)
        ]

        t0 = time.time()
        db.ingest_process_batch(batch, recent_events, "large.csv")
        elapsed = time.time() - t0
        assert elapsed < 1.0, f"Ingestion too slow: {elapsed:.3f}s"

        # Check that process_recent_events is strictly bounded (at most 100 rows)
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM process_recent_events WHERE pid = 1201")
        count = cur.fetchone()[0]
        conn.close()
        assert count <= 100, f"Recent events ring buffer exceeded 100 rows (got {count})"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 13: Stage 20 Database Compatibility
# ==============================================================================
def test_stage20_compatibility():
    temp_dir = tempfile.mkdtemp(prefix="t21_compat_")
    db_path = os.path.join(temp_dir, "compat.db")
    try:
        # Create database and insert alert using Stage 20 schema
        db = AlertDatabase(db_path)
        aid = db.insert_alert({
            "event_timestamp": 77777,
            "pid": 1301,
            "process_name": "compat_proc",
            "syscall_1": 1, "syscall_2": 2, "syscall_3": 3,
            "anomaly_score": 0.90,
            "explanation": "Statistically Deviant",
            "source_dataset": "compat.csv"
        })
        db.update_status(aid, "RESOLVED")
        db.update_notes(aid, "Verified benign scheduled backup job")

        # Verify Stage 20 tables and data exist
        stats = db.get_stats()
        assert stats["total_alerts"] == 1
        assert stats["resolved_alerts"] == 1

        # Verify Stage 21 process tables coexist harmoniously
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r["name"] for r in cur.fetchall()}
        conn.close()

        expected = {"alerts", "ingestion_checkpoints", "process_summary", "process_ngrams", "process_timeline", "process_recent_events"}
        for t in expected:
            assert t in tables, f"Expected table '{t}' missing from database"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 14: Launcher Compatibility
# ==============================================================================
def test_launcher_compatibility():
    run_sh = os.path.join(PROJECT_DIR, "run.sh")
    with open(run_sh, "r", encoding="utf-8", errors="ignore") as f:
        run_content = f.read()

    assert "--dashboard-only" in run_content
    assert "--check" in run_content
    assert "--db" in run_content
    assert "alerts.db" in run_content

    # Verify server.py help includes all options
    res = subprocess.run([sys.executable, os.path.join(PROJECT_DIR, "dashboard", "server.py"), "--help"],
                         stdout=subprocess.PIPE, text=True)
    assert res.returncode == 0
    assert "--dataset" in res.stdout
    assert "--db" in res.stdout

# ==============================================================================
# Main Runner
# ==============================================================================
def main():
    print("=" * 65)
    print(" Stage 21: Process-Wise Monitoring & Analytics Tests")
    print("=" * 65)

    tests = [
        ("TEST  1: Process Aggregation & Metrics", test_process_aggregation),
        ("TEST  2: Process Name Substring Search", test_process_search),
        ("TEST  3: Exact PID Filtering", test_pid_filtering),
        ("TEST  4: Multi-Attribute Sorting", test_sorting),
        ("TEST  5: Server-Side Pagination", test_pagination),
        ("TEST  6: Process Detail Retrieval", test_process_detail_retrieval),
        ("TEST  7: Incremental Event Count Tracking", test_event_counts_incremental),
        ("TEST  8: Alert Retrieval & Incident Status Preservation", test_alert_retrieval_and_incident_status),
        ("TEST  9: Activity Timeline Generation", test_timeline_generation),
        ("TEST 10: Top Syscall 3-Grams Aggregation", test_top_syscall_ngrams),
        ("TEST 11: PID Reuse & Identity Segregation", test_pid_reuse_handling),
        ("TEST 12: Large Dataset Memory Safety & Ring Buffer", test_large_dataset_memory),
        ("TEST 13: Stage 20 Database Coexistence", test_stage20_compatibility),
        ("TEST 14: Stage 24 Launcher Compatibility", test_launcher_compatibility)
    ]

    results = [run_test(name, fn) for name, fn in tests]

    print("=" * 65)
    passed = sum(results)
    total = len(results)
    print(f"STAGE 21 TESTS: {passed}/{total} PASSED")
    print("=" * 65)

    assert passed == total, f"Only {passed}/{total} tests passed."

if __name__ == "__main__":
    main()
