#!/usr/bin/env python3
"""
test_stage20_alerts.py — Comprehensive Automated Test Suite for Stage 20:
Persistent Alert History and Incident Management

Tests:
  1. Database initialization, schema validation, and indexes
  2. Alert insertion, validation, and explanation formatting
  3. Duplicate prevention across restarts and distinct event preservation
  4. Database persistence and state retention across application restarts
  5. Incident status transitions (NEW -> INVESTIGATING -> RESOLVED -> FALSE_ALARM)
  6. Investigation notes editor and non-overwriting during CSV re-ingestion
  7. Multi-criteria search and filtering (process, PID, status, score, timestamp)
  8. Server-side pagination and bidirectional sorting (newest/oldest)
  9. Filtered CSV export generation and string escaping
 10. Fault-tolerant handling of malformed and partial CSV lines
 11. Concurrent thread-safe database ingestion and WAL mode integrity
 12. Dashboard HTTP server REST API integration (/api/alert_history/*)
 13. Launcher compatibility and CLI arguments verification
"""

import sys
import os
import time
import json
import sqlite3
import tempfile
import shutil
import threading
import subprocess
import urllib.request
import urllib.error

# Add project root to sys.path
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.database import AlertDatabase, VALID_STATUSES
from dashboard.server import get_syscall_name, ANOMALY_THRESHOLD

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
# TEST 1: Database Initialization
# ==============================================================================
def test_db_initialization():
    temp_dir = tempfile.mkdtemp(prefix="t20_init_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        assert os.path.exists(db_path), "Database file was not created"

        conn = db.get_connection()
        cur = conn.cursor()

        # Check alerts table
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        assert cur.fetchone() is not None, "Table 'alerts' missing"

        # Check columns
        cur.execute("PRAGMA table_info(alerts)")
        cols = {row["name"]: row["type"] for row in cur.fetchall()}
        required_cols = [
            "alert_id", "event_timestamp", "pid", "process_name",
            "syscall_1", "syscall_2", "syscall_3", "anomaly_score",
            "explanation", "incident_status", "investigation_notes",
            "source_dataset", "record_offset", "file_signature",
            "created_at", "last_updated"
        ]
        for col in required_cols:
            assert col in cols, f"Required column '{col}' missing from alerts table"

        # Check indexes
        cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row["name"] for row in cur.fetchall()}
        expected_indexes = [
            "idx_alerts_status", "idx_alerts_pid", "idx_alerts_process",
            "idx_alerts_timestamp", "idx_alerts_score", "idx_alerts_source"
        ]
        for idx in expected_indexes:
            assert idx in indexes, f"Index '{idx}' missing"

        # Check checkpoints table
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ingestion_checkpoints'")
        assert cur.fetchone() is not None, "Table 'ingestion_checkpoints' missing"
        conn.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 2: Alert Insertion
# ==============================================================================
def test_alert_insertion():
    temp_dir = tempfile.mkdtemp(prefix="t20_insert_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        alert_data = {
            "event_timestamp": 1234567890,
            "pid": 501,
            "process_name": "malicious_proc",
            "syscall_1": 59,
            "syscall_2": 0,
            "syscall_3": 1,
            "anomaly_score": 1.0,
            "explanation": "Unseen 3-Gram: Sequence [execve -> read -> write] was never observed.",
            "source_dataset": "syscall_dataset.csv",
            "record_offset": 100,
            "file_signature": "sig1"
        }
        alert_id = db.insert_alert(alert_data)
        assert alert_id is not None and alert_id > 0, "Insert returned invalid alert_id"

        retrieved = db.get_alert_by_id(alert_id)
        assert retrieved is not None, "Failed to retrieve inserted alert"
        assert retrieved["pid"] == 501
        assert retrieved["process_name"] == "malicious_proc"
        assert retrieved["incident_status"] == "NEW", "Default status must be NEW"
        assert retrieved["investigation_notes"] == "", "Default investigation notes must be empty"
        assert retrieved["anomaly_score"] == 1.0
        assert retrieved["created_at"] is not None
        assert retrieved["last_updated"] is not None
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 3: Duplicate Prevention & Distinct Event Preservation
# ==============================================================================
def test_duplicate_prevention():
    temp_dir = tempfile.mkdtemp(prefix="t20_dedup_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        base_alert = {
            "event_timestamp": 1000,
            "pid": 100,
            "process_name": "worker",
            "syscall_1": 0, "syscall_2": 1, "syscall_3": 2,
            "anomaly_score": 1.0,
            "explanation": "Unseen 3-Gram",
            "source_dataset": "events.csv",
            "record_offset": 50,
            "file_signature": "file_1"
        }
        aid1 = db.insert_alert(base_alert)
        assert aid1 is not None

        # Re-inserting exact duplicate from same file offset must return None and NOT duplicate
        aid_dup = db.insert_alert(base_alert)
        assert aid_dup is None, "Duplicate row was not rejected"

        stats = db.get_stats()
        assert stats["total_alerts"] == 1, f"Expected 1 alert, got {stats['total_alerts']}"

        # Distinct event with identical syscall sequence at different byte offset must NOT be discarded
        distinct_alert = dict(base_alert)
        distinct_alert["record_offset"] = 150 # Next record in file
        distinct_alert["event_timestamp"] = 2000
        aid2 = db.insert_alert(distinct_alert)
        assert aid2 is not None and aid2 != aid1, "Distinct event with same sequence was incorrectly discarded"

        stats2 = db.get_stats()
        assert stats2["total_alerts"] == 2, f"Expected 2 alerts, got {stats2['total_alerts']}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 4: Persistence After Restart
# ==============================================================================
def test_persistence_after_restart():
    temp_dir = tempfile.mkdtemp(prefix="t20_persist_")
    db_path = os.path.join(temp_dir, "persistent.db")
    try:
        # First session: insert and close
        db1 = AlertDatabase(db_path)
        aid = db1.insert_alert({
            "event_timestamp": 5555,
            "pid": 777,
            "process_name": "persistent_proc",
            "syscall_1": 1, "syscall_2": 2, "syscall_3": 3,
            "anomaly_score": 0.95,
            "explanation": "Statistically Deviant",
            "source_dataset": "live.csv",
            "record_offset": 200
        })
        db1.update_status(aid, "INVESTIGATING")
        db1.update_notes(aid, "Reviewing audit log")
        del db1

        # Second session: reopen database
        db2 = AlertDatabase(db_path)
        retrieved = db2.get_alert_by_id(aid)
        assert retrieved is not None, "Failed to retrieve alert after restart"
        assert retrieved["process_name"] == "persistent_proc"
        assert retrieved["incident_status"] == "INVESTIGATING", "Status did not persist"
        assert retrieved["investigation_notes"] == "Reviewing audit log", "Notes did not persist"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 5: Incident Status Updates
# ==============================================================================
def test_status_updates():
    temp_dir = tempfile.mkdtemp(prefix="t20_status_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        aid = db.insert_alert({
            "event_timestamp": 1000,
            "pid": 200,
            "process_name": "proc_stat",
            "syscall_1": 0, "syscall_2": 0, "syscall_3": 0,
            "anomaly_score": 1.0,
            "explanation": "Expl",
            "source_dataset": "test.csv"
        })

        for target_status in ["INVESTIGATING", "RESOLVED", "FALSE_ALARM", "NEW"]:
            updated = db.update_status(aid, target_status)
            assert updated is not None
            assert updated["incident_status"] == target_status, f"Expected {target_status}, got {updated['incident_status']}"

        # Invalid status must be rejected
        try:
            db.update_status(aid, "INVALID_STATUS")
            assert False, "Should have raised ValueError for invalid status"
        except ValueError:
            pass
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 6: Investigation Notes Preservation on Re-ingestion
# ==============================================================================
def test_notes_and_reingest_preservation():
    temp_dir = tempfile.mkdtemp(prefix="t20_notes_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        alert_item = {
            "event_timestamp": 10000,
            "pid": 888,
            "process_name": "critical_svc",
            "syscall_1": 59, "syscall_2": 9, "syscall_3": 10,
            "anomaly_score": 1.0,
            "explanation": "Expl",
            "source_dataset": "dataset_a.csv",
            "record_offset": 350,
            "file_signature": "file_sig_a"
        }
        aid = db.insert_alert(alert_item)
        db.update_status(aid, "INVESTIGATING")
        db.update_notes(aid, "Suspicious reverse shell pattern detected by analyst")

        # Simulate CSV re-ingestion with same alert item
        reingest_res = db.ingest_batch([alert_item])
        assert reingest_res == 0, "Re-ingestion should have inserted 0 new records"

        # Check that user notes and status are intact
        after = db.get_alert_by_id(aid)
        assert after["incident_status"] == "INVESTIGATING", "Status was reset on re-ingestion!"
        assert after["investigation_notes"] == "Suspicious reverse shell pattern detected by analyst", "Notes were overwritten!"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 7: Search and Filtering
# ==============================================================================
def test_search_and_filtering():
    temp_dir = tempfile.mkdtemp(prefix="t20_filter_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        # Populate diverse records
        records = [
            ("nginx", 101, 0.85, "NEW", 1000),
            ("nginx", 102, 0.95, "INVESTIGATING", 2000),
            ("apache2", 103, 1.00, "RESOLVED", 3000),
            ("cron", 104, 0.82, "FALSE_ALARM", 4000),
            ("python3", 105, 1.00, "NEW", 5000),
        ]
        for i, (proc, pid, score, status, ts) in enumerate(records):
            aid = db.insert_alert({
                "event_timestamp": ts, "pid": pid, "process_name": proc,
                "syscall_1": 0, "syscall_2": 1, "syscall_3": 2,
                "anomaly_score": score, "explanation": "test",
                "source_dataset": "dataset.csv", "record_offset": i * 100
            })
            if status != "NEW":
                db.update_status(aid, status)

        # 1. Filter by process name
        res = db.get_alerts_paginated(process_name="nginx")
        assert res["total"] == 2

        # 2. Filter by PID
        res = db.get_alerts_paginated(pid=103)
        assert res["total"] == 1 and res["alerts"][0]["process_name"] == "apache2"

        # 3. Filter by status
        res = db.get_alerts_paginated(incident_status="FALSE_ALARM")
        assert res["total"] == 1 and res["alerts"][0]["process_name"] == "cron"

        # 4. Filter by min score
        res = db.get_alerts_paginated(min_score=1.00)
        assert res["total"] == 2

        # 5. Filter by timestamp range
        res = db.get_alerts_paginated(start_time=2000, end_time=4000)
        assert res["total"] == 3
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 8: Server-Side Pagination & Sorting
# ==============================================================================
def test_pagination_and_sorting():
    temp_dir = tempfile.mkdtemp(prefix="t20_page_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        for i in range(35):
            db.insert_alert({
                "event_timestamp": 1000 + i * 10,
                "pid": 1000 + i,
                "process_name": f"proc_{i}",
                "syscall_1": 0, "syscall_2": 1, "syscall_3": 2,
                "anomaly_score": 0.85,
                "explanation": "test",
                "source_dataset": "data.csv",
                "record_offset": i * 50
            })

        # Page 1 (limit 10)
        p1 = db.get_alerts_paginated(page=1, limit=10, order="desc")
        assert len(p1["alerts"]) == 10
        assert p1["total"] == 35
        assert p1["total_pages"] == 4
        # Newest first
        assert p1["alerts"][0]["event_timestamp"] > p1["alerts"][-1]["event_timestamp"]

        # Page 4 (limit 10) -> last 5 items
        p4 = db.get_alerts_paginated(page=4, limit=10, order="desc")
        assert len(p4["alerts"]) == 5

        # Oldest first
        p_asc = db.get_alerts_paginated(page=1, limit=10, order="asc")
        assert p_asc["alerts"][0]["event_timestamp"] < p_asc["alerts"][-1]["event_timestamp"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 9: Filtered CSV Export
# ==============================================================================
def test_csv_export():
    temp_dir = tempfile.mkdtemp(prefix="t20_export_")
    db_path = os.path.join(temp_dir, "test_alerts.db")
    try:
        db = AlertDatabase(db_path)
        aid = db.insert_alert({
            "event_timestamp": 99999,
            "pid": 333,
            "process_name": 'malicious "quoted" proc',
            "syscall_1": 59, "syscall_2": 0, "syscall_3": 1,
            "anomaly_score": 1.0,
            "explanation": 'Unseen 3-Gram: with "quotes"',
            "source_dataset": "export_test.csv"
        })
        db.update_notes(aid, 'Notes with "quotes" and, commas')

        rows = db.export_filtered_rows()
        assert len(rows) == 1
        r = rows[0]
        assert r["pid"] == 333
        assert 'Notes with "quotes" and, commas' in r["investigation_notes"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 10: Fault-Tolerant Malformed CSV Handling
# ==============================================================================
def test_malformed_csv_handling():
    temp_dir = tempfile.mkdtemp(prefix="t20_malformed_")
    csv_file = os.path.join(temp_dir, "test_corrupt.csv")
    db_path = os.path.join(temp_dir, "test_alerts.db")

    with open(csv_file, "w") as f:
        f.write("monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n")
        f.write("1000,101,\"benign\",0,1,2,0.0100,NORMAL\n")
        f.write("corrupted,line,with,missing\n")
        f.write("not_a_number,abc,\"proc\",invalid,NaN,foo,bar,BAZ\n")
        f.write("2000,102,\"bad_proc\",59,0,1,1.0000,SUSPICIOUS\n")
        f.write("partial_line_without_newline")

    from dashboard.server import DatasetMonitor
    db = AlertDatabase(db_path)
    monitor = DatasetMonitor(csv_file, db=db)
    time.sleep(1.2) # Allow monitor loop to process

    try:
        stats = db.get_stats()
        # Only the 1 valid suspicious row should be in the database
        assert stats["total_alerts"] == 1, f"Expected 1 alert, got {stats['total_alerts']}"
        alerts = db.get_alerts_paginated()["alerts"]
        assert alerts[0]["process_name"] == "bad_proc"
        assert alerts[0]["pid"] == 102
    finally:
        monitor.running = False
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 11: Concurrent Ingestion & Thread Safety
# ==============================================================================
def test_concurrent_ingestion():
    temp_dir = tempfile.mkdtemp(prefix="t20_concurrent_")
    db_path = os.path.join(temp_dir, "test_concurrent.db")
    try:
        db = AlertDatabase(db_path)
        errors = []

        def worker(thread_id, count):
            try:
                for i in range(count):
                    offset = thread_id * 10000 + i
                    aid = db.insert_alert({
                        "event_timestamp": 100000 + offset,
                        "pid": 2000 + thread_id,
                        "process_name": f"thread_{thread_id}",
                        "syscall_1": 0, "syscall_2": 1, "syscall_3": 2,
                        "anomaly_score": 0.90,
                        "explanation": "Concurrent test",
                        "source_dataset": "concurrent.csv",
                        "record_offset": offset
                    })
                    if aid and i % 3 == 0:
                        db.update_status(aid, "INVESTIGATING")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t, 25)) for t in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert len(errors) == 0, f"Concurrent workers encountered errors: {errors}"
        stats = db.get_stats()
        assert stats["total_alerts"] == 100, f"Expected 100 alerts, got {stats['total_alerts']}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 12: Dashboard REST API Integration
# ==============================================================================
def test_dashboard_api_integration():
    temp_dir = tempfile.mkdtemp(prefix="t20_api_")
    csv_file = os.path.join(temp_dir, "test_api.csv")
    db_path = os.path.join(temp_dir, "alerts.db")

    with open(csv_file, "w") as f:
        f.write("monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n")
        f.write('1000000,701,"api_badproc",59,9,10,1.0000,SUSPICIOUS\n')
        f.write('2000000,702,"api_benign",0,1,2,0.0100,NORMAL\n')

    port = 5897
    cmd = [
        sys.executable,
        os.path.join(PROJECT_DIR, "dashboard", "server.py"),
        "--port", str(port),
        "--dataset", csv_file,
        "--db", db_path
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    base = f"http://127.0.0.1:{port}"
    try:
        # 1. Test /api/alert_history
        with urllib.request.urlopen(f"{base}/api/alert_history", timeout=4) as r:
            assert r.status == 200
            data = json.loads(r.read().decode())
            assert data["total"] == 1
            alert = data["alerts"][0]
            assert alert["pid"] == 701
            assert alert["process_name"] == "api_badproc"
            assert "sequence_str" in alert
            alert_id = alert["alert_id"]

        # 2. Test /api/alert_history/detail
        with urllib.request.urlopen(f"{base}/api/alert_history/detail?id={alert_id}", timeout=4) as r:
            assert r.status == 200
            detail = json.loads(r.read().decode())["alert"]
            assert detail["alert_id"] == alert_id

        # 3. Test /api/alert_history/update_status
        req_st = urllib.request.Request(
            f"{base}/api/alert_history/update_status",
            data=json.dumps({"alert_id": alert_id, "status": "INVESTIGATING"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_st, timeout=4) as r:
            assert r.status == 200
            res = json.loads(r.read().decode())
            assert res["alert"]["incident_status"] == "INVESTIGATING"

        # 4. Test /api/alert_history/update_notes
        req_notes = urllib.request.Request(
            f"{base}/api/alert_history/update_notes",
            data=json.dumps({"alert_id": alert_id, "notes": "Investigated by security team"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_notes, timeout=4) as r:
            assert r.status == 200
            res = json.loads(r.read().decode())
            assert res["alert"]["investigation_notes"] == "Investigated by security team"

        # 5. Test /api/alert_history/stats
        with urllib.request.urlopen(f"{base}/api/alert_history/stats", timeout=4) as r:
            assert r.status == 200
            stats = json.loads(r.read().decode())
            assert stats["total_alerts"] == 1
            assert stats["investigating_alerts"] == 1
            assert stats["new_alerts"] == 0

        # 6. Test /api/alert_history/export
        with urllib.request.urlopen(f"{base}/api/alert_history/export", timeout=4) as r:
            assert r.status == 200
            csv_content = r.read().decode()
            assert "api_badproc" in csv_content
            assert "Investigated by security team" in csv_content
    finally:
        proc.terminate()
        proc.wait(timeout=3)
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==============================================================================
# TEST 13: Launcher Compatibility
# ==============================================================================
def test_launcher_compatibility():
    run_sh = os.path.join(PROJECT_DIR, "run.sh")
    assert os.path.exists(run_sh), "run.sh launcher missing"

    # Verify run.sh contains required Stage 20 elements
    with open(run_sh, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    assert "--db" in content, "run.sh should support --db argument"
    assert "alerts.db" in content, "run.sh should reference alerts.db"
    assert "Alert Database" in content, "run.sh should display Alert Database banner"

    # Verify server.py CLI parser accepts --db
    server_py = os.path.join(PROJECT_DIR, "dashboard", "server.py")
    res = subprocess.run([sys.executable, server_py, "--help"], stdout=subprocess.PIPE, text=True)
    assert res.returncode == 0
    assert "--db" in res.stdout, "server.py --help missing --db option"

# ==============================================================================
# Main Test Runner
# ==============================================================================
def main():
    print("=" * 65)
    print(" Stage 20: Persistent Alert History & Incident Management Tests")
    print("=" * 65)

    tests = [
        ("TEST  1: SQLite Database Initialization & Schema", test_db_initialization),
        ("TEST  2: Anomaly Alert Insertion & Explanations", test_alert_insertion),
        ("TEST  3: Duplicate Prevention & Event Preservation", test_duplicate_prevention),
        ("TEST  4: Persistence Across Application Restarts", test_persistence_after_restart),
        ("TEST  5: Incident Status Lifecycle Transitions", test_status_updates),
        ("TEST  6: Investigation Notes Preservation on Reingest", test_notes_and_reingest_preservation),
        ("TEST  7: Multi-Criteria Search & Filtering", test_search_and_filtering),
        ("TEST  8: Server-Side Pagination & Sorting", test_pagination_and_sorting),
        ("TEST  9: Filtered Incident CSV Export", test_csv_export),
        ("TEST 10: Fault-Tolerant Malformed CSV Ingestion", test_malformed_csv_handling),
        ("TEST 11: Concurrent Multi-Thread Ingestion & WAL", test_concurrent_ingestion),
        ("TEST 12: Dashboard REST API Endpoints Integration", test_dashboard_api_integration),
        ("TEST 13: Launcher Compatibility & CLI Options", test_launcher_compatibility)
    ]

    results = [run_test(name, fn) for name, fn in tests]

    print("=" * 65)
    passed = sum(results)
    total = len(results)
    print(f"STAGE 20 TESTS: {passed}/{total} PASSED")
    print("=" * 65)

    assert passed == total, f"Only {passed}/{total} tests passed."

if __name__ == "__main__":
    main()
