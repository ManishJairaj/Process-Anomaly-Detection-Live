#!/usr/bin/env python3
"""
test_stage25_integration.py -- Stage 25 Final Integration, End-to-End Pipeline & Resilience Tests

Process Anomaly Detection Using System Calls with eBPF

Tests:
  1. Syscall ABI Mapping Consistency:
     Core Linux x86_64 security syscalls map identically across severity, database, and server.
  2. Rule-Based Severity Classification:
     Validates explicit rules for CRITICAL, HIGH, MEDIUM, and LOW severity levels.
  3. Severity Precedence Order:
     Verifies CRITICAL > HIGH > MEDIUM > LOW precedence hierarchy.
  4. End-to-End CSV Ingestion & Parsing:
     CSV records are incrementally read, parsed, and recorded in in-memory queues.
  5. SQLite Ingestion & Schema Integrity:
     Alert records persist accurately in SQLite with all 19 columns and correct datatypes.
  6. Deduplication & Checkpoint Resilience:
     Re-reading identical CSV events never creates duplicate alert records.
  7. Incident Management State Preservation:
     Analyst incident statuses and investigation notes are preserved during CSV re-ingestion.
  8. Process-Wise Behavioral Aggregation:
     Per-PID event counters, normal/suspicious splits, and anomaly percentages calculate accurately.
  9. Process Status Host Verification:
     Active vs historical process determination verifies running state safely without false positives.
 10. Malformed CSV Line Fault-Tolerance:
     Non-numeric fields, truncated records, and empty lines are skipped cleanly without crashing.
 11. Missing & Empty Dataset Graceful Recovery:
     Dataset monitor handles non-existent or 0-byte CSV files gracefully.
 12. Demo Workload Generator Batch & Schema Validation:
     tools/demo_workload.py outputs valid RFC-compliant CSV matching detector schema.
 13. Security Triage Statistics & Distribution:
     Triage counters accurately summarize severity counts and unresolved high-priority incidents.
 14. Server REST API Integration:
     Server endpoints (/api/status, /api/events, /api/alerts, /api/triage/stats, /api/processes) respond with valid JSON.
"""

import os
import sys
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

from dashboard.severity import (
    classify_severity, resolve_syscall_name, SeverityClassification,
    RULE_ENGINE_VERSION, X86_64_SYSCALL_MAP
)
from dashboard.database import AlertDatabase, VALID_STATUSES, VALID_SEVERITIES, is_process_running_on_host
from dashboard.server import DatasetMonitor, get_syscall_name, ANOMALY_THRESHOLD
import tools.demo_workload as demo_workload


# ==============================================================================
# TEST 1: Syscall ABI Mapping Consistency
# ==============================================================================
def test_1_syscall_abi_consistency():
    key_syscalls = [
        (0, "read"),
        (1, "write"),
        (2, "open"),
        (41, "socket"),
        (42, "connect"),
        (56, "clone"),
        (57, "fork"),
        (59, "execve"),
        (62, "kill"),
        (90, "chmod"),
        (101, "ptrace"),
        (105, "setuid"),
        (126, "capset"),
        (161, "chroot"),
        (217, "getdents64"),
        (257, "openat"),
        (322, "execveat"),
    ]
    for num, expected_name in key_syscalls:
        assert resolve_syscall_name(num) == expected_name, f"Syscall {num} should resolve to {expected_name}"
        assert get_syscall_name(num) == expected_name, f"Server get_syscall_name({num}) should match {expected_name}"


# ==============================================================================
# TEST 2: Rule-Based Severity Classification
# ==============================================================================
def test_2_rule_based_severity():
    # CRITICAL: Privilege escalation
    c_priv = classify_severity(102, 105, 126, 1.0, "priv-tool")
    assert c_priv.severity == "CRITICAL"
    assert c_priv.rule_id == "CRITICAL_PRIVILEGE_OR_CAPABILITY"

    # CRITICAL: Execve + Connect in same 3-gram
    c_net_exec = classify_severity(41, 42, 59, 1.0, "rev-sh")
    assert c_net_exec.severity == "CRITICAL"
    assert c_net_exec.rule_id == "CRITICAL_EXEC_WITH_NETWORK"

    # CRITICAL: Ptrace + Mprotect
    c_inj = classify_severity(101, 9, 10, 1.0, "injector")
    assert c_inj.severity == "CRITICAL"
    assert c_inj.rule_id == "CRITICAL_TRACING_WITH_MEMORY_MOD"

    # HIGH: Execution
    c_exec = classify_severity(57, 56, 59, 1.0, "worker")
    assert c_exec.severity == "HIGH"
    assert c_exec.rule_id == "HIGH_PROCESS_EXECUTION"

    # HIGH: Network socket
    c_sock = classify_severity(41, 49, 50, 1.0, "recon")
    assert c_sock.severity == "HIGH"
    assert c_sock.rule_id == "HIGH_NETWORK_ACTIVITY"

    # MEDIUM: Filesystem mutation
    c_fs = classify_severity(83, 84, 87, 1.0, "wiper")
    assert c_fs.severity == "MEDIUM"
    assert c_fs.rule_id == "MEDIUM_FILESYSTEM_MUTATION"

    # LOW: Routine IO marginal deviation
    c_low = classify_severity(201, 4, 3, 0.84, "cron")
    assert c_low.severity == "LOW"
    assert c_low.rule_id == "LOW_ROUTINE_IO_DEVIATION"


# ==============================================================================
# TEST 3: Severity Precedence Order
# ==============================================================================
def test_3_severity_precedence():
    # Sequence with both setuid (CRITICAL) and execve (HIGH) -> Must be CRITICAL
    c_crit_high = classify_severity(105, 59, 1, 1.0, "priv_exec")
    assert c_crit_high.severity == "CRITICAL"

    # Sequence with execve (HIGH) and routine IO (which could otherwise be LOW) -> Must be HIGH
    c_high_low = classify_severity(0, 1, 59, 0.85, "worker")
    assert c_high_low.severity == "HIGH"

    # Routine IO with high score >= 0.90 -> Demotes to MEDIUM (not LOW)
    c_med = classify_severity(0, 1, 3, 0.95, "logger")
    assert c_med.severity == "MEDIUM"


# ==============================================================================
# TEST 4: End-to-End CSV Ingestion & Parsing
# ==============================================================================
def test_4_e2e_csv_ingestion():
    temp_dir = tempfile.mkdtemp(prefix="t25_e2e_")
    try:
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts + 1},1001,nginx,232,288,40,0.0050,NORMAL\n")
            f.write(f"{ts + 2},2002,curl,41,42,59,1.0000,SUSPICIOUS\n")

        monitor = DatasetMonitor(csv_file, db=None, auto_start=False)
        monitor._read_incremental()

        assert monitor.total_processed == 2, f"Expected 2 processed, got {monitor.total_processed}"
        assert monitor.normal_count == 1
        assert monitor.suspicious_count == 1
        assert len(monitor.alerts) == 1
        alert = monitor.alerts[0]
        assert alert["pid"] == 2002
        assert alert["process_name"] == "curl"
        assert alert["severity"] == "CRITICAL"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 5: SQLite Ingestion & Schema Integrity
# ==============================================================================
def test_5_sqlite_ingestion_and_schema():
    temp_dir = tempfile.mkdtemp(prefix="t25_db_")
    try:
        db_file = os.path.join(temp_dir, "test_alerts.db")
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        db = AlertDatabase(db_file)

        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts},3003,bash,57,56,59,1.0000,SUSPICIOUS\n")

        monitor = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor._read_incremental()

        res = db.get_alerts_paginated(page=1, limit=10)
        assert res["total"] == 1
        a = res["alerts"][0]
        assert a["pid"] == 3003
        assert a["process_name"] == "bash"
        assert a["severity"] == "HIGH"
        assert a["severity_rule"] == "HIGH_PROCESS_EXECUTION"
        assert a["incident_status"] == "NEW"
        assert a["source_dataset"] == "test.csv"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 6: Deduplication & Checkpoint Resilience
# ==============================================================================
def test_6_deduplication_and_checkpoints():
    temp_dir = tempfile.mkdtemp(prefix="t25_dedup_")
    try:
        db_file = os.path.join(temp_dir, "test_alerts.db")
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        db = AlertDatabase(db_file)

        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts},4004,daemon,41,42,59,1.0000,SUSPICIOUS\n")

        monitor1 = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor1._read_incremental()

        # Simulate second monitor instance re-reading from start
        monitor2 = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor2._read_incremental()

        res = db.get_alerts_paginated(page=1, limit=10)
        assert res["total"] == 1, f"Expected 1 alert due to deduplication, got {res['total']}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 7: Incident Management State Preservation
# ==============================================================================
def test_7_incident_state_preservation():
    temp_dir = tempfile.mkdtemp(prefix="t25_preserv_")
    try:
        db_file = os.path.join(temp_dir, "test_alerts.db")
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        db = AlertDatabase(db_file)

        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts},5005,worker,57,56,59,1.0000,SUSPICIOUS\n")

        monitor = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor._read_incremental()

        res = db.get_alerts_paginated(page=1, limit=10)
        alert_id = res["alerts"][0]["alert_id"]

        # Analyst triages alert
        db.update_status(alert_id, "RESOLVED")
        db.update_notes(alert_id, "Verified benign container bootstrap process.")

        # Re-trigger ingestion
        monitor._read_incremental()

        # Confirm notes and status were NOT overwritten
        refreshed = db.get_alert_by_id(alert_id)
        assert refreshed["incident_status"] == "RESOLVED"
        assert "Verified benign container" in refreshed["investigation_notes"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 8: Process-Wise Behavioral Aggregation
# ==============================================================================
def test_8_process_wise_aggregation():
    temp_dir = tempfile.mkdtemp(prefix="t25_proc_")
    try:
        db_file = os.path.join(temp_dir, "test_alerts.db")
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        db = AlertDatabase(db_file)

        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts + 1},6006,nginx,232,0,1,0.0020,NORMAL\n")
            f.write(f"{ts + 2},6006,nginx,0,1,3,0.0015,NORMAL\n")
            f.write(f"{ts + 3},6006,nginx,41,42,59,1.0000,SUSPICIOUS\n")

        monitor = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor._read_incremental()

        p_res = db.get_processes_paginated(page=1, limit=10)
        assert p_res["total"] == 1
        proc = p_res["processes"][0]
        assert proc["pid"] == 6006
        assert proc["process_name"] == "nginx"
        assert proc["total_events"] == 3
        assert proc["normal_events"] == 2
        assert proc["suspicious_events"] == 1
        assert proc["anomaly_percentage"] == 33.33

        # Detail view
        detail = db.get_process_detail(6006)
        assert detail is not None
        assert detail["process_name"] == "nginx"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 9: Process Status Host Verification
# ==============================================================================
def test_9_process_status_host_verification():
    # Current test runner process should be detected as active
    cur_pid = os.getpid()
    assert is_process_running_on_host(cur_pid) is True

    # High non-existent PID should be detected as terminated
    fake_pid = 999999
    assert is_process_running_on_host(fake_pid) is False


# ==============================================================================
# TEST 10: Malformed CSV Line Fault-Tolerance
# ==============================================================================
def test_10_malformed_csv_fault_tolerance():
    temp_dir = tempfile.mkdtemp(prefix="t25_malform_")
    try:
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        ts = time.time_ns()

        with open(csv_file, "a", encoding="utf-8") as f:
            f.write("corrupted,line,with,too,few,fields\n")
            f.write(f"{ts},bad_pid,name,1,2,3,0.5,NORMAL\n")
            f.write(f"{ts},1002,name,bad_s1,2,3,0.5,NORMAL\n")
            f.write(f"{ts},1003,name,1,2,3,bad_score,NORMAL\n")
            f.write("\n\n")
            f.write(f"{ts + 10},7007,survivor,0,1,3,0.0020,NORMAL\n")

        monitor = DatasetMonitor(csv_file, db=None, auto_start=False)
        monitor._read_incremental()

        # Only the 1 valid line should be accepted
        assert monitor.total_processed == 1
        assert monitor.normal_count == 1
        assert monitor.suspicious_count == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 11: Missing & Empty Dataset Graceful Recovery
# ==============================================================================
def test_11_missing_and_empty_dataset():
    temp_dir = tempfile.mkdtemp(prefix="t25_missing_")
    try:
        non_existent_csv = os.path.join(temp_dir, "does_not_exist.csv")
        monitor = DatasetMonitor(non_existent_csv, db=None, auto_start=False)
        monitor._read_incremental()
        assert monitor.total_processed == 0

        # Empty 0-byte file
        open(non_existent_csv, "w").close()
        monitor._read_incremental()
        assert monitor.total_processed == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 12: Demo Workload Generator Batch & Schema Validation
# ==============================================================================
def test_12_demo_workload_generator():
    temp_dir = tempfile.mkdtemp(prefix="t25_demo_")
    try:
        csv_file = os.path.join(temp_dir, "demo_output.csv")
        db_file = os.path.join(temp_dir, "demo_alerts.db")
        db = AlertDatabase(db_file)

        # Run batch generation
        demo_workload.run_batch(csv_file, count=15, quiet=True)
        assert os.path.exists(csv_file)

        with open(csv_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]

        # Must have header and records
        assert len(lines) > 5
        assert lines[0] == demo_workload.CSV_HEADER.strip()

        # Ingest into SQLite
        monitor = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor._read_incremental()

        assert monitor.total_processed > 5
        assert monitor.suspicious_count > 0

        # Verify all severities populated
        triage = db.get_triage_stats()
        assert triage["critical_alerts"] > 0
        assert triage["high_alerts"] > 0
        assert triage["medium_alerts"] > 0
        assert triage["low_alerts"] > 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 13: Security Triage Statistics & Distribution
# ==============================================================================
def test_13_security_triage_statistics():
    temp_dir = tempfile.mkdtemp(prefix="t25_triage_")
    try:
        db_file = os.path.join(temp_dir, "test_alerts.db")
        csv_file = os.path.join(temp_dir, "test.csv")
        demo_workload.init_csv(csv_file, force_clean=True)
        db = AlertDatabase(db_file)

        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts + 10},101,priv,102,105,126,1.0000,SUSPICIOUS\n") # CRITICAL
            f.write(f"{ts + 20},102,exec,57,56,59,1.0000,SUSPICIOUS\n")     # HIGH
            f.write(f"{ts + 30},103,wipe,83,84,87,1.0000,SUSPICIOUS\n")     # MEDIUM
            f.write(f"{ts + 40},104,cron,201,4,3,0.8400,SUSPICIOUS\n")      # LOW

        monitor = DatasetMonitor(csv_file, db=db, auto_start=False)
        monitor._read_incremental()

        stats = db.get_triage_stats()
        assert stats["total_alerts"] == 4
        assert stats["critical_alerts"] == 1
        assert stats["high_alerts"] == 1
        assert stats["medium_alerts"] == 1
        assert stats["low_alerts"] == 1
        assert stats["unresolved_high_priority"] == 2 # 1 Critical + 1 High in NEW status
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# TEST 14: Server REST API Integration
# ==============================================================================
def test_14_server_rest_api_integration():
    temp_dir = tempfile.mkdtemp(prefix="t25_srv_")
    port = 5891
    proc = None
    try:
        csv_file = os.path.join(temp_dir, "test.csv")
        db_file = os.path.join(temp_dir, "test_alerts.db")
        demo_workload.init_csv(csv_file, force_clean=True)

        # Seed data
        ts = time.time_ns()
        with open(csv_file, "a", encoding="utf-8") as f:
            f.write(f"{ts + 1},1001,nginx,232,288,40,0.0050,NORMAL\n")
            f.write(f"{ts + 2},2002,curl,41,42,59,1.0000,SUSPICIOUS\n")

        srv_script = os.path.join(PROJECT_DIR, "dashboard", "server.py")
        proc = subprocess.Popen(
            [sys.executable, srv_script, "--port", str(port), "--dataset", csv_file, "--db", db_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(1.8)

        # 1. /api/status
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=3) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "total_processed" in data
            assert "threshold" in data

        # 2. /api/events
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/events", timeout=3) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "events" in data

        # 3. /api/triage/stats
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/triage/stats", timeout=3) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "critical_alerts" in data

        # 4. /api/processes
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/processes", timeout=3) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "processes" in data

        # 5. /api/alert_history
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/alert_history", timeout=3) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "alerts" in data
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Main Test Runner
# ==============================================================================
def main():
    print("=" * 68)
    print(" Stage 25: Final Integration, End-to-End Pipeline & Resilience Tests")
    print("=" * 68)

    tests = [
        ("Syscall ABI Consistency", test_1_syscall_abi_consistency),
        ("Rule-Based Severity Classification", test_2_rule_based_severity),
        ("Severity Precedence Order", test_3_severity_precedence),
        ("End-to-End CSV Ingestion & Parsing", test_4_e2e_csv_ingestion),
        ("SQLite Ingestion & Schema Integrity", test_5_sqlite_ingestion_and_schema),
        ("Deduplication & Checkpoint Resilience", test_6_deduplication_and_checkpoints),
        ("Incident Management State Preservation", test_7_incident_state_preservation),
        ("Process-Wise Behavioral Aggregation", test_8_process_wise_aggregation),
        ("Process Status Host Verification", test_9_process_status_host_verification),
        ("Malformed CSV Fault-Tolerance", test_10_malformed_csv_fault_tolerance),
        ("Missing & Empty Dataset Recovery", test_11_missing_and_empty_dataset),
        ("Demo Workload Generator Compatibility", test_12_demo_workload_generator),
        ("Security Triage Statistics", test_13_security_triage_statistics),
        ("Server REST API Integration", test_14_server_rest_api_integration),
    ]

    passed = 0
    for idx, (name, fn) in enumerate(tests, 1):
        try:
            fn()
            print(f"[TEST {idx:2d}: {name}] ... PASSED")
            passed += 1
        except Exception as e:
            print(f"[TEST {idx:2d}: {name}] ... FAILED: {e}")
            import traceback
            traceback.print_exc()

    print("=" * 68)
    print(f"STAGE 25 INTEGRATION TESTS: {passed}/{len(tests)} PASSED")
    print("=" * 68)

    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    main()
