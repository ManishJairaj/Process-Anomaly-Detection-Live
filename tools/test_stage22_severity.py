#!/usr/bin/env python3
"""
test_stage22_severity.py — Automated Unit and Integration Tests for Stage 22:
Rule-Based Alert Severity Classification and Security Triage

Verifies:
 1. Syscall number-to-name architecture-aware mapping
 2. Correct architecture handling (x86_64 ABI)
 3. Unknown/invalid syscall handling without exceptions
 4. HIGH severity rules (execve, ptrace, network, kill, chmod)
 5. MEDIUM severity rules (unseen sequence, filesystem mutation, statistical deviation)
 6. LOW severity rules (marginal score purely of routine I/O)
 7. CRITICAL severity rules (privilege alteration, exec+network, ptrace+mprotect, kernel module)
 8. Rule precedence (CRITICAL > HIGH > MEDIUM > LOW)
 9. Deterministic classification repeatability
10. Database migration adding severity columns
11. Historical alert backfilling without data corruption
12. Live alert ingestion attaching severity
13. Severity filtering via get_alerts_paginated
14. Severity and triage statistics aggregation
15. Severity-aware CSV export
16. Preservation of incident notes and status across re-ingestion
17. Stage 21 process integration (process alerts with severity)
18. Stage 24 launcher compatibility
"""

import os
import sys
import tempfile
import sqlite3
import subprocess

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.severity import (
    classify_severity, resolve_syscall_name, SeverityClassification,
    RULE_ENGINE_VERSION, X86_64_SYSCALL_MAP,
    SYSCALLS_EXEC, SYSCALLS_PTRACE, SYSCALLS_PRIVILEGE, SYSCALLS_NETWORK
)
from dashboard.database import AlertDatabase, VALID_STATUSES, VALID_SEVERITIES

def test_1_syscall_mapping():
    assert resolve_syscall_name(0) == "read", "Syscall 0 should be read"
    assert resolve_syscall_name(1) == "write", "Syscall 1 should be write"
    assert resolve_syscall_name(59) == "execve", "Syscall 59 should be execve"
    assert resolve_syscall_name(101) == "ptrace", "Syscall 101 should be ptrace"
    assert resolve_syscall_name(257) == "openat", "Syscall 257 should be openat"
    assert resolve_syscall_name(322) == "execveat", "Syscall 322 should be execveat"

def test_2_architecture_handling():
    # Verify standard x86_64 syscall count and key ABI definitions
    assert len(X86_64_SYSCALL_MAP) >= 300, "x86_64 table should contain >= 300 syscalls"
    assert X86_64_SYSCALL_MAP[105] == "setuid", "105 must be setuid on x86_64"
    assert X86_64_SYSCALL_MAP[42] == "connect", "42 must be connect on x86_64"

def test_3_unknown_syscall_handling():
    res1 = resolve_syscall_name(9999)
    assert res1 == "unknown(9999)", f"Expected unknown(9999), got {res1}"
    res2 = resolve_syscall_name(-1)
    assert res2 == "unknown(-1)", f"Expected unknown(-1), got {res2}"
    res3 = resolve_syscall_name("invalid")
    assert "invalid" in res3

def test_4_high_severity_rules():
    # Process execution
    c1 = classify_severity(59, 0, 1, 0.95, "bash")
    assert c1.severity == "HIGH"
    assert c1.rule_id == "HIGH_PROCESS_EXECUTION"
    assert "execve" in c1.relevant_syscalls

    # Process tracing
    c2 = classify_severity(101, 0, 1, 0.90, "strace")
    assert c2.severity == "HIGH"
    assert c2.rule_id == "HIGH_PROCESS_TRACING"

    # Network socket
    c3 = classify_severity(41, 0, 1, 0.92, "curl")
    assert c3.severity == "HIGH"
    assert c3.rule_id == "HIGH_NETWORK_ACTIVITY"

    # Process manipulation
    c4 = classify_severity(62, 0, 1, 0.88, "kill")
    assert c4.severity == "HIGH"
    assert c4.rule_id == "HIGH_PROCESS_MANIPULATION"

    # Permission change
    c5 = classify_severity(90, 0, 1, 0.89, "chmod")
    assert c5.severity == "HIGH"
    assert c5.rule_id == "HIGH_PERMISSION_CHANGE"

def test_5_medium_severity_rules():
    # Filesystem mutation
    c1 = classify_severity(257, 83, 84, 0.88, "touch")
    assert c1.severity == "MEDIUM"
    assert c1.rule_id == "MEDIUM_FILESYSTEM_MUTATION"

    # Unseen sequence without critical/high primitives
    c2 = classify_severity(22, 32, 23, 1.0, "pipe_app")
    assert c2.severity == "MEDIUM"
    assert c2.rule_id == "MEDIUM_UNSEEN_SEQUENCE"

    # Statistical deviation
    c3 = classify_severity(9, 11, 12, 0.85, "allocator")
    assert c3.severity == "MEDIUM"
    assert c3.rule_id == "MEDIUM_STATISTICAL_DEVIATION"

def test_6_low_severity_rules():
    # Marginal deviation purely consisting of routine I/O
    c1 = classify_severity(0, 1, 0, 0.82, "logger")
    assert c1.severity == "LOW"
    assert c1.rule_id == "LOW_ROUTINE_IO_DEVIATION"

    c2 = classify_severity(4, 5, 262, 0.84, "finder")
    assert c2.severity == "LOW"
    assert c2.rule_id == "LOW_ROUTINE_IO_DEVIATION"

def test_7_critical_severity_rules():
    # Privilege alteration
    c1 = classify_severity(105, 0, 1, 0.95, "sudo")
    assert c1.severity == "CRITICAL"
    assert c1.rule_id == "CRITICAL_PRIVILEGE_OR_CAPABILITY"

    # Process execution combined with network connection in same 3-gram
    c2 = classify_severity(59, 42, 1, 1.0, "revshell")
    assert c2.severity == "CRITICAL"
    assert c2.rule_id == "CRITICAL_EXEC_WITH_NETWORK"

    # Process tracing combined with memory protection
    c3 = classify_severity(101, 10, 0, 1.0, "injector")
    assert c3.severity == "CRITICAL"
    assert c3.rule_id == "CRITICAL_TRACING_WITH_MEMORY_MOD"

    # Kernel module modification
    c4 = classify_severity(175, 0, 1, 0.99, "insmod")
    assert c4.severity == "CRITICAL"
    assert c4.rule_id == "CRITICAL_KERNEL_MODIFICATION"

def test_8_rule_precedence():
    # Privilege (CRITICAL) vs Exec (HIGH) -> CRITICAL wins
    c1 = classify_severity(105, 59, 0, 1.0)
    assert c1.severity == "CRITICAL"

    # Exec (HIGH) vs Routine I/O (LOW) -> HIGH wins
    c2 = classify_severity(59, 0, 1, 0.82)
    assert c2.severity == "HIGH"

    # Filesystem Mutation (MEDIUM) vs Routine I/O (LOW) -> MEDIUM wins
    c3 = classify_severity(257, 0, 1, 0.82)
    assert c3.severity == "MEDIUM"

def test_9_deterministic_classification():
    runs = [classify_severity(59, 42, 1, 1.0, "app") for _ in range(20)]
    first_dict = runs[0].to_dict()
    for r in runs[1:]:
        assert r.to_dict() == first_dict, "Classification must be 100% deterministic"

def test_10_database_migration():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        # Create legacy Stage 20 schema WITHOUT severity columns
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_timestamp INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                syscall_1 INTEGER NOT NULL,
                syscall_2 INTEGER NOT NULL,
                syscall_3 INTEGER NOT NULL,
                anomaly_score REAL NOT NULL,
                explanation TEXT NOT NULL,
                incident_status TEXT NOT NULL DEFAULT 'NEW',
                investigation_notes TEXT NOT NULL DEFAULT '',
                source_dataset TEXT NOT NULL,
                record_offset INTEGER DEFAULT NULL,
                file_signature TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                last_updated TEXT NOT NULL
            );
        """)
        conn.execute("""
            INSERT INTO alerts (
                event_timestamp, pid, process_name,
                syscall_1, syscall_2, syscall_3,
                anomaly_score, explanation,
                incident_status, investigation_notes,
                source_dataset, created_at, last_updated
            ) VALUES (1000, 100, 'bash', 59, 0, 1, 0.95, 'deviant', 'NEW', 'Legacy note', 'data.csv', '2026-10-29', '2026-10-29');
        """)
        conn.commit()
        conn.close()

        # Initialize AlertDatabase on legacy DB -> triggers Stage 22 migration
        db = AlertDatabase(db_path)
        alert = db.get_alert_by_id(1)
        assert alert is not None
        assert "severity" in alert
        assert alert["severity"] == "HIGH", f"Expected HIGH, got {alert['severity']}"
        assert alert["severity_rule"] == "HIGH_PROCESS_EXECUTION"
        assert alert["investigation_notes"] == "Legacy note", "Notes must be preserved"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_11_historical_alert_backfilling():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        # Insert without severity
        a1_id = db.insert_alert({
            "event_timestamp": 2000,
            "pid": 200,
            "process_name": "curl",
            "syscall_1": 42,
            "syscall_2": 0,
            "syscall_3": 1,
            "anomaly_score": 0.92,
            "explanation": "dev",
            "source_dataset": "test.csv"
        })
        a1 = db.get_alert_by_id(a1_id)
        assert a1["severity"] == "HIGH"
        assert a1["severity_rule"] == "HIGH_NETWORK_ACTIVITY"

        # Re-run backfill -> idempotent
        conn = db.get_connection()
        updated = db._backfill_severity(conn)
        conn.close()
        assert updated == 0, "Second backfill should update 0 rows"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_12_live_alert_ingestion():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        batch = [
            {
                "event_timestamp": 3000,
                "pid": 300,
                "process_name": "sudo",
                "syscall_1": 105,
                "syscall_2": 0,
                "syscall_3": 1,
                "anomaly_score": 1.0,
                "explanation": "unseen",
                "source_dataset": "live.csv"
            },
            {
                "event_timestamp": 3001,
                "pid": 301,
                "process_name": "cat",
                "syscall_1": 0,
                "syscall_2": 1,
                "syscall_3": 0,
                "anomaly_score": 0.81,
                "explanation": "marginal",
                "source_dataset": "live.csv"
            }
        ]
        inserted = db.ingest_batch(batch)
        assert inserted == 2

        sudo_alert = db.get_alert_by_id(1)
        assert sudo_alert["severity"] == "CRITICAL"

        cat_alert = db.get_alert_by_id(2)
        assert cat_alert["severity"] == "LOW"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_13_severity_filtering():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        db.insert_alert({
            "event_timestamp": 4001, "pid": 401, "process_name": "sudo",
            "syscall_1": 105, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 1.0,
            "explanation": "e", "source_dataset": "d"
        })
        db.insert_alert({
            "event_timestamp": 4002, "pid": 402, "process_name": "bash",
            "syscall_1": 59, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 0.95,
            "explanation": "e", "source_dataset": "d"
        })

        crit_res = db.get_alerts_paginated(severity="CRITICAL")
        assert crit_res["total"] == 1
        assert crit_res["alerts"][0]["process_name"] == "sudo"

        high_res = db.get_alerts_paginated(severity="HIGH")
        assert high_res["total"] == 1
        assert high_res["alerts"][0]["process_name"] == "bash"

        med_res = db.get_alerts_paginated(severity="MEDIUM")
        assert med_res["total"] == 0
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_14_severity_and_triage_statistics():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        db.insert_alert({
            "event_timestamp": 5001, "pid": 501, "process_name": "root_tool",
            "syscall_1": 105, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 1.0,
            "explanation": "e", "source_dataset": "d", "incident_status": "NEW"
        })
        db.insert_alert({
            "event_timestamp": 5002, "pid": 502, "process_name": "bash",
            "syscall_1": 59, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 0.95,
            "explanation": "e", "source_dataset": "d", "incident_status": "INVESTIGATING"
        })
        db.insert_alert({
            "event_timestamp": 5003, "pid": 503, "process_name": "bash",
            "syscall_1": 59, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 0.95,
            "explanation": "e", "source_dataset": "d", "incident_status": "RESOLVED"
        })

        stats = db.get_stats()
        assert stats["critical_alerts"] == 1
        assert stats["high_alerts"] == 2
        assert stats["unresolved_high_priority"] == 2

        triage = db.get_triage_stats()
        assert triage["critical_alerts"] == 1
        assert triage["high_alerts"] == 2
        assert triage["unresolved_high_priority"] == 2
        assert len(triage["top_flagged_processes"]) >= 1
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_15_severity_aware_csv_export():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        db.insert_alert({
            "event_timestamp": 6001, "pid": 601, "process_name": "sudo",
            "syscall_1": 105, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 1.0,
            "explanation": "e", "source_dataset": "d"
        })
        rows = db.export_filtered_rows(severity="CRITICAL")
        assert len(rows) == 1
        assert rows[0]["severity"] == "CRITICAL"
        assert "severity_rule" in rows[0]
        assert "severity_reason" in rows[0]
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_16_preservation_of_incident_notes():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        aid = db.insert_alert({
            "event_timestamp": 7001, "pid": 701, "process_name": "curl",
            "syscall_1": 42, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 0.9,
            "explanation": "e", "source_dataset": "d",
            "record_offset": 100, "file_signature": "sig1",
            "investigation_notes": "Analyst note 123"
        })
        db.update_status(aid, "INVESTIGATING")

        # Ingest identical event with duplicate check -> must ignore and keep status and notes
        reingested = db.insert_alert({
            "event_timestamp": 7001, "pid": 701, "process_name": "curl",
            "syscall_1": 42, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 0.9,
            "explanation": "e", "source_dataset": "d",
            "record_offset": 100, "file_signature": "sig1",
            "investigation_notes": "Overwriting note"
        })
        assert reingested is None, "Duplicate event must be ignored"

        alert = db.get_alert_by_id(aid)
        assert alert["incident_status"] == "INVESTIGATING"
        assert alert["investigation_notes"] == "Analyst note 123"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_17_stage21_process_integration():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = AlertDatabase(db_path)
        db.insert_alert({
            "event_timestamp": 8001, "pid": 801, "process_name": "testproc",
            "syscall_1": 59, "syscall_2": 0, "syscall_3": 1, "anomaly_score": 0.95,
            "explanation": "e", "source_dataset": "d"
        })
        proc_alerts = db.get_process_alerts(801, "testproc")
        assert len(proc_alerts) == 1
        assert proc_alerts[0]["severity"] == "HIGH"
        assert proc_alerts[0]["severity_rule"] == "HIGH_PROCESS_EXECUTION"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_18_launcher_compatibility():
    # Verify dashboard server launches and responds with severity endpoints
    proc = subprocess.Popen(
        [sys.executable, "dashboard/server.py", "--port", "5099", "--dataset", "gt_eval_dataset.csv"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    try:
        import time
        import urllib.request
        time.sleep(1.5)

        # Probe triage endpoint
        req = urllib.request.Request("http://127.0.0.1:5099/api/triage/stats")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            import json
            data = json.loads(resp.read().decode('utf-8'))
            assert "critical_alerts" in data
            assert "unresolved_high_priority" in data
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

def main():
    print("=" * 65)
    print(" Stage 22: Rule-Based Severity Classification & Triage Tests")
    print("=" * 65)

    tests = [
        ("Syscall Mapping", test_1_syscall_mapping),
        ("Architecture Handling", test_2_architecture_handling),
        ("Unknown Syscall Handling", test_3_unknown_syscall_handling),
        ("HIGH Severity Rules", test_4_high_severity_rules),
        ("MEDIUM Severity Rules", test_5_medium_severity_rules),
        ("LOW Severity Rules", test_6_low_severity_rules),
        ("CRITICAL Severity Rules", test_7_critical_severity_rules),
        ("Rule Precedence", test_8_rule_precedence),
        ("Deterministic Classification", test_9_deterministic_classification),
        ("Database Migration", test_10_database_migration),
        ("Historical Backfill", test_11_historical_alert_backfilling),
        ("Live Alert Ingestion", test_12_live_alert_ingestion),
        ("Severity Filtering", test_13_severity_filtering),
        ("Severity Statistics", test_14_severity_and_triage_statistics),
        ("Severity-Aware CSV Export", test_15_severity_aware_csv_export),
        ("Notes Preservation", test_16_preservation_of_incident_notes),
        ("Stage 21 Integration", test_17_stage21_process_integration),
        ("Stage 24 Launcher Compatibility", test_18_launcher_compatibility)
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

    print("=" * 65)
    print(f"STAGE 22 TESTS: {passed}/{len(tests)} PASSED")
    print("=" * 65)

    if passed != len(tests):
        sys.exit(1)

if __name__ == "__main__":
    main()
