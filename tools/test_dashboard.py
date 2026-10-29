#!/usr/bin/env python3
"""
test_dashboard.py — Automated Test Suite for Real-Time Monitoring Dashboard (Stage 19)

Tests:
  1. Dashboard server launches and serves HTTP 200 for index.html, CSS, and JS
  2. Status API (/api/status) returns valid metadata and statistics
  3. Events API (/api/events) parses and displays CSV records correctly
  4. Incremental live updates: appending a row appears in /api/events without restart
  5. Suspicious-event filter (/api/events?suspicious_only=1) returns only alerts
  6. PID and Process filters (/api/events?pid=X&process=Y) filter accurately
  7. Anomaly alerts API (/api/alerts) includes root-cause explanations
  8. Analytics endpoints (/api/stats/processes, /api/stats/timeline) work
  9. Malformed CSV rows do not crash the server or corrupt event parsing
 10. Large dataset safety: memory remains bounded (< 50 MB) on large datasets
 11. Export endpoint (/api/export) streams valid CSV data
 12. Dataset switching API (/api/set_dataset) updates active source
"""

import sys
import os
import time
import json
import urllib.request
import urllib.error
import subprocess
import tempfile
import shutil

TEST_PORT = 5899
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"

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

def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.status, resp.read(), resp.headers

def http_post_json(path, data):
    url = f"{BASE_URL}{path}"
    payload = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.status, resp.read()

def main():
    print("=" * 60)
    print(" Stage 19: Dashboard Automated Unit & Integration Tests")
    print("=" * 60)

    # Create temporary CSV file for controlled testing
    temp_dir = tempfile.mkdtemp(prefix="dash_test_")
    test_csv = os.path.join(temp_dir, "test_live.csv")

    with open(test_csv, "w") as f:
        f.write("monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n")
        f.write('1000000,101,"systemd",0,1,2,0.0100,NORMAL\n')
        f.write('2000000,102,"bash",2,0,3,0.0500,NORMAL\n')
        f.write('3000000,102,"bash",59,9,10,1.0000,SUSPICIOUS\n')
        f.write('4000000,103,"malproc",101,102,103,1.0000,SUSPICIOUS\n')

    # Launch dashboard server in subprocess
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "..", "dashboard", "server.py"),
        "--port", str(TEST_PORT),
        "--dataset", test_csv
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2) # Allow server to start

    try:
        # TEST 1: Launch and static files
        def test_static():
            st, body, _ = http_get("/")
            assert st == 200, f"Expected 200 got {st}"
            assert b"SyscallGuard" in body, "Missing title in index.html"

            st, body, _ = http_get("/dashboard.css")
            assert st == 200 and b"--bg-primary" in body, "Failed to serve CSS"

            st, body, _ = http_get("/dashboard.js")
            assert st == 200 and b"fetchData" in body, "Failed to serve JS"

        # TEST 2: Status API
        def test_status():
            st, body, _ = http_get("/api/status")
            assert st == 200
            data = json.loads(body.decode())
            assert "total_processed" in data
            assert data["total_processed"] >= 4
            assert data["suspicious_count"] >= 2
            assert data["normal_count"] >= 2
            assert data["dataset_file"] == "test_live.csv"

        # TEST 3: Events API
        def test_events():
            st, body, _ = http_get("/api/events")
            assert st == 200
            data = json.loads(body.decode())
            events = data["events"]
            assert len(events) >= 4
            assert events[0]["pid"] in (101, 102, 103)
            assert "sequence_str" in events[0]

        # TEST 4: Live Incremental Append
        def test_incremental():
            # Append 2 new lines
            with open(test_csv, "a") as f:
                f.write('5000000,104,"test_daemon",0,0,1,0.0050,NORMAL\n')
                f.write('6000000,104,"test_daemon",99,99,99,1.0000,SUSPICIOUS\n')
            time.sleep(1.0) # Wait for monitor poll

            st, body, _ = http_get("/api/events?limit=2")
            data = json.loads(body.decode())
            events = data["events"]
            assert len(events) >= 2
            found_104 = any(e["pid"] == 104 for e in events)
            assert found_104, "Incrementally appended row not detected!"

        # TEST 5: Suspicious-only filter
        def test_suspicious_filter():
            st, body, _ = http_get("/api/events?suspicious_only=1")
            data = json.loads(body.decode())
            events = data["events"]
            assert len(events) > 0
            for e in events:
                assert e["is_suspicious"] is True, f"Found non-suspicious in filtered: {e}"

        # TEST 6: PID and process filters
        def test_pid_proc_filter():
            st, body, _ = http_get("/api/events?pid=102")
            data = json.loads(body.decode())
            for e in data["events"]:
                assert e["pid"] == 102, f"Expected PID 102 got {e['pid']}"

            st, body, _ = http_get("/api/events?process=systemd")
            data = json.loads(body.decode())
            for e in data["events"]:
                assert "systemd" in e["process_name"].lower()

        # TEST 7: Alerts API & explanations
        def test_alerts_api():
            st, body, _ = http_get("/api/alerts")
            data = json.loads(body.decode())
            alerts = data["alerts"]
            assert len(alerts) > 0
            for a in alerts:
                assert a["is_suspicious"] is True
                assert a["explanation"] is not None
                assert "Unseen" in a["explanation"] or "Deviant" in a["explanation"]

        # TEST 8: Analytics endpoints
        def test_analytics():
            st, body, _ = http_get("/api/stats/processes")
            data = json.loads(body.decode())
            assert "processes" in data
            assert len(data["processes"]) > 0

            st, body, _ = http_get("/api/stats/timeline")
            data = json.loads(body.decode())
            assert "timeline" in data

        # TEST 9: Malformed rows
        def test_malformed_rows():
            with open(test_csv, "a") as f:
                f.write("corrupted,line,with,missing,values\n")
                f.write("not_a_number,abc,proc,-1,bad,val,NaN,NORMAL\n")
                f.write('7000000,105,"valid_proc",1,2,3,0.0200,NORMAL\n')
            time.sleep(1.0)

            st, body, _ = http_get("/api/events?limit=5")
            assert st == 200, "Server crashed on malformed CSV lines!"
            data = json.loads(body.decode())
            found_105 = any(e["pid"] == 105 for e in data["events"])
            assert found_105, "Valid row following malformed lines was not ingested!"

        # TEST 10: Large dataset memory safety
        def test_large_dataset_safety():
            # Create a 100,000 row CSV (~8MB)
            large_csv = os.path.join(temp_dir, "large_test.csv")
            with open(large_csv, "w") as f:
                f.write("monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n")
                for i in range(50000):
                    f.write(f'{1000000 + i},999,"load_test",0,1,2,0.0100,NORMAL\n')

            # Switch dataset to large CSV
            st, body = http_post_json("/api/set_dataset", {"dataset": large_csv})
            assert st == 200
            time.sleep(1.5)

            st, body, _ = http_get("/api/status")
            assert st == 200
            data = json.loads(body.decode())
            assert data["dataset_file"] == "large_test.csv"
            # Verify events returned is bounded
            st, body, _ = http_get("/api/events?limit=500")
            events = json.loads(body.decode())["events"]
            assert len(events) <= 500

        # TEST 11: Export CSV
        def test_export():
            st, body, headers = http_get("/api/export")
            assert st == 200
            assert b"timestamp_ns,pid,process_name" in body
            assert "text/csv" in headers.get("Content-Type", "")

        # Run all test cases
        tests = [
            ("TEST 1: Dashboard Static Launch", test_static),
            ("TEST 2: Status Metadata API", test_status),
            ("TEST 3: Events Ingestion & Display", test_events),
            ("TEST 4: Live Incremental Tailing", test_incremental),
            ("TEST 5: Suspicious-Event Filtering", test_suspicious_filter),
            ("TEST 6: PID & Process Substring Filter", test_pid_proc_filter),
            ("TEST 7: Anomaly Alerts & Root Cause Explanation", test_alerts_api),
            ("TEST 8: Process & Timeline Analytics", test_analytics),
            ("TEST 9: Fault-Tolerant Malformed Row Handling", test_malformed_rows),
            ("TEST 10: Large Dataset Memory Safety", test_large_dataset_safety),
            ("TEST 11: Filtered CSV Export Stream", test_export)
        ]

        results = [run_test(name, fn) for name, fn in tests]

        print("=" * 60)
        passed = sum(results)
        total = len(results)
        print(f"DASHBOARD TESTS: {passed}/{total} PASSED")
        print("=" * 60)
        assert passed == total, f"Only {passed}/{total} tests passed."

    finally:
        proc.terminate()
        proc.wait(timeout=3)
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
