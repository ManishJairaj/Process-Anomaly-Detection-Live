#!/usr/bin/env python3
"""
server.py — Real-Time Syscall Anomaly Detection Dashboard Server (Stage 19, 20 & 21)

Features:
- Incremental CSV tailing without loading entire large datasets into memory
- Safe buffer management with bounded in-memory deques
- Syscall sequence explanation generator (mirrors src/explanation.c)
- REST API for live stats, events, alerts, time-series, and CSV export
- Persistent SQLite Alert History & Incident Management (Stage 20)
- Process-wise Behavioral Analysis & Inspection APIs (Stage 21)
- Works using standard library http.server (zero external dependencies required)
- Safe detector monitoring (checks detector process status, displays launch commands)
- Bound to localhost (127.0.0.1:5000) by default
"""

import os
import sys
import time
import json
import re
import glob
import subprocess
import threading
from collections import deque, Counter
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import SQLite Alert Database manager
try:
    from dashboard.database import AlertDatabase, VALID_STATUSES, VALID_SEVERITIES, is_process_running_on_host
    from dashboard.severity import classify_severity, resolve_syscall_name, RULE_ENGINE_VERSION
except ImportError:
    from database import AlertDatabase, VALID_STATUSES, VALID_SEVERITIES, is_process_running_on_host
    from severity import classify_severity, resolve_syscall_name, RULE_ENGINE_VERSION

# Configuration defaults
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
MAX_EVENT_HISTORY = 2000
MAX_ALERT_HISTORY = 500
ANOMALY_THRESHOLD = 0.80

# Determine project directory
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
DEFAULT_DB_PATH = os.path.join(PROJECT_DIR, "data", "alerts.db")

# Global instances
MONITOR = None
DB = None

def get_syscall_name(sc_id):
    return resolve_syscall_name(sc_id)

class DatasetMonitor:
    """Incrementally monitors and parses CSV output from the syscall detector."""
    def __init__(self, csv_path, db=None, auto_start=True):
        self.csv_path = csv_path
        self.db = db
        self.lock = threading.Lock()
        self.last_pos = 0
        self.last_inode = None
        self.events = deque(maxlen=MAX_EVENT_HISTORY)
        self.alerts = deque(maxlen=MAX_ALERT_HISTORY)
        self.event_counter = 0
        self.total_processed = 0
        self.normal_count = 0
        self.suspicious_count = 0
        self.process_alerts = Counter()
        self.unique_pids = set()
        self.unique_processes = set()
        self.timeline_buckets = deque(maxlen=60) # Last 60 time windows (e.g. 5s each)
        self.col_indices = {}
        self.running = True
        self.thread = threading.Thread(target=self._tail_loop, daemon=True)
        if auto_start:
            self.thread.start()

    def set_dataset(self, new_path):
        with self.lock:
            self.csv_path = new_path
            self.last_pos = 0
            self.last_inode = None
            self.events.clear()
            self.alerts.clear()
            self.event_counter = 0
            self.total_processed = 0
            self.normal_count = 0
            self.suspicious_count = 0
            self.process_alerts.clear()
            self.unique_pids.clear()
            self.unique_processes.clear()
            self.timeline_buckets.clear()
            self.col_indices.clear()

    def _parse_header(self, header_line):
        cols = [c.strip().strip('"') for c in header_line.split(',')]
        self.col_indices = {c: i for i, c in enumerate(cols)}

    def _tail_loop(self):
        while self.running:
            try:
                self._read_incremental()
            except Exception:
                pass
            time.sleep(0.5)

    def _read_incremental(self):
        if not os.path.exists(self.csv_path):
            return

        st = os.stat(self.csv_path)
        cur_inode = (st.st_dev, st.st_ino)
        file_sig = f"{st.st_dev}_{st.st_ino}_{int(getattr(st, 'st_ctime', 0))}"

        # Handle file recreation / rotation / truncation
        if self.last_inode != cur_inode or st.st_size < self.last_pos:
            self.last_pos = 0
            self.last_inode = cur_inode

        # If file is brand new, read from near end if massive (> 10MB) to preserve memory
        if self.last_pos == 0 and st.st_size > 10 * 1024 * 1024:
            # Seek to last ~500 KB to bootstrap initial dashboard state
            with open(self.csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                header = f.readline()
                self._parse_header(header)
                f.seek(max(0, st.st_size - 512 * 1024))
                f.readline() # Discard partial line
                self.last_pos = f.tell()

        with open(self.csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            if self.last_pos == 0:
                header = f.readline()
                self._parse_header(header)
                self.last_pos = f.tell()
            else:
                f.seek(self.last_pos)

            new_events = []
            alert_batch = []
            proc_batch = {}
            recent_events_batch = []

            while True:
                line_start_pos = f.tell()
                line = f.readline()
                if not line:
                    break
                if not line.endswith('\n') and f.tell() == st.st_size:
                    # Incomplete line write from eBPF logger, wait for next tick
                    f.seek(line_start_pos)
                    break

                self.last_pos = f.tell()
                line = line.strip()
                if not line or line.startswith('monotonic_timestamp_ns'):
                    continue

                parsed = self._parse_line(line)
                if parsed:
                    new_events.append(parsed)
                    pid_val = parsed["pid"]
                    proc_val = parsed["process_name"]
                    ts_val = parsed["timestamp_ns"]
                    score_val = parsed["anomaly_score"]
                    is_susp = parsed["is_suspicious"]
                    s1, s2, s3 = parsed["syscalls"]

                    # Process-wise batch aggregation (Stage 21)
                    pkey = (pid_val, proc_val)
                    if pkey not in proc_batch:
                        proc_batch[pkey] = {
                            "pid": pid_val,
                            "process_name": proc_val,
                            "total_events": 0,
                            "normal_events": 0,
                            "suspicious_events": 0,
                            "max_score": score_val,
                            "first_timestamp": ts_val,
                            "last_timestamp": ts_val,
                            "ngrams": Counter(),
                            "timeline": Counter()
                        }
                    pdata = proc_batch[pkey]
                    pdata["total_events"] += 1
                    if is_susp:
                        pdata["suspicious_events"] += 1
                    else:
                        pdata["normal_events"] += 1
                    pdata["first_timestamp"] = min(pdata["first_timestamp"], ts_val)
                    pdata["last_timestamp"] = max(pdata["last_timestamp"], ts_val)
                    pdata["max_score"] = max(pdata["max_score"], score_val)
                    pdata["ngrams"][(s1, s2, s3, 1 if is_susp else 0)] += 1

                    # Group into time bucket (5-second window: 5_000_000_000 ns)
                    time_bucket = ts_val // 5_000_000_000
                    pdata["timeline"][(time_bucket, "suspicious" if is_susp else "normal")] += 1

                    recent_events_batch.append({
                        "pid": pid_val,
                        "process_name": proc_val,
                        "event_timestamp": ts_val,
                        "syscall_1": s1, "syscall_2": s2, "syscall_3": s3,
                        "anomaly_score": score_val,
                        "is_suspicious": 1 if is_susp else 0
                    })

                    if is_susp:
                        alert_batch.append({
                            "event_timestamp": ts_val,
                            "pid": pid_val,
                            "process_name": proc_val,
                            "syscall_1": s1,
                            "syscall_2": s2,
                            "syscall_3": s3,
                            "anomaly_score": score_val,
                            "explanation": parsed["explanation"],
                            "source_dataset": os.path.basename(self.csv_path),
                            "record_offset": line_start_pos,
                            "file_signature": file_sig,
                            "severity": parsed.get("severity"),
                            "severity_rule": parsed.get("severity_rule"),
                            "severity_reason": parsed.get("severity_reason"),
                            "severity_rule_version": parsed.get("severity_rule_version")
                        })

            if new_events:
                with self.lock:
                    for ev in new_events:
                        self._record_event(ev)

            # Persist alerts, checkpoints, and process aggregates in SQLite
            if self.db:
                checkpoint = {
                    "source_dataset": os.path.basename(self.csv_path),
                    "file_signature": file_sig,
                    "last_byte_offset": self.last_pos,
                    "last_line_number": self.total_processed,
                    "last_event_timestamp": alert_batch[-1]["event_timestamp"] if alert_batch else (new_events[-1]["timestamp_ns"] if new_events else 0)
                }
                if alert_batch or new_events:
                    self.db.ingest_batch(alert_batch, checkpoint)
                if proc_batch:
                    self.db.ingest_process_batch(proc_batch, recent_events_batch, os.path.basename(self.csv_path))

    def _parse_line(self, line):
        # CSV parsing with quoted strings handling
        parts = []
        in_quotes = False
        cur = []
        for ch in line:
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == ',' and not in_quotes:
                parts.append(''.join(cur).strip().strip('"'))
                cur = []
            else:
                cur.append(ch)
        parts.append(''.join(cur).strip().strip('"'))

        if len(parts) < 8:
            return None

        try:
            ts = int(parts[0])
            pid = int(parts[1])
            proc_name = parts[2] if parts[2] else "unknown"
            s1 = int(parts[3])
            s2 = int(parts[4])
            s3 = int(parts[5])
            score = float(parts[6])
            label = parts[7].upper()
            is_suspicious = (label == "SUSPICIOUS" or score >= ANOMALY_THRESHOLD)

            s1_name = get_syscall_name(s1)
            s2_name = get_syscall_name(s2)
            s3_name = get_syscall_name(s3)
            seq_display = f"{s1_name} ({s1}) -> {s2_name} ({s2}) -> {s3_name} ({s3})"

            explanation = None
            severity = None
            severity_rule = None
            severity_reason = None
            severity_rule_version = None
            if is_suspicious:
                if score >= 1.0:
                    explanation = f"Unseen 3-Gram: Sequence [{s1_name} -> {s2_name} -> {s3_name}] was never observed during normal baseline training (score 1.0000 >= threshold {ANOMALY_THRESHOLD:.2f})."
                else:
                    explanation = f"Statistically Deviant: Sequence [{s1_name} -> {s2_name} -> {s3_name}] occurred with anomalous frequency (score {score:.4f} >= threshold {ANOMALY_THRESHOLD:.2f})."

                c = classify_severity(s1, s2, s3, score, proc_name)
                severity = c.severity
                severity_rule = c.rule_id
                severity_reason = c.reason
                severity_rule_version = c.rule_version

            self.event_counter += 1
            return {
                "id": self.event_counter,
                "timestamp_ns": ts,
                "timestamp_fmt": time.strftime('%H:%M:%S', time.localtime()),
                "pid": pid,
                "process_name": proc_name,
                "syscalls": [s1, s2, s3],
                "sequence_str": seq_display,
                "anomaly_score": round(score, 4),
                "is_suspicious": is_suspicious,
                "status": "SUSPICIOUS" if is_suspicious else "NORMAL",
                "explanation": explanation,
                "severity": severity,
                "severity_rule": severity_rule,
                "severity_reason": severity_reason,
                "severity_rule_version": severity_rule_version
            }
        except (ValueError, IndexError):
            return None

    def _record_event(self, ev):
        self.events.append(ev)
        self.total_processed += 1
        self.unique_pids.add(ev["pid"])
        self.unique_processes.add(ev["process_name"])

        if ev["is_suspicious"]:
            self.suspicious_count += 1
            self.alerts.append(ev)
            self.process_alerts[ev["process_name"]] += 1
        else:
            self.normal_count += 1

        # Bucket by current epoch second for timeline chart
        now_sec = int(time.time())
        if not self.timeline_buckets or self.timeline_buckets[-1]["time"] != now_sec:
            self.timeline_buckets.append({"time": now_sec, "normal": 0, "suspicious": 0})
        if ev["is_suspicious"]:
            self.timeline_buckets[-1]["suspicious"] += 1
        else:
            self.timeline_buckets[-1]["normal"] += 1

    def get_status(self):
        with self.lock:
            detector_pid = get_detector_pid()
            st_size = os.path.getsize(self.csv_path) if os.path.exists(self.csv_path) else 0
            anomaly_pct = (self.suspicious_count / self.total_processed * 100.0) if self.total_processed > 0 else 0.0

            return {
                "detector_running": (detector_pid is not None),
                "detector_pid": detector_pid,
                "dataset_file": os.path.basename(self.csv_path),
                "dataset_path": self.csv_path,
                "dataset_size_bytes": st_size,
                "total_processed": self.total_processed,
                "normal_count": self.normal_count,
                "suspicious_count": self.suspicious_count,
                "anomaly_percentage": round(anomaly_pct, 2),
                "unique_processes_count": len(self.unique_processes),
                "unique_pids_count": len(self.unique_pids),
                "active_processes": sorted(list(self.unique_processes))[:20],
                "threshold": ANOMALY_THRESHOLD
            }

    def get_events(self, since_id=0, limit=100, suspicious_only=False, pid=None, process=None):
        with self.lock:
            res = []
            for ev in reversed(self.events):
                if ev["id"] <= since_id:
                    continue
                if suspicious_only and not ev["is_suspicious"]:
                    continue
                if pid is not None and ev["pid"] != pid:
                    continue
                if process and process.lower() not in ev["process_name"].lower():
                    continue
                res.append(ev)
                if len(res) >= limit:
                    break
            return res

    def get_alerts(self, limit=50):
        with self.lock:
            return list(reversed(self.alerts))[:limit]

    def get_top_processes(self, limit=10):
        with self.lock:
            top = self.process_alerts.most_common(limit)
            return [{"process": p, "count": c} for p, c in top]

    def get_timeline(self):
        with self.lock:
            return list(self.timeline_buckets)

def get_detector_pid():
    """Detect if syscall-detector-live is active."""
    try:
        out = subprocess.check_output(['pgrep', '-f', 'syscall-detector-live'], stderr=subprocess.DEVNULL)
        pids = [int(p) for p in out.decode().strip().split() if p.isdigit() and int(p) != os.getpid()]
        for p in pids:
            try:
                with open(f"/proc/{p}/cmdline", "rb") as f:
                    cmd = f.read().decode('utf-8', errors='ignore')
                    if "syscall-detector-live" in cmd and "server.py" not in cmd and "python" not in cmd:
                        return p
            except Exception:
                continue
        return None
    except Exception:
        return None

class DashboardHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence standard HTTP access logs to keep terminal output clean
        pass

    def send_json(self, data, status=200):
        payload = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        elif path == "/dashboard.css" or path == "/static/dashboard.css":
            self.serve_file(os.path.join(STATIC_DIR, "dashboard.css"), "text/css")
        elif path == "/dashboard.js" or path == "/static/dashboard.js":
            self.serve_file(os.path.join(STATIC_DIR, "dashboard.js"), "application/javascript")
        elif path == "/api/status":
            self.send_json(MONITOR.get_status())
        elif path == "/api/events":
            since_id = int(query.get("since", [0])[0])
            limit = min(500, int(query.get("limit", [100])[0]))
            susp_only = query.get("suspicious_only", ["0"])[0] in ("1", "true", "True")
            pid_val = int(query.get("pid")[0]) if "pid" in query and query["pid"][0].isdigit() else None
            proc_val = query.get("process", [None])[0]
            events = MONITOR.get_events(since_id, limit, susp_only, pid_val, proc_val)
            self.send_json({"events": events, "count": len(events)})
        elif path == "/api/alerts":
            limit = min(200, int(query.get("limit", [50])[0]))
            alerts = MONITOR.get_alerts(limit)
            self.send_json({"alerts": alerts, "count": len(alerts)})
        elif path == "/api/stats/processes":
            top = MONITOR.get_top_processes(10)
            self.send_json({"processes": top})
        elif path == "/api/stats/timeline":
            timeline = MONITOR.get_timeline()
            self.send_json({"timeline": timeline})
        elif path == "/api/export":
            self.export_csv(query)

        # STAGE 20: Alert History & Incident Management Endpoints
        elif path == "/api/alert_history":
            self.handle_get_alert_history(query)
        elif path == "/api/alert_history/detail" or (path.startswith("/api/alert_history/") and path.split("/")[-1].isdigit()):
            self.handle_get_alert_detail(path, query)
        elif path == "/api/alert_history/stats":
            self.send_json(DB.get_stats())
        elif path == "/api/triage/stats":
            self.send_json(DB.get_triage_stats())
        elif path == "/api/alert_history/export":
            self.handle_export_alert_history(query)

        # STAGE 21: Process-Wise Monitoring & Behavioral Analytics Endpoints
        elif path == "/api/processes":
            self.handle_get_processes(query)
        elif path == "/api/processes/detail":
            self.handle_get_process_detail(query)
        elif path == "/api/processes/events":
            self.handle_get_process_events(query)
        elif path == "/api/processes/alerts":
            self.handle_get_process_alerts(query)
        elif path == "/api/processes/timeline":
            self.handle_get_process_timeline(query)
        elif path == "/api/processes/top_ngrams":
            self.handle_get_process_top_ngrams(query)

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/set_dataset":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
                dataset = data.get("dataset")
                if dataset and os.path.exists(dataset):
                    MONITOR.set_dataset(dataset)
                    self.send_json({"status": "ok", "message": f"Switched to {dataset}"})
                else:
                    self.send_json({"status": "error", "message": "Dataset file not found"}, 400)
            except Exception as e:
                self.send_json({"status": "error", "message": str(e)}, 500)

        # STAGE 20: Incident status and notes updates
        elif path == "/api/alert_history/update_status":
            self.handle_post_update_status()
        elif path == "/api/alert_history/update_notes":
            self.handle_post_update_notes()

        else:
            self.send_response(404)
            self.end_headers()

    # ==========================================================================
    # STAGE 20 HANDLERS
    # ==========================================================================

    def handle_get_alert_history(self, query):
        """Retrieve paginated and filtered alerts from SQLite."""
        try:
            page_str = query.get("page", ["1"])[0]
            page = int(page_str) if page_str.isdigit() else 1
            limit_str = query.get("limit", ["25"])[0]
            limit = min(200, int(limit_str)) if limit_str.isdigit() else 25

            proc = query.get("process", [None])[0] or query.get("search", [None])[0]
            pid_raw = query.get("pid", [None])[0]
            pid_val = int(pid_raw) if pid_raw and pid_raw.isdigit() else None
            status_val = query.get("status", [None])[0]
            sev_val = query.get("severity", [None])[0]
            min_score_raw = query.get("min_score", [None])[0]
            min_score = float(min_score_raw) if min_score_raw else None
            max_score_raw = query.get("max_score", [None])[0]
            max_score = float(max_score_raw) if max_score_raw else None
            start_time = query.get("start_time", [None])[0]
            end_time = query.get("end_time", [None])[0]
            sort_by = query.get("sort_by", [None])[0]
            order_val = query.get("order", ["desc"])[0]

            res = DB.get_alerts_paginated(
                page=page,
                limit=limit,
                process_name=proc,
                pid=pid_val,
                incident_status=status_val,
                severity=sev_val,
                min_score=min_score,
                max_score=max_score,
                start_time=start_time,
                end_time=end_time,
                sort_by=sort_by,
                order=order_val
            )

            for a in res["alerts"]:
                s1_n = get_syscall_name(a["syscall_1"])
                s2_n = get_syscall_name(a["syscall_2"])
                s3_n = get_syscall_name(a["syscall_3"])
                a["sequence_str"] = f"{s1_n} ({a['syscall_1']}) -> {s2_n} ({a['syscall_2']}) -> {s3_n} ({a['syscall_3']})"

            self.send_json(res)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_get_alert_detail(self, path, query):
        """Retrieve full details of an individual alert."""
        try:
            alert_id = None
            if path == "/api/alert_history/detail":
                alert_id_str = query.get("id", [None])[0]
                if alert_id_str and alert_id_str.isdigit():
                    alert_id = int(alert_id_str)
            else:
                parts = path.split("/")
                if len(parts) >= 4 and parts[-1].isdigit():
                    alert_id = int(parts[-1])

            if alert_id is None:
                self.send_json({"error": "Missing or invalid alert id"}, 400)
                return

            alert = DB.get_alert_by_id(alert_id)
            if alert:
                s1_n = get_syscall_name(alert["syscall_1"])
                s2_n = get_syscall_name(alert["syscall_2"])
                s3_n = get_syscall_name(alert["syscall_3"])
                alert["sequence_str"] = f"{s1_n} ({alert['syscall_1']}) -> {s2_n} ({alert['syscall_2']}) -> {s3_n} ({alert['syscall_3']})"
                self.send_json({"alert": alert})
            else:
                self.send_json({"error": "Alert not found"}, 404)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_post_update_status(self):
        """Update incident status (NEW, INVESTIGATING, RESOLVED, FALSE_ALARM)."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            alert_id = int(data.get("alert_id", 0))
            new_status = data.get("status")
            if not alert_id or not new_status:
                self.send_json({"error": "Missing alert_id or status"}, 400)
                return

            updated = DB.update_status(alert_id, new_status)
            if updated:
                s1_n = get_syscall_name(updated["syscall_1"])
                s2_n = get_syscall_name(updated["syscall_2"])
                s3_n = get_syscall_name(updated["syscall_3"])
                updated["sequence_str"] = f"{s1_n} ({updated['syscall_1']}) -> {s2_n} ({updated['syscall_2']}) -> {s3_n} ({updated['syscall_3']})"
                self.send_json({"status": "ok", "alert": updated})
            else:
                self.send_json({"error": "Alert not found"}, 404)
        except ValueError as ve:
            self.send_json({"error": str(ve)}, 400)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_post_update_notes(self):
        """Update investigation notes for an alert."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            alert_id = int(data.get("alert_id", 0))
            notes = data.get("notes", "")
            if not alert_id:
                self.send_json({"error": "Missing alert_id"}, 400)
                return

            updated = DB.update_notes(alert_id, notes)
            if updated:
                s1_n = get_syscall_name(updated["syscall_1"])
                s2_n = get_syscall_name(updated["syscall_2"])
                s3_n = get_syscall_name(updated["syscall_3"])
                updated["sequence_str"] = f"{s1_n} ({updated['syscall_1']}) -> {s2_n} ({updated['syscall_2']}) -> {s3_n} ({updated['syscall_3']})"
                self.send_json({"status": "ok", "alert": updated})
            else:
                self.send_json({"error": "Alert not found"}, 404)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_export_alert_history(self, query):
        """Export filtered alert history as CSV stream."""
        proc = query.get("process", [None])[0] or query.get("search", [None])[0]
        pid_raw = query.get("pid", [None])[0]
        pid_val = int(pid_raw) if pid_raw and pid_raw.isdigit() else None
        status_val = query.get("status", [None])[0]
        sev_val = query.get("severity", [None])[0]
        min_score_raw = query.get("min_score", [None])[0]
        min_score = float(min_score_raw) if min_score_raw else None
        sort_by = query.get("sort_by", [None])[0]
        order_val = query.get("order", ["desc"])[0]

        rows = DB.export_filtered_rows(
            process_name=proc,
            pid=pid_val,
            incident_status=status_val,
            severity=sev_val,
            min_score=min_score,
            sort_by=sort_by,
            order=order_val
        )

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="alert_history_export.csv"')
        self.end_headers()

        header = "alert_id,event_timestamp,pid,process_name,syscall_1,syscall_2,syscall_3,sequence,anomaly_score,severity,severity_rule,severity_reason,incident_status,investigation_notes,source_dataset,created_at,last_updated,explanation\n"
        self.wfile.write(header.encode('utf-8'))
        for r in rows:
            notes_clean = str(r.get("investigation_notes", "")).replace('"', '""')
            expl_clean = str(r.get("explanation", "")).replace('"', '""')
            proc_clean = str(r.get("process_name", "")).replace('"', '""')
            sev_clean = str(r.get("severity", "MEDIUM")).replace('"', '""')
            sev_rule_clean = str(r.get("severity_rule", "")).replace('"', '""')
            sev_reason_clean = str(r.get("severity_reason", "")).replace('"', '""')
            seq_clean = str(r.get("sequence_str", f"{r.get('syscall_1')} -> {r.get('syscall_2')} -> {r.get('syscall_3')}")).replace('"', '""')
            row_str = (
                f'{r["alert_id"]},{r["event_timestamp"]},{r["pid"]},"{proc_clean}",'
                f'{r["syscall_1"]},{r["syscall_2"]},{r["syscall_3"]},"{seq_clean}",{float(r["anomaly_score"]):.4f},'
                f'"{sev_clean}","{sev_rule_clean}","{sev_reason_clean}",'
                f'{r["incident_status"]},"{notes_clean}","{r["source_dataset"]}",'
                f'"{r["created_at"]}","{r["last_updated"]}","{expl_clean}"\n'
            )
            self.wfile.write(row_str.encode('utf-8'))

    # ==========================================================================
    # STAGE 21 HANDLERS: PROCESS-WISE ANALYTICS
    # ==========================================================================

    def handle_get_processes(self, query):
        """Retrieve paginated process summaries with monitoring status."""
        try:
            page_str = query.get("page", ["1"])[0]
            page = int(page_str) if page_str.isdigit() else 1
            limit_str = query.get("limit", ["25"])[0]
            limit = min(200, int(limit_str)) if limit_str.isdigit() else 25

            search = query.get("search", [None])[0] or query.get("process", [None])[0]
            pid_raw = query.get("pid", [None])[0]
            pid_val = int(pid_raw) if pid_raw and pid_raw.isdigit() else None
            sort_by = query.get("sort_by", ["total"])[0]
            order = query.get("order", ["desc"])[0]

            res = DB.get_processes_paginated(
                page=page,
                limit=limit,
                search=search,
                pid=pid_val,
                sort_by=sort_by,
                order=order
            )
            self.send_json(res)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_get_process_detail(self, query):
        """Retrieve individual process summary details."""
        try:
            pid_raw = query.get("pid", [None])[0]
            if not pid_raw or not pid_raw.isdigit():
                self.send_json({"error": "Missing or invalid PID"}, 400)
                return

            pid = int(pid_raw)
            process_name = query.get("process", [None])[0]
            detail = DB.get_process_detail(pid, process_name)
            if detail:
                self.send_json({"process": detail})
            else:
                self.send_json({"error": f"Process with PID {pid} not found"}, 404)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_get_process_events(self, query):
        """Retrieve recent syscall sequences for a process."""
        try:
            pid_raw = query.get("pid", [None])[0]
            if not pid_raw or not pid_raw.isdigit():
                self.send_json({"error": "Missing or invalid PID"}, 400)
                return

            pid = int(pid_raw)
            process_name = query.get("process", [None])[0]
            limit_str = query.get("limit", ["50"])[0]
            limit = min(200, int(limit_str)) if limit_str.isdigit() else 50
            susp_only = query.get("suspicious_only", ["0"])[0] in ("1", "true", "True")

            events = DB.get_process_recent_events(pid, process_name, limit, susp_only)
            self.send_json({"events": events, "count": len(events)})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_get_process_alerts(self, query):
        """Retrieve persistent anomaly alerts for a process."""
        try:
            pid_raw = query.get("pid", [None])[0]
            if not pid_raw or not pid_raw.isdigit():
                self.send_json({"error": "Missing or invalid PID"}, 400)
                return

            pid = int(pid_raw)
            process_name = query.get("process", [None])[0]
            limit_str = query.get("limit", ["50"])[0]
            limit = min(200, int(limit_str)) if limit_str.isdigit() else 50

            alerts = DB.get_process_alerts(pid, process_name, limit)
            self.send_json({"alerts": alerts, "count": len(alerts)})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_get_process_timeline(self, query):
        """Retrieve activity timeline buckets for a process."""
        try:
            pid_raw = query.get("pid", [None])[0]
            if not pid_raw or not pid_raw.isdigit():
                self.send_json({"error": "Missing or invalid PID"}, 400)
                return

            pid = int(pid_raw)
            process_name = query.get("process", [None])[0]

            timeline = DB.get_process_timeline(pid, process_name)
            self.send_json({"timeline": timeline})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def handle_get_process_top_ngrams(self, query):
        """Retrieve most frequent syscall 3-grams for a process."""
        try:
            pid_raw = query.get("pid", [None])[0]
            if not pid_raw or not pid_raw.isdigit():
                self.send_json({"error": "Missing or invalid PID"}, 400)
                return

            pid = int(pid_raw)
            process_name = query.get("process", [None])[0]
            limit_str = query.get("limit", ["10"])[0]
            limit = min(50, int(limit_str)) if limit_str.isdigit() else 10

            top_ngrams = DB.get_process_top_ngrams(pid, process_name, limit)
            self.send_json({"top_ngrams": top_ngrams, "count": len(top_ngrams)})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def serve_file(self, file_path, content_type):
        if not os.path.exists(file_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not found")
            return
        with open(file_path, 'rb') as f:
            content = f.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(content)

    def export_csv(self, query):
        susp_only = query.get("suspicious_only", ["0"])[0] in ("1", "true")
        events = MONITOR.get_events(limit=MAX_EVENT_HISTORY, suspicious_only=susp_only)
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv')
        self.send_header('Content-Disposition', 'attachment; filename="anomaly_events_export.csv"')
        self.end_headers()

        header = "timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,status,explanation\n"
        self.wfile.write(header.encode('utf-8'))
        for ev in events:
            expl = f'"{ev["explanation"]}"' if ev["explanation"] else '""'
            row = f'{ev["timestamp_ns"]},{ev["pid"]},"{ev["process_name"]}",{ev["syscalls"][0]},{ev["syscalls"][1]},{ev["syscalls"][2]},{ev["anomaly_score"]},{ev["status"]},{expl}\n'
            self.wfile.write(row.encode('utf-8'))

def find_initial_dataset():
    candidates = [
        os.path.join(PROJECT_DIR, "gt_eval_dataset.csv"),
        os.path.join(PROJECT_DIR, "syscall_dataset.csv"),
        os.path.join(PROJECT_DIR, "syscall_dataset_prev.csv")
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 0:
            return c
    return os.path.join(PROJECT_DIR, "syscall_dataset.csv")

def main():
    global MONITOR, DB
    import argparse
    parser = argparse.ArgumentParser(description="Real-Time Syscall Anomaly Monitoring Dashboard")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--dataset", default=None, help="Initial dataset CSV path to monitor")
    parser.add_argument("--db", default=None, help="Path to SQLite alerts database (default: data/alerts.db)")
    args = parser.parse_args()

    db_path = args.db if args.db else DEFAULT_DB_PATH
    dataset_path = args.dataset if args.dataset else find_initial_dataset()

    print("=" * 60)
    print(" eBPF Syscall Anomaly Detection — Live Monitoring Dashboard")
    print("=" * 60)
    print(f"Server Host  : http://{args.host}:{args.port}")
    print(f"Active Dataset: {dataset_path}")
    print(f"Alert Database: {db_path}")
    print(f"Safety Mode  : Unprivileged Local Server (No root/sudo required)")
    print(f"Static Assets: {STATIC_DIR}")
    print("=" * 60)

    DB = AlertDatabase(db_path)
    MONITOR = DatasetMonitor(dataset_path, db=DB)

    HTTPServer.allow_reuse_address = True
    server = HTTPServer((args.host, args.port), DashboardHTTPHandler)

    import signal
    def handle_term(signum, frame):
        MONITOR.running = False
        try:
            server.server_close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_term)

    try:
        print(f"[READY] Dashboard running at http://{args.host}:{args.port}/")
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n[SHUTDOWN] Stopping dashboard server...")
        MONITOR.running = False
        try:
            server.server_close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
