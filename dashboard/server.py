#!/usr/bin/env python3
"""
server.py — Real-Time Syscall Anomaly Detection Dashboard Server (Stage 19)

Features:
- Incremental CSV tailing without loading entire large datasets into memory
- Safe buffer management with bounded in-memory deques
- Syscall sequence explanation generator (mirrors src/explanation.c)
- REST API for live stats, events, alerts, time-series, and CSV export
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

# Configuration defaults
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
MAX_EVENT_HISTORY = 2000
MAX_ALERT_HISTORY = 500
ANOMALY_THRESHOLD = 0.80

# Determine project directory
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Build syscall ID to name dictionary
def build_syscall_map():
    mapping = {}
    try:
        out = subprocess.check_output(
            ['gcc', '-dM', '-E', '-include', 'sys/syscall.h', '-x', 'c', '/dev/null'],
            stderr=subprocess.DEVNULL
        ).decode('utf-8', errors='ignore')
        for line in out.splitlines():
            if line.startswith('#define SYS_') or line.startswith('#define __NR_'):
                parts = line.split()
                if len(parts) >= 3 and parts[2].isdigit():
                    name = parts[1].replace('SYS_', '').replace('__NR_', '')
                    mapping[int(parts[2])] = name
    except Exception:
        pass
    # Basic fallback definitions
    fallbacks = {
        0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
        9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
        14: "rt_sigprocmask", 21: "access", 56: "clone", 57: "fork", 59: "execve",
        60: "exit", 62: "kill", 63: "uname", 72: "fcntl", 83: "mkdir", 84: "rmdir",
        257: "openat", 262: "newfstatat"
    }
    for k, v in fallbacks.items():
        if k not in mapping:
            mapping[k] = v
    return mapping

SYSCALL_MAP = build_syscall_map()

def get_syscall_name(sc_id):
    return SYSCALL_MAP.get(sc_id, f"syscall_{sc_id}")

class DatasetMonitor:
    """Incrementally monitors and parses CSV output from the syscall detector."""
    def __init__(self, csv_path):
        self.csv_path = csv_path
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
            except Exception as e:
                pass
            time.sleep(0.5)

    def _read_incremental(self):
        if not os.path.exists(self.csv_path):
            return

        st = os.stat(self.csv_path)
        cur_inode = (st.st_dev, st.st_ino)

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
            while True:
                line = f.readline()
                if not line:
                    break
                if not line.endswith('\n') and f.tell() == st.st_size:
                    # Incomplete line write from eBPF logger, wait for next tick
                    f.seek(self.last_pos)
                    break

                self.last_pos = f.tell()
                line = line.strip()
                if not line or line.startswith('monotonic_timestamp_ns'):
                    continue

                parsed = self._parse_line(line)
                if parsed:
                    new_events.append(parsed)

            if new_events:
                with self.lock:
                    for ev in new_events:
                        self._record_event(ev)

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
            if is_suspicious:
                if score >= 1.0:
                    explanation = f"Unseen 3-Gram: Sequence [{s1_name} -> {s2_name} -> {s3_name}] was never observed during normal baseline training (score 1.0000 >= threshold {ANOMALY_THRESHOLD:.2f})."
                else:
                    explanation = f"Statistically Deviant: Sequence [{s1_name} -> {s2_name} -> {s3_name}] occurred with anomalous frequency (score {score:.4f} >= threshold {ANOMALY_THRESHOLD:.2f})."

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
                "explanation": explanation
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

# Global monitor instance
MONITOR = None

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
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/set_dataset":
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
        else:
            self.send_response(404)
            self.end_headers()

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
    global MONITOR
    import argparse
    parser = argparse.ArgumentParser(description="Real-Time Syscall Anomaly Monitoring Dashboard")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--dataset", default=None, help="Initial dataset CSV path to monitor")
    args = parser.parse_args()

    dataset_path = args.dataset if args.dataset else find_initial_dataset()
    print("=" * 60)
    print(" eBPF Syscall Anomaly Detection — Live Monitoring Dashboard")
    print("=" * 60)
    print(f"Server Host  : http://{args.host}:{args.port}")
    print(f"Active Dataset: {dataset_path}")
    print(f"Safety Mode  : Unprivileged Local Server (No root/sudo required)")
    print(f"Static Assets: {STATIC_DIR}")
    print("=" * 60)

    MONITOR = DatasetMonitor(dataset_path)

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
