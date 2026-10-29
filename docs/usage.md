# System Usage & Operation Guide

**Process Anomaly Detection Using System Calls with eBPF**

---

## 1. Quick Start (One Command)

The primary entry point is `./run.sh`, which manages prerequisite verification, dashboard startup, privilege handling, process supervision, and signal traps cleanly:

```bash
./run.sh
```

- Prompts for `sudo` only for the eBPF kernel detector.
- Launches the web dashboard under the unprivileged calling user account.
- Opens HTTP service on `http://127.0.0.1:5000/`.
- Press `Ctrl+C` to terminate both services cleanly.

---

## 2. Command-Line Options

The launcher accepts standard GNU-style flags:

| Flag | Description | Default |
|---|---|---|
| `-h`, `--help` | Show command usage and options | -- |
| `-c`, `--check` | Verify system prerequisites without starting services | -- |
| `-d`, `--dashboard-only` | Launch web dashboard only (unprivileged, no root) | False |
| `--demo` | Launch dashboard with simulated live event generator | False |
| `-p`, `--port <num>` | Dashboard HTTP listening port | `5000` |
| `--host <ip>` | Dashboard listen interface IP | `127.0.0.1` |
| `-o`, `--output <path>` | Append-only CSV dataset output file | `syscall_dataset.csv` |
| `-m`, `--model <path>` | Trained baseline model binary | `baseline_model.dat` |
| `--detector <path>` | eBPF detector binary executable | `ebpf/syscall-detector-live` |
| `--db <path>` | SQLite persistent alerts database | `data/alerts.db` |
| `-q`, `--quiet` | Suppress non-alert stdout lines from detector | False |

---

## 3. Operational Modes

### Mode A: Full Live eBPF Monitoring (Default)
Attaches eBPF program to kernel tracepoints and monitors all host processes in real time:
```bash
./run.sh
```

### Mode B: Historical Review / Dashboard-Only
Launches only the web dashboard to inspect historical alerts, search by PID, review notes, or export CSVs:
```bash
./run.sh --dashboard-only
```

### Mode C: Live Examiner Demonstration (No Root Required)
Streams simulated benign and security-deviant system call sequences into the dashboard in real time:
```bash
./run.sh --demo
```

### Mode D: Custom Port and Dataset
Useful when testing multiple configurations or running parallel evaluation sets:
```bash
./run.sh --port 8080 --output data/evaluation_run1.csv --db data/eval1.db
```

---

## 4. Web Dashboard Walkthrough

Open your web browser to `http://127.0.0.1:5000/`.

### 4.1 Real-Time Monitoring View
- **Status Bar**: Shows detector status (Active/Disabled), total events ingested, anomaly count, and current anomaly percentage.
- **Throughput & Anomaly Dynamic Charts**: Real-time canvas charts plotting event volume per second and anomaly distribution over time.
- **Live Anomaly Feed**: Streaming table of events. Rows tagged `NORMAL` appear in dark slate; rows exceeding the 0.80 anomaly threshold appear highlighted with severity badges.

### 4.2 Security Triage Summary
- Displays counts of `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` alerts.
- Highlights **Unresolved High-Priority** alerts (`CRITICAL` or `HIGH` in `NEW` or `INVESTIGATING` status).
- Lists top flagged processes requiring analyst attention.

### 4.3 Process-Wise Monitoring (`Processes` Tab)
- Search processes by name (e.g. `curl`, `bash`, `nginx`).
- Filter by exact PID.
- Inspect metrics: Total 3-Grams, Normal count, Suspicious count, Anomaly %, and Last Observed time.
- **Host Process State**: Distinguishes `ACTIVE` processes (currently executing on the host) from `TERMINATED` historical records via `/proc` cross-verification.
- Click any process to open its **Process Details View**:
  - Top 3-gram sequences with individual occurrence counts.
  - Activity timeline distribution.
  - Recent sequence buffer.
  - One-click navigation to all historical alerts associated with that process.

### 4.4 Alert History & Incident Management (`Alert History` Tab)
- Full server-side pagination with sorting by timestamp, anomaly score, or severity precedence.
- Multi-criteria filtering: Process name substring, PID, Incident status, Severity level, and Min/Max score.
- **Incident Status Modification**: Click status badge to transition:
  `NEW` -> `INVESTIGATING` -> `RESOLVED` -> `FALSE_ALARM`.
- **Investigation Notes**: Type in-place notes directly in the row and click **Save**. Notes persist in SQLite across dashboard restarts.
- **Export Filtered CSV**: Click **Export CSV** to download a forensic record matching active filters.
