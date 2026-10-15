# Stage 7: Live Verification and Clean Baseline Dataset Report

## Executive Summary

Stage 7 of the Process Anomaly Detection project focuses on verifying the live eBPF detector implementation, providing exact instructions for collecting a clean benign baseline dataset (`baseline_syscalls.csv`), validating dataset integrity via a new automated dataset validator (`tools/validate_dataset.py`), and preparing an offline model trainer (`tools/train_from_csv.c`) for controlled evaluation.

All model structures, $N=3$ sliding windowing, scoring formulas ($1.0$ vs $1.0 / (1.0 + \text{count})$), thresholds ($0.80$ live, $0.25$ ADFA-LD), and existing datasets/models were strictly preserved.

---

## 1. Implementation Verification Summary

| Component / Feature | Implementation Verification | Status |
| :--- | :--- | :--- |
| **Detector & Launcher PID Display** | Displays `Detector PID: <PID> \| Launcher PID: <PPID>` at startup | **VERIFIED** |
| **Parent PID Exclusion** | Excludes both `own_pid` AND `parent_pid` (`parent_pid > 1`) | **VERIFIED** |
| **Targeted Filtering** | Does **NOT** filter unrelated processes named `sudo` under different PIDs | **VERIFIED** |
| **Custom Output Path (`-o`)** | `-o <path>` / `--output <path>` sets custom output CSV path cleanly | **VERIFIED** |
| **Startup Output Logging** | Prints `Dataset logging enabled: <path>` at startup | **VERIFIED** |
| **CSV Header Invariance** | Writes 8-column header on file creation; avoids duplicate headers on append | **VERIFIED** |
| **Clean Shutdown Flush** | Flushes buffered records to disk on `SIGINT` / `SIGTERM` before exit | **VERIFIED** |
| **File Integrity** | Existing `syscall_dataset.csv` (244 MB) and `normal_model.dat` preserved | **VERIFIED** |

---

## 2. Live Verification Instructions & Execution Steps

### Required Linux Privileges
Attaching the eBPF skeleton to kernel raw syscall tracepoints (`tracepoint/raw_syscalls/sys_enter`) requires elevated capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` / `root`).

### Exact Command for Live Baseline Collection
To launch the live detector with custom output `baseline_syscalls.csv`, execute:

```bash
sudo ./ebpf/syscall-detector-live -m normal_model.dat -o baseline_syscalls.csv
```

### Verification Steps During Live Execution
1. **Tracepoint Attachment**: Confirm console output displays:
   ```
   Real-Time Process Anomaly Detection Started
   ===========================================
   Detector PID: 54321 | Launcher PID: 54320
   Normal model loaded successfully
   Dataset logging enabled: baseline_syscalls.csv
   Monitoring real Linux syscalls... (Press Ctrl+C to stop)
   ```
2. **Event Arrival**: Observe live console logs (or quiet mode output) indicating 3-gram sequences being received and scored.
3. **Self & Launcher Exclusion**: Verify PID `54321` (detector) and PID `54320` (`sudo` launcher) do NOT produce events in `baseline_syscalls.csv`.
4. **Unrelated Process Monitoring**: Run benign processes in separate terminals (e.g. `ls`, `gcc`, `cat`, `curl`, `python3`) and confirm their PIDs appear in `baseline_syscalls.csv`.
5. **CSV Row Logging**: Check `baseline_syscalls.csv` to confirm records are actively populated.

---

## 3. Benign Workload Baseline Collection Plan

To collect a clean normal baseline without artificial or suspicious noise, execute ordinary developer tasks during the collection window:
1. **Terminal Operations**: Directory navigation (`cd`, `ls`), viewing logs (`cat`, `less`), file manipulation (`cp`, `mv`).
2. **File Editing & Development**: Opening text files in `nano` / `vim` / IDE, editing C source code.
3. **Compilation & Build**: Compiling programs (`gcc -Wall -O2 src/main.c -o main`), running `make`.
4. **Tool Execution**: Executing python scripts, running git commands (`git status`, `git diff`).
5. **Browser / Network Activity**: Fetching web pages via `curl` / `wget` or standard browser operations.

---

## 4. Dataset Validation Utility (`tools/validate_dataset.py`)

A new automated dataset validator (`tools/validate_dataset.py`) was created to inspect CSV datasets prior to model training.

### Validation Checks Performed
- **Header Structure**: Validates 8 columns (`monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label`).
- **Data Types & Ranges**: PID $\ge 0$, Syscall IDs $\ge 0$, Anomaly Score $\in [0.0, 1.0]$.
- **Label Consistency**: Validates `predicted_label` is either `NORMAL` or `SUSPICIOUS`.
- **Structural Integrity**: Detects duplicate headers, incomplete trailing rows, and malformed fields.
- **Statistics**: Reports total rows, unique PIDs, unique process names, and label distribution.

### Verification Run on Existing Dataset (`syscall_dataset.csv`)
```bash
python3 tools/validate_dataset.py syscall_dataset.csv
```
**Results**:
- File Size: 243.70 MB (4,742,250 lines)
- Valid Records: 4,742,249
- Unique PIDs: 303 | Unique Processes: 82
- Duplicate Headers: 0 | Incomplete Rows: 0 | Malformed Rows: 0 | Invalid PIDs: 0 | Score Out-of-Bounds: 0
- Status: **CLEAN & VALIDATED**

---

## 5. Model Training & Controlled Evaluation Plan

### Offline CSV Model Trainer (`tools/train_from_csv.c`)
Created `tools/train_from_csv.c` to train a binary `NormalModel` from clean baseline CSV files without needing live BPF kernel attachment:
```bash
./tools/train_from_csv baseline_syscalls.csv baseline_model.dat
```

### Controlled Evaluation Plan
1. **Baseline Normal Split**: 70% of clean benign baseline data used for training (`baseline_model.dat`), 30% reserved for validation.
2. **Controlled Anomalous Workload**: Test workload containing synthetic unseen syscall sequences or distinct test processes (`eval_anomalous_syscalls.csv`).
3. **Evaluation Metrics**:
   - **False Positive Rate (FPR)**: Percentage of benign validation 3-grams flagged as suspicious.
   - **Attack Recall**: Percentage of anomalous 3-grams correctly flagged as suspicious.
   - **Precision & F1-Score**: Overall detection harmonic balance.
   - **Detection Latency**: Measure average per-event scoring delay ($\le 10\ \mu\text{s}$).

---

## 6. Build and Test Suite Results

```bash
make clean && make && make benchmarks
./tools/test_model_serialization
./tools/test_trainer_detector_compat
./tools/test_explanation
./tools/test_explanation_integration
./tools/test_pid_filtering_and_logging
python3 tools/validate_dataset.py syscall_dataset.csv
```

All 12 targets built cleanly. All unit tests and dataset validation checks **PASSED**.

---

## 7. Status & Readiness

- **Live Kernel Verification**: Pending interactive execution of `sudo ./ebpf/syscall-detector-live -m normal_model.dat -o baseline_syscalls.csv`.
- **Dataset Readiness**: `tools/validate_dataset.py` and `tools/train_from_csv.c` are ready for execution upon completion of baseline collection.
- **Next Stage**: Stage 8 — Baseline Model Training & Controlled Anomaly Evaluation.
