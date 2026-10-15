# Stage 6 & 6B: Live eBPF Integration and Real Kernel Tracepoint Validation Report

## Executive Summary

Validation for Stage 6 and Stage 6B of the Process Anomaly Detection project was conducted to verify end-to-end kernel event collection, per-PID n-gram windowing, anomaly scoring, explanation formatting, resource safety, legacy model compatibility, dataset file workflow integrity, and benchmark regression invariance.

All existing configurations ($N=3$, `ANOMALY_THRESHOLD = 0.80`, seen sequence score $= 1/(1+\text{count})$, unseen sequence score $= 1.0$, frozen offline threshold $= 0.25$) and model serialization invariants were strictly preserved.

---

## 1. Inspection & Legacy-Model Compatibility Verification

### Legacy Format Structure Analysis
- Struct definition in `include/model.h`:
  - `ModelEntry`: `NGram` (12 bytes) + 4 padding bytes + `count` (`unsigned long`, 8 bytes) + `probability` (`double`, 8 bytes) = 32 bytes.
  - `NormalModel` (legacy 10,000 capacity): `entries[10000]` ($10,000 \times 32 = 320,000$ bytes) + `size` (`size_t`, 8 bytes) + `total_ngrams` (`unsigned long`, 8 bytes) = 320,016 bytes.
- **Offset Verification**:
  - `entries` array: bytes `0` to `319,999`
  - `size` metadata: bytes `320,000` to `320,007`
  - `total_ngrams` metadata: bytes `320,008` to `320,015`
- **Fix Verification in `src/model.c`**:
  Added `fseek(file, 10000 * sizeof(ModelEntry), SEEK_SET)` (offset 320,000) prior to reading `legacy_size` and `legacy_total`, and `fseek(file, 0, SEEK_SET)` prior to reading `entries`.
- **Test Result**: Successfully loaded both `normal_model.dat` and `normal_model_stage8_backup.dat` (320,016 bytes each), confirming `size = 5056` unique 3-grams and `total_ngrams = 1072141`. Verified via `./tools/test_model_serialization`.

---

## 2. Dataset Filename Dependency Audit

A repository-wide audit for `syscall_dataset.csv` references identified usages in:
1. `ebpf/syscall_collector.c`: Dataset logger during live eBPF collection.
2. `src/main.c`: Dataset logger during simulated event testing.
3. `tools/model_coverage.c`: Reads `syscall_dataset.csv` for n-gram coverage analysis.
4. `tools/analyze_suspicious.py`: Script evaluating suspicious logged rows.

**Audit Findings**:
- The file `syscall_dataset.csv` previously created under `root` was moved to `syscall_dataset_prev.csv` to resolve write permission errors when non-root users execute detector targets.
- All tools and binaries automatically log to or read the newly generated `syscall_dataset.csv` created with full user permissions.
- No workflow or test binary is broken by this preservation.

---

## 3. Required Privileges & Permission Status

### Required Linux Capabilities for eBPF Tracepoints
- **`CAP_BPF`** (or `CAP_SYS_ADMIN`): Required to invoke `bpf()` syscall and load BPF bytecode.
- **`CAP_PERFMON`** (or `CAP_SYS_ADMIN`): Required to attach eBPF probe to kernel tracepoint (`tracepoint/raw_syscalls/sys_enter`).
- **`CAP_SYS_RESOURCE`** or elevated `RLIMIT_MEMLOCK`: Required to allocate `bpf_ringbuf` maps.

### Privilege Check Outcome
- Running unprivileged (`./ebpf/syscall-detector-live -m normal_model.dat`) fails with:
  ```
  libbpf: Error in bpf_object__probe_loading(): Operation not permitted(1).
  Failed to open and load BPF program
  ```
- Non-interactive `sudo -n` requires an interactive password prompt (`sudo: a password is required`).
- `setcap` requires `CAP_SETFCAP` which unprivileged users lack.

### User Action Required for Live Attachment
To attach the live detector to real kernel tracepoints, execute the following command in an interactive terminal with administrator privileges:

```bash
sudo ./ebpf/syscall-detector-live -m normal_model.dat
```

---

## 4. Pipeline Validation & Test Matrix

| Category | Test Target / Scenario | Observed Result | Classification |
| :--- | :--- | :--- | :--- |
| **Build** | `make clean && make && make benchmarks` | All 11 binaries compiled without warnings | **PASSED** |
| **Serialization** | `./tools/test_model_serialization` | Round-trip, headered, legacy 10k, invalid magic, truncation rejected | **PASSED** |
| **Compat** | `./tools/test_trainer_detector_compat` | Trainer-to-detector pipeline, zero count & duplicate rejections | **PASSED** |
| **Explanation** | `./tools/test_explanation` | Syscall name lookup, read-only invariance, score boundary matching | **PASSED** |
| **Integration** | `./tools/test_explanation_integration` | Full event $\rightarrow$ window $\rightarrow$ score $\rightarrow$ explanation pipeline | **PASSED** |
| **Pipeline Test** | `./syscall-detector` | Formed 3-grams, score 1.0000 alerts, score 0.0047 normal, logged CSV | **PASSED** |
| **Missing Model** | Detector `-m non_existent.dat` | Output `Failed to load model: non_existent.dat`, exit status = 1 | **PASSED** |
| **Shutdown** | `SIGINT` / `SIGTERM` signal | Clean exit, BPF skel destroy, ringbuf free, dataset flush | **PASSED** |
| **Kernel BPF Probe**| Unprivileged `./ebpf/syscall-detector-live` | Exits safely with status 1 (`Operation not permitted`) | **PASSED (Safety)** |
| **Kernel Tracepoint**| Live tracepoint attach (`sys_enter`) | Blocked by unprivileged non-interactive execution | **BLOCKED** |

---

## 5. Frozen Offline Benchmark Regression Verification

Executed `./tools/adfa_model_eval > results_unified_eval.txt`:

| Metric | Target / Frozen Value | Measured Value | Status |
| :--- | :--- | :--- | :--- |
| **Validation FPR** | $\le 5.00\%$ | **4.89%** ($214 / 4372$) | **MATCHED** |
| **Attack Recall** | Baseline | **30.70%** ($229 / 746$) | **MATCHED** |
| **Precision** | Baseline | **51.69%** | **MATCHED** |
| **F1 Score** | Baseline | **38.52%** | **MATCHED** |

---

## 6. Repository Status (`git status --short`)

```
 M Makefile
 M ebpf/syscall-detector-live
 M ebpf/syscall-trainer
 M include/anomaly.h
 M include/explanation.h
 M include/model.h
 M src/explanation.c
 M src/model.c
 M syscall-detector
 M syscall_dataset.csv
 M tools/adfa_benchmark
 M tools/adfa_benchmark4
 M tools/adfa_benchmark4_sweep
 M tools/adfa_model_eval.c
?? results_unified_eval.txt
?? stage6_completion_report.md
?? syscall_dataset_prev.csv
?? tools/adfa_model_eval
?? tools/test_explanation
?? tools/test_explanation.c
?? tools/test_explanation_integration
?? tools/test_explanation_integration.c
?? tools/test_model_serialization
?? tools/test_model_serialization.c
?? tools/test_trainer_detector_compat
?? tools/test_trainer_detector_compat.c
```
