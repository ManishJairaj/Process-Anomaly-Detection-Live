# Stage 18: Independent Evaluation, Model Provenance, and Comparative Analysis Report

## Executive Summary

Stage 18 addressed fundamental scientific validity challenges in the syscall 3-gram anomaly detection project. In prior stages (Stages 1–16), evaluation relied on a temporal 70/30 block split of the training dataset (`syscall_dataset.csv`), causing severe evaluation leakage because rows evaluated in the 30% held-out set shared the exact same system context, processes, and background workloads as the 70% training set. Furthermore, unlabelled live detector records were improperly labeled as "false positives" despite lacking independent ground-truth verification.

Stage 18 introduced:
1. **Independent CSV Evaluation Mode** (`tools/eval_baseline_model --model <model.dat> --eval-csv <eval.csv>`): Evaluates all records in a genuinely separate dataset without splitting.
2. **Leakage Detection**: Uses device and inode inspection (`stat`) to detect and warn if the evaluation dataset is identical to the training dataset.
3. **Terminology Correction**: Replaced "False Positive Rate" with "Alert Rate" for unverified live traces.
4. **Cryptographic Model Provenance** (`tools/gen_model_provenance`): Emits structured JSON provenance tracking model SHA-256 hashes, dataset hashes, training methods, and label filter modes.
5. **Side-by-Side Model Comparison** (`tools/model_compare`): Evaluates `baseline_model.dat` and `experimental_normal_only_model.dat` on identical records without retraining.
6. **Automated Test Suite** (`tools/test_eval_independent`): 10 unit tests validating all Stage 18 functionality.

---

## 1. Key Tools & Architectural Enhancements

### 1.1 Independent Evaluation Tool (`tools/eval_baseline_model.c`)
- **Modes**:
  - *Legacy Positional Mode*: `./tools/eval_baseline_model [model.dat] [dataset.csv]` (maintains backward compatibility with Stage 16/17 workflows).
  - *Independent Mode*: `./tools/eval_baseline_model --model <model.dat> --eval-csv <eval.csv>`.
- **Dynamic Header Parsing**: Uses `parse_csv_header()` to locate `syscall_1`, `syscall_2`, and `syscall_3` columns dynamically by header name rather than relying on fixed column offsets.
- **Robust Ingestion**: Handles malformed lines, embedded duplicate headers (from appended logger runs), and missing fields gracefully without crashing.
- **Leakage Guard**: Compares `st_dev` and `st_ino` of the training dataset against the evaluation dataset to warn against self-evaluation leakage.

### 1.2 Model Provenance Manifests (`tools/gen_model_provenance.c`)
Generates standardized provenance files:
- `baseline_model.dat.provenance.json`:
  - SHA-256: `13b5b286d8e0248f7ebb0131fe14d146e482d1c938c295e39d16d2e56da3dc4b`
  - Unique 3-grams: 7,456 | Total training n-grams: 1,456,768
  - Training dataset: `/tmp/live_syscall_dataset.csv` (SHA-256: `da11dedc...`)
  - Label filter: `all-rows`
- `experimental_normal_only_model.dat.provenance.json`:
  - SHA-256: `775bc0366ae3919c886ff8713cf19870ea92a822f4f7c63ff196e9b86b39d419`
  - Unique 3-grams: 5,665 | Total training n-grams: 7,152,582
  - Training dataset: `/tmp/live_syscall_dataset.csv`
  - Label filter: `normal-only`

### 1.3 Side-by-Side Model Comparison (`tools/model_compare.c`)
Compares two models against the same independent CSV:
- Evaluates identical record counts.
- Reports unique 3-grams, total training n-grams, model binary size, anomalous records, alert rate, and average in-memory scoring latency.

---

## 2. Automated Test Suite (Stage 18)

All 10 tests in `tools/test_eval_independent.c` verify edge cases and core guarantees:

```
Stage 18 Independent Evaluation Unit Tests
===========================================
Binaries under test:
  ./tools/eval_baseline_model
  ./tools/gen_model_provenance

[TEST  1] Valid independent evaluation CSV, correct counts... PASSED
[TEST  2] Missing evaluation CSV — graceful failure... PASSED
[TEST  3] Malformed CSV rows — counted, valid rows scored... PASSED
[TEST  4] Empty CSV (header only) — reports zero rows... PASSED
[TEST  5] Non-standard column order detected by header name... PASSED
[TEST  6] Leakage warning fires when eval CSV == training CSV... PASSED
[TEST  7] Model provenance generation — JSON fields present... PASSED
[TEST  8] Provenance generation does not alter model binary... PASSED
[TEST  9] Consistent eval record count across two models... PASSED
[TEST 10] Backward compat: legacy positional mode output strings... PASSED

ALL STAGE 18 INDEPENDENT EVALUATION TESTS PASSED SUCCESSFULLY.
```

---

## 3. Preservation of System Invariants
- Existing models (`baseline_model.dat`, `normal_model.dat`, `experimental_normal_only_model.dat`) remained unaltered.
- Anomaly threshold of `0.80` strictly preserved.
- Scoring formula $S = 1/(1+\text{count})$ preserved.
- All 35 prior unit/integration tests from Stages 1–17 continued to pass (bringing the total to 45 passing tests).
