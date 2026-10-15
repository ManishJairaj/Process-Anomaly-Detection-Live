#!/usr/bin/env python3
import sys
import os

EXPECTED_HEADER = [
    "monotonic_timestamp_ns",
    "pid",
    "process_name",
    "syscall_1",
    "syscall_2",
    "syscall_3",
    "anomaly_score",
    "predicted_label"
]

VALID_LABELS = {"NORMAL", "SUSPICIOUS"}

def validate_dataset(filepath):
    print(f"Dataset Validation Report for: {filepath}")
    print("=" * 60)

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return False

    file_size_bytes = os.path.getsize(filepath)
    print(f"File Size          : {file_size_bytes} bytes ({file_size_bytes / (1024*1024):.2f} MB)")

    if file_size_bytes == 0:
        print("Error: Dataset file is empty (0 bytes).")
        return False

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    total_lines = len(lines)
    print(f"Total Lines        : {total_lines}")

    if total_lines < 1:
        print("Error: No lines in file.")
        return False

    # Check header
    first_line = lines[0].strip()
    header_fields = [h.strip('"') for h in first_line.split(",")]

    header_valid = True
    if header_fields != EXPECTED_HEADER:
        print(f"Header Mismatch!")
        print(f"  Expected: {EXPECTED_HEADER}")
        print(f"  Found   : {header_fields}")
        header_valid = False
    else:
        print(f"CSV Header         : VALID ({len(header_fields)} columns)")

    # Data row validation
    duplicate_headers = 0
    incomplete_rows = 0
    malformed_rows = 0
    valid_records = 0

    unique_pids = set()
    unique_processes = set()
    label_counts = {"NORMAL": 0, "SUSPICIOUS": 0}
    score_out_of_bounds = 0
    invalid_pids = 0
    invalid_syscalls = 0

    for idx, raw_line in enumerate(lines[1:], start=2):
        line = raw_line.strip()
        if not line:
            continue

        if "monotonic_timestamp_ns" in line:
            duplicate_headers += 1
            continue

        fields = [f.strip('"') for f in line.split(",")]

        if len(fields) != 8:
            incomplete_rows += 1
            continue

        try:
            ts = int(fields[0])
            pid = int(fields[1])
            comm = fields[2]
            s1 = int(fields[3])
            s2 = int(fields[4])
            s3 = int(fields[5])
            score = float(fields[6])
            label = fields[7]

            if pid < 0:
                invalid_pids += 1
            else:
                unique_pids.add(pid)

            unique_processes.add(comm)

            if s1 < 0 or s2 < 0 or s3 < 0:
                invalid_syscalls += 1

            if score < 0.0 or score > 1.0001:
                score_out_of_bounds += 1

            if label in VALID_LABELS:
                label_counts[label] += 1
            else:
                malformed_rows += 1

            valid_records += 1

        except ValueError:
            malformed_rows += 1

    print("\nValidation Summary:")
    print("-" * 60)
    print(f"Valid Records       : {valid_records}")
    print(f"Unique PIDs         : {len(unique_pids)}")
    print(f"Unique Processes    : {len(unique_processes)}")
    print(f"Labels              : NORMAL = {label_counts['NORMAL']}, SUSPICIOUS = {label_counts['SUSPICIOUS']}")
    print(f"Duplicate Headers   : {duplicate_headers}")
    print(f"Incomplete Rows     : {incomplete_rows}")
    print(f"Malformed Rows      : {malformed_rows}")
    print(f"Invalid PIDs        : {invalid_pids}")
    print(f"Invalid Syscall IDs : {invalid_syscalls}")
    print(f"Score Out-of-Bounds : {score_out_of_bounds}")

    is_clean = (
        header_valid and
        duplicate_headers == 0 and
        incomplete_rows == 0 and
        malformed_rows == 0 and
        invalid_pids == 0 and
        invalid_syscalls == 0 and
        score_out_of_bounds == 0 and
        valid_records > 0
    )

    print("\nFinal Dataset Status:")
    print("-" * 60)
    if is_clean:
        print("STATUS: CLEAN & VALIDATED (Ready for model evaluation)")
    else:
        print("STATUS: ERRORS FOUND (Review issues before training)")

    return is_clean

if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else "syscall_dataset.csv"
    validate_dataset(target_path)
