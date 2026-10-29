#!/usr/bin/env python3
"""
strace_collector.py — Unprivileged Syscall Tracer & Dataset Generator (Stage 19)

Extracts syscall sequences from strace output files, maintains per-PID 3-gram
sliding windows, scores them against a trained NormalModel binary (.dat),
and appends events to the dataset CSV in the exact format used by the live
eBPF detector:

monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label
"""

import sys
import os
import re
import glob
import struct
import argparse
import subprocess

def get_syscall_table():
    """Extract x86_64 syscall names to numbers from system headers."""
    table = {}
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
                    table[name] = int(parts[2])
    except Exception as e:
        # Fallback table for essential x86_64 syscalls
        pass
    return table

def load_model(model_path):
    """Load binary model file."""
    entries = {}
    if not os.path.exists(model_path):
        return entries
    try:
        with open(model_path, 'rb') as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                return entries
            magic, version, ngram_size, entry_count, total_ngrams = struct.unpack('<IIIIQ', hdr)
            if magic != 0x5041444D or version != 1:
                return entries
            for _ in range(entry_count):
                buf = f.read(32)
                if len(buf) < 32:
                    break
                s1, s2, s3, pad, count, prob = struct.unpack('<iiiiQd', buf)
                entries[(s1, s2, s3)] = count
    except Exception as e:
        pass
    return entries

def score_ngram(model_entries, ngram):
    """Compute anomaly score for 3-gram."""
    count = model_entries.get(ngram, 0)
    if count == 0:
        return 1.0
    return 1.0 / (1.0 + float(count))

def process_strace_dir(strace_dir, model_path, output_csv, mono_offset_ns):
    syscall_table = get_syscall_table()
    model_entries = load_model(model_path)

    # Find all trace files: prefix.<pid>
    trace_files = glob.glob(os.path.join(strace_dir, "*"))
    events = []

    # Regex for strace line:
    # 1792060745.666276694 write(1, "...", 11) = 11
    # or unfinished/resumed syscalls
    line_re = re.compile(r"^(\d+\.\d+)\s+([a-zA-Z0-9_]+)\(")

    for tfile in trace_files:
        basename = os.path.basename(tfile)
        # Extract PID from suffix
        parts = basename.rsplit(".", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        pid = int(parts[1])

        # Infer process name if possible
        proc_name = "workload"
        window = []

        try:
            with open(tfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = line_re.match(line)
                    if not m:
                        continue
                    ts_str, sc_name = m.groups()
                    if sc_name not in syscall_table:
                        continue
                    sc_id = syscall_table[sc_name]

                    if sc_name == "execve":
                        # Try to extract executable name
                        comm_match = re.search(r'execve\("([^"]+)"', line)
                        if comm_match:
                            proc_name = os.path.basename(comm_match.group(1))

                    try:
                        unix_ns = int(float(ts_str) * 1e9)
                    except ValueError:
                        continue
                    mono_ns = unix_ns - mono_offset_ns

                    window.append(sc_id)
                    if len(window) > 3:
                        window.pop(0)

                    if len(window) == 3:
                        ngram = (window[0], window[1], window[2])
                        score = score_ngram(model_entries, ngram)
                        label = "SUSPICIOUS" if score >= 0.80 else "NORMAL"
                        events.append((mono_ns, pid, proc_name, ngram[0], ngram[1], ngram[2], score, label))
        except Exception:
            continue

    # Sort all events chronologically by monotonic timestamp
    events.sort(key=lambda x: x[0])

    # Write or append to CSV
    file_exists = os.path.exists(output_csv) and os.path.getsize(output_csv) > 0
    with open(output_csv, "a", encoding="utf-8") as out:
        if not file_exists:
            out.write("monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n")
        for ev in events:
            out.write(f'{ev[0]},{ev[1]},"{ev[2]}",{ev[3]},{ev[4]},{ev[5]},{ev[6]:.4f},{ev[7]}\n')

    return len(events)

def main():
    parser = argparse.ArgumentParser(description="Convert strace output to detector CSV dataset")
    parser.add_argument("--strace-dir", required=True, help="Directory containing strace output files")
    parser.add_argument("--model", required=True, help="Path to model file (.dat)")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--mono-offset", type=int, required=True, help="Realtime minus Monotonic offset in ns")

    args = parser.parse_args()
    count = process_strace_dir(args.strace_dir, args.model, args.output, args.mono_offset)
    print(f"[INFO] Processed {count} 3-gram events from strace.")

if __name__ == "__main__":
    main()
