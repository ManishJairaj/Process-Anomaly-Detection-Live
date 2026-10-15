#!/usr/bin/env bash
# workload_runner.sh — Ground-Truth Workload Collection Framework (Stage 19)
#
# Runs a set of safe, reproducible Linux workloads (benign and controlled
# security-relevant) while an eBPF syscall detector records events.
#
# Usage:
#   sudo ./tools/workload_runner.sh [options]
#
# Options:
#   --model <path>       Model file for detector (default: baseline_model.dat)
#   --output <path>      Output CSV path (default: gt_eval_dataset.csv)
#   --manifest <path>    Output manifest path (default: gt_manifest.json)
#   --workspace <dir>    Temp workspace (default: /tmp/gt_workloads_$$)
#   --skip-detector      Don't start eBPF detector (for testing only)
#   --help               Show usage
#
# SAFETY:
#   - All file operations in a temporary workspace
#   - No system configuration changes
#   - No real malware, privilege escalation, or destructive commands
#   - No modification of user documents or production services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

MODEL_PATH="${PROJECT_DIR}/baseline_model.dat"
OUTPUT_CSV=""
MANIFEST_PATH=""
WORKSPACE=""
SKIP_DETECTOR=0
TRACER="auto"
DETECTOR_PID=""

print_usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# *//'
}

cleanup() {
    if [ -n "$DETECTOR_PID" ] && kill -0 "$DETECTOR_PID" 2>/dev/null; then
        echo "[CLEANUP] Stopping eBPF detector (PID $DETECTOR_PID)..."
        kill -SIGINT "$DETECTOR_PID" 2>/dev/null || true
        wait "$DETECTOR_PID" 2>/dev/null || true
    fi
    if [ -n "$WORKSPACE" ] && [ -d "$WORKSPACE" ]; then
        echo "[CLEANUP] Removing workspace: $WORKSPACE"
        rm -rf "$WORKSPACE"
    fi
}

trap cleanup EXIT

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --model)      MODEL_PATH="$2"; shift 2 ;;
        --output)     OUTPUT_CSV="$2"; shift 2 ;;
        --manifest)   MANIFEST_PATH="$2"; shift 2 ;;
        --workspace)  WORKSPACE="$2"; shift 2 ;;
        --skip-detector) SKIP_DETECTOR=1; shift ;;
        --tracer)     TRACER="$2"; shift 2 ;;
        --help|-h)    print_usage; exit 0 ;;
        *) echo "Unknown option: $1"; print_usage; exit 1 ;;
    esac
done

if [ "$SKIP_DETECTOR" -eq 1 ]; then
    TRACER="none"
fi

if [ "$TRACER" = "auto" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        TRACER="ebpf"
    else
        TRACER="strace"
    fi
fi

# Defaults
WORKSPACE="${WORKSPACE:-/tmp/gt_workloads_$$}"
OUTPUT_CSV="${OUTPUT_CSV:-${PROJECT_DIR}/gt_eval_dataset.csv}"
MANIFEST_PATH="${MANIFEST_PATH:-${PROJECT_DIR}/gt_manifest.json}"

mkdir -p "$WORKSPACE"

# System info for manifest
HOSTNAME_STR=$(hostname 2>/dev/null || echo "unknown")
ARCH_STR=$(uname -m 2>/dev/null || echo "unknown")
KERNEL_STR=$(uname -r 2>/dev/null || echo "unknown")

echo "========================================"
echo " Stage 19: Ground-Truth Workload Runner"
echo "========================================"
echo "Model        : $MODEL_PATH"
echo "Output CSV   : $OUTPUT_CSV"
echo "Manifest     : $MANIFEST_PATH"
echo "Workspace    : $WORKSPACE"
echo "Architecture : $ARCH_STR"
echo "Kernel       : $KERNEL_STR"
echo "Tracer       : $TRACER"
echo ""

# Start eBPF detector in background if ebpf mode selected
if [ "$TRACER" = "ebpf" ]; then
    echo "[INFO] Starting eBPF detector..."
    "${PROJECT_DIR}/ebpf/syscall-detector-live" \
        --model "$MODEL_PATH" \
        --output "$OUTPUT_CSV" \
        --quiet &
    DETECTOR_PID=$!
    echo "[INFO] Detector PID: $DETECTOR_PID"
    sleep 2  # Allow detector to stabilize
elif [ "$TRACER" = "strace" ]; then
    echo "[INFO] Initializing safe unprivileged strace collector..."
    STRACE_DIR="$WORKSPACE/strace_logs"
    mkdir -p "$STRACE_DIR"
    MONO_OFFSET=$(python3 -c "import time; print(time.clock_gettime_ns(time.CLOCK_REALTIME) - time.clock_gettime_ns(time.CLOCK_MONOTONIC))")
    rm -f "$OUTPUT_CSV"
fi

# Monotonic clock helper (nanoseconds)
mono_ns() {
    # Read monotonic clock from /proc/timer_list or clock_gettime via python
    python3 -c "import time; print(int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1e9))"
}

# Manifest accumulator
MANIFEST_ENTRIES=()

run_workload() {
    local WORKLOAD_ID="$1"
    local WORKLOAD_TYPE="$2"        # benign or security_relevant
    local GROUND_TRUTH_LABEL="$3"   # benign or suspicious
    local DESCRIPTION="$4"
    shift 4

    local START_NS
    START_NS=$(mono_ns)
    local W_PID=""

    echo "[WORKLOAD] $WORKLOAD_ID ($WORKLOAD_TYPE) — $DESCRIPTION"

    if [ "$TRACER" = "strace" ]; then
        local W_STRACE_DIR="$STRACE_DIR/$WORKLOAD_ID"
        mkdir -p "$W_STRACE_DIR"
        (
            exec strace -f -ff -o "$W_STRACE_DIR/trace" --absolute-timestamps=unix,ns "$@" >/dev/null 2>&1
        ) &
        W_PID=$!
        wait "$W_PID" 2>/dev/null || true

        local TRACED_PID
        TRACED_PID=$(ls "$W_STRACE_DIR"/trace.* 2>/dev/null | sed 's/.*\.//' | sort -n | head -1 || true)
        if [ -n "$TRACED_PID" ]; then
            W_PID="$TRACED_PID"
        fi

        python3 "$SCRIPT_DIR/strace_collector.py" \
            --strace-dir "$W_STRACE_DIR" \
            --model "$MODEL_PATH" \
            --output "$OUTPUT_CSV" \
            --mono-offset "$MONO_OFFSET"
    else
        # Run workload commands in a subshell to capture PID
        (
            "$@"
        ) &
        W_PID=$!
        wait "$W_PID" 2>/dev/null || true
    fi

    local END_NS
    END_NS=$(mono_ns)

    # Record manifest entry
    MANIFEST_ENTRIES+=("$(cat <<ENTRY
    {
      "workload_id": "$WORKLOAD_ID",
      "workload_type": "$WORKLOAD_TYPE",
      "ground_truth_label": "$GROUND_TRUTH_LABEL",
      "pid": $W_PID,
      "start_timestamp_ns": $START_NS,
      "end_timestamp_ns": $END_NS,
      "description": "$DESCRIPTION",
      "dataset_filename": "$(basename "$OUTPUT_CSV")",
      "host_arch": "$ARCH_STR",
      "kernel_version": "$KERNEL_STR"
    }
ENTRY
)")

    echo "  PID=$W_PID  start=$START_NS  end=$END_NS"
    sleep 1  # Brief pause between workloads
}

# ========================================================================
# BENIGN WORKLOADS
# ========================================================================

# B1: File reading
run_workload "B1_file_read" "benign" "benign" \
    "Read system files (/etc/hostname, /etc/os-release)" \
    bash -c "cat /etc/hostname > /dev/null; cat /etc/os-release > /dev/null; cat /proc/version > /dev/null"

# B2: File writing
run_workload "B2_file_write" "benign" "benign" \
    "Write and append to files in workspace" \
    bash -c "for i in \$(seq 1 20); do echo \"Line \$i test data\" >> \"$WORKSPACE/output_\$i.txt\"; done"

# B3: Directory traversal
run_workload "B3_dir_traverse" "benign" "benign" \
    "Recursive directory listing of /usr/share/doc" \
    bash -c "find /usr/share/doc -maxdepth 2 -type f 2>/dev/null | head -200 > /dev/null"

# B4: File compression
run_workload "B4_compression" "benign" "benign" \
    "Create and compress files with gzip" \
    bash -c "dd if=/dev/urandom of=\"$WORKSPACE/random_data\" bs=1024 count=100 2>/dev/null; gzip -k \"$WORKSPACE/random_data\" 2>/dev/null; gunzip \"$WORKSPACE/random_data.gz\" 2>/dev/null"

# B5: Compilation
run_workload "B5_compile" "benign" "benign" \
    "Compile a small C program" \
    bash -c "echo '#include <stdio.h>
int main() { printf(\"hello\\n\"); return 0; }' > \"$WORKSPACE/hello.c\"; gcc -o \"$WORKSPACE/hello\" \"$WORKSPACE/hello.c\" 2>/dev/null; \"$WORKSPACE/hello\" > /dev/null"

# B6: Local process execution
run_workload "B6_process_exec" "benign" "benign" \
    "Normal process creation (ls, uname, date, id)" \
    bash -c "ls /tmp > /dev/null; uname -a > /dev/null; date > /dev/null; id > /dev/null; whoami > /dev/null"

# B7: File copy and rename
run_workload "B7_file_copy" "benign" "benign" \
    "Copy and rename files in workspace" \
    bash -c "echo 'test content' > \"$WORKSPACE/src_file.txt\"; cp \"$WORKSPACE/src_file.txt\" \"$WORKSPACE/dst_file.txt\"; mv \"$WORKSPACE/dst_file.txt\" \"$WORKSPACE/renamed.txt\""

# B8: Process information gathering
run_workload "B8_proc_info" "benign" "benign" \
    "Read process information from /proc" \
    bash -c "cat /proc/self/status > /dev/null; cat /proc/self/maps > /dev/null 2>/dev/null; cat /proc/cpuinfo > /dev/null"

# ========================================================================
# SECURITY-RELEVANT WORKLOADS (controlled, safe simulations)
# ========================================================================

# S1: Repeated failed file access
run_workload "S1_failed_access" "security_relevant" "suspicious" \
    "Repeated attempts to read nonexistent/inaccessible files" \
    bash -c "for i in \$(seq 1 50); do cat /etc/shadow 2>/dev/null || true; cat /nonexistent_file_\$i 2>/dev/null || true; done"

# S2: Protected file access attempts
run_workload "S2_protected_files" "security_relevant" "suspicious" \
    "Attempt to access protected system files without permission" \
    bash -c "for f in /etc/shadow /etc/gshadow /root/.bashrc /etc/sudoers; do cat \"\$f\" 2>/dev/null || true; ls -la \"\$f\" 2>/dev/null || true; done; for i in \$(seq 1 20); do cat /proc/1/environ 2>/dev/null || true; done"

# S3: Unusual process creation patterns (fork bomb simulation — SAFE version)
run_workload "S3_rapid_fork" "security_relevant" "suspicious" \
    "Rapid sequential process creation (safe, bounded)" \
    bash -c "for i in \$(seq 1 30); do (echo \"\$i\" > /dev/null) & done; wait"

# S4: Rapid file modification
run_workload "S4_rapid_modify" "security_relevant" "suspicious" \
    "Rapid file creation/modification/deletion in workspace" \
    bash -c "mkdir -p \"$WORKSPACE/rapid\"; for i in \$(seq 1 50); do echo \"data_\$i\" > \"$WORKSPACE/rapid/file_\$i.txt\"; done; for i in \$(seq 1 50); do cat \"$WORKSPACE/rapid/file_\$i.txt\" > /dev/null; done; rm -rf \"$WORKSPACE/rapid\""

# S5: Enumeration-like behavior
run_workload "S5_enumeration" "security_relevant" "suspicious" \
    "System enumeration patterns (reading multiple /proc and /sys entries)" \
    bash -c "for d in /proc/[0-9]*; do cat \"\$d/cmdline\" 2>/dev/null || true; done | head -100 > /dev/null; ls /proc/net/ 2>/dev/null > /dev/null; cat /proc/net/tcp 2>/dev/null > /dev/null"

# ========================================================================
# Write manifest JSON
# ========================================================================
echo ""
echo "[INFO] Writing ground-truth manifest to: $MANIFEST_PATH"

{
    echo "{"
    echo "  \"schema_version\": 1,"
    echo "  \"experiment_type\": \"ground_truth_evaluation\","
    echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"host_arch\": \"$ARCH_STR\","
    echo "  \"kernel_version\": \"$KERNEL_STR\","
    echo "  \"hostname\": \"$HOSTNAME_STR\","
    echo "  \"model_file\": \"$(basename "$MODEL_PATH")\","
    echo "  \"dataset_file\": \"$(basename "$OUTPUT_CSV")\","
    echo "  \"timestamp_type\": \"monotonic_ns\","
    echo "  \"timestamp_note\": \"All timestamps use CLOCK_MONOTONIC in nanoseconds. eBPF events use the same clock.\","
    echo "  \"workloads\": ["

    local_count=0
    total=${#MANIFEST_ENTRIES[@]}
    for entry in "${MANIFEST_ENTRIES[@]}"; do
        local_count=$((local_count + 1))
        echo "$entry"
        if [ "$local_count" -lt "$total" ]; then
            echo "    ,"
        fi
    done

    echo "  ]"
    echo "}"
} > "$MANIFEST_PATH"

# Stop detector
if [ -n "$DETECTOR_PID" ] && kill -0 "$DETECTOR_PID" 2>/dev/null; then
    echo "[INFO] Stopping eBPF detector..."
    kill -SIGINT "$DETECTOR_PID" 2>/dev/null || true
    wait "$DETECTOR_PID" 2>/dev/null || true
    DETECTOR_PID=""
fi

echo ""
echo "========================================"
echo " Workload Collection Complete"
echo "========================================"
echo "Dataset : $OUTPUT_CSV"
echo "Manifest: $MANIFEST_PATH"
echo "Workloads executed: ${#MANIFEST_ENTRIES[@]}"
echo ""
echo "Next step: Run ground-truth evaluation"
echo "  ./tools/gt_evaluate --manifest $MANIFEST_PATH --dataset $OUTPUT_CSV --model $MODEL_PATH"
