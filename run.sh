#!/usr/bin/env bash
# ==============================================================================
# run.sh — One-Command Startup and System Integration Launcher (Stage 24)
#
# Process Anomaly Detection Using System Calls with eBPF
#
# Usage:
#   ./run.sh [options]
#
# Options:
#   --help, -h             Show this help message and exit
#   --check, -c            Validate system prerequisites without starting services
#   --dashboard-only, -d   Launch the web dashboard only (unprivileged, no sudo)
#   --model, -m <path>     Trained model file (default: baseline_model.dat)
#   --port, -p <num>       Dashboard port (default: 5000)
#   --output, -o <path>    Output CSV file for events (default: syscall_dataset.csv)
#   --host <ip>            Dashboard host address (default: 127.0.0.1)
#   --detector <path>      Path to detector executable (default: ebpf/syscall-detector-live)
#   --quiet, -q            Run detector in quiet mode (anomaly alerts only)
# ==============================================================================

set -uo pipefail

# 1. Resolve project root directory automatically
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

# Defaults
MODEL_PATH="${PROJECT_DIR}/baseline_model.dat"
DETECTOR_PATH="${PROJECT_DIR}/ebpf/syscall-detector-live"
OUTPUT_CSV="${PROJECT_DIR}/syscall_dataset.csv"
DASHBOARD_HOST="127.0.0.1"
DASHBOARD_PORT=5000
DASHBOARD_ONLY=0
CHECK_ONLY=0
QUIET_MODE=0

# Process tracking variables (only processes started by this launcher)
DASHBOARD_PID=""
DETECTOR_PID=""

# Help message
print_usage() {
    cat <<EOF
Process Anomaly Detection System Launcher (Stage 24)

Usage:
  ./run.sh [options]

Primary Options:
  --help, -h             Show this help message and exit
  --check, -c            Validate system prerequisites without starting services
  --dashboard-only, -d   Launch only the web dashboard (unprivileged, no sudo required)
  --model, -m <path>     Path to trained anomaly model (default: baseline_model.dat)
  --port, -p <num>       Dashboard HTTP port (default: 5000)
  --output, -o <path>    Path to CSV dataset output (default: syscall_dataset.csv)
  --host <ip>            Dashboard listen host (default: 127.0.0.1)
  --detector <path>      Path to eBPF detector binary (default: ebpf/syscall-detector-live)
  --quiet, -q            Suppress informational event printing from detector

Examples:
  ./run.sh                      # Launch full system (Detector + Dashboard)
  ./run.sh --dashboard-only     # Launch dashboard only for historical log review
  ./run.sh --check              # Verify prerequisites and system readiness
  ./run.sh --port 8080 --output data/live.csv
EOF
}

# Parse command line options
while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            print_usage
            exit 0
            ;;
        --check|-c)
            CHECK_ONLY=1
            shift
            ;;
        --dashboard-only|-d)
            DASHBOARD_ONLY=1
            shift
            ;;
        --model|-m)
            if [ $# -lt 2 ] || [[ "$2" =~ ^-- ]]; then
                echo "[ERROR] Option $1 requires a file path argument." >&2
                exit 1
            fi
            MODEL_PATH="$2"
            shift 2
            ;;
        --port|-p)
            if [ $# -lt 2 ] || [[ "$2" =~ ^-- ]]; then
                echo "[ERROR] Option $1 requires a port number argument." >&2
                exit 1
            fi
            DASHBOARD_PORT="$2"
            shift 2
            ;;
        --output|-o)
            if [ $# -lt 2 ] || [[ "$2" =~ ^-- ]]; then
                echo "[ERROR] Option $1 requires an output CSV path argument." >&2
                exit 1
            fi
            OUTPUT_CSV="$2"
            shift 2
            ;;
        --host)
            if [ $# -lt 2 ] || [[ "$2" =~ ^-- ]]; then
                echo "[ERROR] Option $1 requires an IP address argument." >&2
                exit 1
            fi
            DASHBOARD_HOST="$2"
            shift 2
            ;;
        --detector)
            if [ $# -lt 2 ] || [[ "$2" =~ ^-- ]]; then
                echo "[ERROR] Option $1 requires an executable path argument." >&2
                exit 1
            fi
            DETECTOR_PATH="$2"
            shift 2
            ;;
        --quiet|-q)
            QUIET_MODE=1
            shift
            ;;
        *)
            echo "[ERROR] Unknown option: $1" >&2
            echo "Run './run.sh --help' for available options." >&2
            exit 1
            ;;
    esac
done

# Resolve paths to absolute if relative
if [[ "$MODEL_PATH" != /* ]]; then
    MODEL_PATH="${PROJECT_DIR}/${MODEL_PATH}"
fi
if [[ "$DETECTOR_PATH" != /* ]]; then
    DETECTOR_PATH="${PROJECT_DIR}/${DETECTOR_PATH}"
fi
if [[ "$OUTPUT_CSV" != /* ]]; then
    OUTPUT_CSV="${PROJECT_DIR}/${OUTPUT_CSV}"
fi

# ==============================================================================
# Prerequisite Verification Function
# ==============================================================================
check_prerequisites() {
    local check_failed=0

    echo "============================================================"
    echo " Stage 24: System Prerequisite Check"
    echo "============================================================"

    # 1. OS check
    if [ "$(uname -s)" = "Linux" ]; then
        echo "[OK] Operating System      : Linux ($(uname -r), $(uname -m))"
    else
        echo "[FAIL] Operating System    : Not Linux ($(uname -s))"
        check_failed=1
    fi

    # 2. Python 3 check
    if command -v python3 >/dev/null 2>&1; then
        local py_ver
        py_ver=$(python3 --version 2>&1)
        echo "[OK] Python 3 Interpreter  : $py_ver"
    else
        echo "[FAIL] Python 3 Interpreter: Not found in PATH"
        check_failed=1
    fi

    # 3. Model check
    if [ -f "$MODEL_PATH" ]; then
        local model_sz
        model_sz=$(wc -c < "$MODEL_PATH" 2>/dev/null || echo "unknown")
        echo "[OK] Trained Anomaly Model : $MODEL_PATH ($model_sz bytes)"
    else
        echo "[FAIL] Trained Anomaly Model : Missing file '$MODEL_PATH'"
        check_failed=1
    fi

    # 4. Detector executable check
    if [ "$DASHBOARD_ONLY" -eq 0 ]; then
        if [ -x "$DETECTOR_PATH" ]; then
            echo "[OK] eBPF Detector Binary  : $DETECTOR_PATH (Executable)"
        elif [ -f "$DETECTOR_PATH" ]; then
            echo "[FAIL] eBPF Detector Binary : '$DETECTOR_PATH' exists but is not executable"
            check_failed=1
        else
            echo "[FAIL] eBPF Detector Binary : Missing executable '$DETECTOR_PATH' (Run 'make' to build)"
            check_failed=1
        fi
    else
        echo "[SKIP] eBPF Detector Binary: (Dashboard-only mode active)"
    fi

    # 5. Kernel BTF check
    if [ "$DASHBOARD_ONLY" -eq 0 ]; then
        if [ -r /sys/kernel/btf/vmlinux ]; then
            echo "[OK] Kernel BTF Info       : /sys/kernel/btf/vmlinux readable"
        else
            echo "[WARN] Kernel BTF Info     : /sys/kernel/btf/vmlinux not readable (Kernel eBPF requires BTF support)"
        fi
    else
        echo "[SKIP] Kernel BTF Info     : (Dashboard-only mode active)"
    fi

    # 6. Port availability check
    if ! [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] || [ "$DASHBOARD_PORT" -lt 1 ] || [ "$DASHBOARD_PORT" -gt 65535 ]; then
        echo "[FAIL] Dashboard Port      : Invalid port '$DASHBOARD_PORT' (Must be 1-65535)"
        check_failed=1
    else
        if python3 -c "import socket; s = socket.socket(); s.bind(('$DASHBOARD_HOST', $DASHBOARD_PORT)); s.close()" 2>/dev/null; then
            echo "[OK] Dashboard Port        : $DASHBOARD_HOST:$DASHBOARD_PORT is available"
        else
            echo "[FAIL] Dashboard Port      : $DASHBOARD_HOST:$DASHBOARD_PORT is already in use"
            check_failed=1
        fi
    fi

    # 7. Output directory check
    local out_dir
    out_dir=$(dirname "$OUTPUT_CSV")
    if [ -d "$out_dir" ] || mkdir -p "$out_dir" 2>/dev/null; then
        echo "[OK] Output Directory      : $out_dir (Writable)"
    else
        echo "[FAIL] Output Directory    : Cannot create directory '$out_dir'"
        check_failed=1
    fi

    # 8. Dashboard server script check
    if [ -f "$PROJECT_DIR/dashboard/server.py" ]; then
        echo "[OK] Dashboard Server      : $PROJECT_DIR/dashboard/server.py"
    else
        echo "[FAIL] Dashboard Server    : Missing $PROJECT_DIR/dashboard/server.py"
        check_failed=1
    fi

    echo "============================================================"
    if [ $check_failed -eq 0 ]; then
        echo "[SUCCESS] All system prerequisites satisfied."
    else
        echo "[ERROR] Prerequisite check failed. Address reported issues above."
    fi
    echo "============================================================"
    return $check_failed
}

# If --check was passed, run checks and exit
if [ "$CHECK_ONLY" -eq 1 ]; then
    check_prerequisites
    exit $?
fi

# ==============================================================================
# Run Preliminary Checks Before Launching
# ==============================================================================
if ! check_prerequisites; then
    echo "[ABORT] System prerequisites not satisfied. Use './run.sh --check' to review." >&2
    exit 1
fi

# ==============================================================================
# Safe Process Cleanup Function
# ==============================================================================
cleanup() {
    # Disable trap to avoid recursive invocation
    trap - SIGINT SIGTERM SIGHUP EXIT
    echo ""
    echo "[SHUTDOWN] Stopping services..."

    # 1. Stop dashboard if started by this script
    if [ -n "$DASHBOARD_PID" ] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        echo "[SHUTDOWN] Stopping dashboard (PID $DASHBOARD_PID)..."
        kill -SIGTERM "$DASHBOARD_PID" 2>/dev/null || true
        # Wait up to 3 seconds for graceful exit
        for _ in 1 2 3; do
            if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then break; fi
            sleep 0.5
        done
        if kill -0 "$DASHBOARD_PID" 2>/dev/null; then
            kill -SIGKILL "$DASHBOARD_PID" 2>/dev/null || true
        fi
        wait "$DASHBOARD_PID" 2>/dev/null || true
    fi

    # 2. Stop detector if started by this script
    if [ -n "$DETECTOR_PID" ] && kill -0 "$DETECTOR_PID" 2>/dev/null; then
        echo "[SHUTDOWN] Stopping eBPF detector (PID $DETECTOR_PID)..."
        if [ "$(id -u)" -eq 0 ]; then
            kill -SIGINT "$DETECTOR_PID" 2>/dev/null || true
        else
            sudo kill -SIGINT "$DETECTOR_PID" 2>/dev/null || kill -SIGINT "$DETECTOR_PID" 2>/dev/null || true
        fi
        for _ in 1 2 3; do
            if ! kill -0 "$DETECTOR_PID" 2>/dev/null; then break; fi
            sleep 0.5
        done
        if kill -0 "$DETECTOR_PID" 2>/dev/null; then
            if [ "$(id -u)" -eq 0 ]; then
                kill -SIGKILL "$DETECTOR_PID" 2>/dev/null || true
            else
                sudo kill -SIGKILL "$DETECTOR_PID" 2>/dev/null || true
            fi
        fi
        wait "$DETECTOR_PID" 2>/dev/null || true
    fi

    echo "[SHUTDOWN] All launcher-managed services stopped cleanly."
}

# Register signal traps
trap cleanup SIGINT SIGTERM SIGHUP EXIT

# ==============================================================================
# Data Safety & Output CSV Preparation
# ==============================================================================
out_dir=$(dirname "$OUTPUT_CSV")
mkdir -p "$out_dir"

if [ ! -f "$OUTPUT_CSV" ]; then
    echo "[INFO] Initializing new output CSV: $OUTPUT_CSV"
    echo "monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label" > "$OUTPUT_CSV"
else
    echo "[INFO] Preserving existing dataset: $OUTPUT_CSV ($(wc -l < "$OUTPUT_CSV") lines)"
fi

# ==============================================================================
# Launch Dashboard (Always Unprivileged / Normal User)
# ==============================================================================
echo ""
echo "[INFO] Starting Web Dashboard on http://${DASHBOARD_HOST}:${DASHBOARD_PORT}/..."

# If launcher is somehow executed as root, run dashboard as SUDO_USER if available
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    su - "$SUDO_USER" -c "python3 '$PROJECT_DIR/dashboard/server.py' --host '$DASHBOARD_HOST' --port '$DASHBOARD_PORT' --dataset '$OUTPUT_CSV'" &
    DASHBOARD_PID=$!
else
    python3 "$PROJECT_DIR/dashboard/server.py" \
        --host "$DASHBOARD_HOST" \
        --port "$DASHBOARD_PORT" \
        --dataset "$OUTPUT_CSV" &
    DASHBOARD_PID=$!
fi

# Verify dashboard started
sleep 1.2
if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    echo "[ERROR] Web dashboard failed to start. Check port $DASHBOARD_PORT." >&2
    exit 1
fi
echo "[OK] Web Dashboard active (PID $DASHBOARD_PID, User: $(whoami))"

# ==============================================================================
# Launch Detector (If not in --dashboard-only mode)
# ==============================================================================
if [ "$DASHBOARD_ONLY" -eq 0 ]; then
    DETECTOR_ARGS=("-m" "$MODEL_PATH" "-o" "$OUTPUT_CSV")
    if [ "$QUIET_MODE" -eq 1 ]; then
        DETECTOR_ARGS+=("-q")
    fi

    echo "[INFO] Starting eBPF syscall detector..."

    if [ "$(id -u)" -eq 0 ]; then
        "$DETECTOR_PATH" "${DETECTOR_ARGS[@]}" &
        DETECTOR_PID=$!
    else
        echo "[INFO] Elevating privileges for eBPF tracepoint attachment..."
        if ! sudo -v 2>/dev/null; then
            echo "[PROMPT] Sudo privileges required for eBPF kernel attachment:"
            if ! sudo -v; then
                echo "[ERROR] Sudo authentication failed. Cannot start eBPF detector." >&2
                echo "[INFO] Run with '--dashboard-only' to view existing datasets without root." >&2
                exit 1
            fi
        fi

        sudo "$DETECTOR_PATH" "${DETECTOR_ARGS[@]}" &
        DETECTOR_PID=$!
    fi

    sleep 1.5
    if ! kill -0 "$DETECTOR_PID" 2>/dev/null; then
        echo "[ERROR] eBPF detector failed to start or exited prematurely." >&2
        exit 1
    fi
    echo "[OK] eBPF Detector active (PID $DETECTOR_PID)"
fi

# ==============================================================================
# Display System Status & Supervision Loop
# ==============================================================================
echo ""
echo "============================================================"
echo " Process Anomaly Detection System Active"
echo "============================================================"
echo " Dashboard URL  : http://${DASHBOARD_HOST}:${DASHBOARD_PORT}/"
echo " Active Dataset : $OUTPUT_CSV"
echo " Anomaly Model  : $MODEL_PATH"
echo " Dashboard PID  : $DASHBOARD_PID"
if [ "$DASHBOARD_ONLY" -eq 0 ]; then
    echo " Detector PID   : $DETECTOR_PID (eBPF Kernel Collector)"
else
    echo " Detector Mode  : Disabled (--dashboard-only)"
fi
echo "============================================================"
echo " System running. Press Ctrl+C to terminate cleanly."
echo "============================================================"

# Supervision loop: monitor active child processes
while true; do
    if [ -n "$DASHBOARD_PID" ] && ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        echo "[ERROR] Dashboard process (PID $DASHBOARD_PID) exited unexpectedly."
        exit 1
    fi
    if [ -n "$DETECTOR_PID" ] && ! kill -0 "$DETECTOR_PID" 2>/dev/null; then
        echo "[ERROR] Detector process (PID $DETECTOR_PID) exited unexpectedly."
        exit 1
    fi
    sleep 1
done
