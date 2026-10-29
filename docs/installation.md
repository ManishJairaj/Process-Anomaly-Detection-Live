# Installation & System Setup Guide

**Process Anomaly Detection Using System Calls with eBPF**  
*Target Environment: Ubuntu 22.04 LTS / 24.04 LTS (Linux Kernel >= 5.8)*

---

## 1. System Requirements

| Component | Minimum Specification | Recommended Specification |
|---|---|---|
| **Operating System** | Ubuntu Linux 22.04 LTS | Ubuntu Linux 24.04 LTS |
| **Linux Kernel** | >= 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`) | 6.x LTS with BTF enabled |
| **CPU Architecture** | x86_64 | x86_64 multi-core |
| **RAM** | 2 GB | 4 GB+ |
| **Storage** | 500 MB free disk space | 2 GB+ free disk space |
| **Python** | Python 3.8+ | Python 3.10+ |
| **Privileges** | Sudo / root for eBPF kernel collector | Standard user for dashboard & demo |

---

## 2. Package Dependencies Installation

Update package lists and install required compilers, libraries, and kernel headers:

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    linux-headers-$(uname -r) \
    python3 \
    python3-pip \
    sqlite3
```

### 2.1 Verifying Kernel BTF Support
eBPF tracepoints rely on kernel BPF Type Format (BTF) debugging information. Verify that your kernel exposes `/sys/kernel/btf/vmlinux`:

```bash
ls -lh /sys/kernel/btf/vmlinux
```

If the file exists and is readable, kernel BTF is properly supported. Standard Ubuntu 20.04 HWE, 22.04, and 24.04 kernels include BTF by default.

---

## 3. Cloning and Repository Structure

Navigate to your workspace directory:

```bash
cd /path/to/Process-Anomaly-Detection-Live-main
```

Ensure file permissions are correctly set:

```bash
chmod +x run.sh workload_runner.sh tools/*.py
```

---

## 4. Building the Project

Compile the eBPF detector, trainer, and verification utilities using `make`:

```bash
make clean
make all
make benchmarks
```

### 4.1 Build Artifacts Verification
Confirm that the compiled binaries have been generated:

```bash
ls -lh ebpf/syscall-detector-live ebpf/syscall-trainer syscall-detector
```

---

## 5. System Pre-Flight Validation

The launcher provides an automated self-test flag (`--check` / `-c`) to inspect all dependencies, file paths, model availability, and port bindings prior to launch:

```bash
./run.sh --check
```

Expected output:
```text
============================================================
 Stage 24: System Prerequisite Check
============================================================
[OK] Operating System      : Linux (6.x, x86_64)
[OK] Python 3 Interpreter  : Python 3.10.x
[OK] Trained Anomaly Model : baseline_model.dat (xxx bytes)
[OK] eBPF Detector Binary  : ebpf/syscall-detector-live (Executable)
[OK] Kernel BTF Info       : /sys/kernel/btf/vmlinux readable
[OK] Dashboard Port        : 127.0.0.1:5000 is available
[OK] Output Directory      : . (Writable)
[OK] Dashboard Server      : dashboard/server.py
============================================================
[SUCCESS] All system prerequisites satisfied.
============================================================
```

---

## 6. Running Without Root Privileges (Demo & Dashboard Mode)

If you are running in an environment where `sudo` or kernel eBPF is unavailable (such as a restricted student VM, container without `CAP_BPF`, or non-Linux host for dashboard inspection):

- **Dashboard Only**:
  ```bash
  ./run.sh --dashboard-only
  ```
- **Simulated Live Workload Demo**:
  ```bash
  ./run.sh --demo
  ```
  *(Or run `python3 tools/demo_workload.py --rate 3 --stream` in a separate terminal.)*
