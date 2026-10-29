# Telemetry Boundaries, Methodology & Honest Limitations

**Process Anomaly Detection Using System Calls with eBPF**  
*Academic Viva Evaluation & Technical Limitations Document*

---

## 1. Alert Rate vs. False Positive Rate (Crucial Academic Distinction)

During model validation on unlabelled or semi-synthetic datasets, our pipeline demonstrated an **alert rate of 0.1836%** (approximately 1.8 suspicious sequences per 1,000 observed 3-grams).

### The Distinction:
- **Alert Rate ($\text{Alerts} / \text{Total Events}$)**: The empirical proportion of observed 3-gram sequences that exceeded the anomaly threshold ($S \ge 0.80$). It reflects the model's sensitivity and background noise under normal host workloads.
- **False Positive Rate ($\text{FP} / (\text{FP} + \text{TN})$)**: The statistical proportion of strictly benign sequences that were incorrectly classified as malicious. Computing a true False Positive Rate requires a fully ground-truth-labeled dataset where every single invocation is verified as benign or hostile.
- **Academic Stance**: We do **not** claim an empirical False Positive Rate of 0.1836% without certified ground-truth labeling. Similarly, we do not claim verified real-world attack recall metrics from incompatible benchmark distributions without continuous live hostile validation.

---

## 2. Telemetry Boundaries: What eBPF Captures vs. What It Does Not

To operate with minimal CPU overhead (< 1.5% CPU under standard server load), our eBPF collector captures a focused set of telemetry fields:

### Captured by Collector:
1. **System Call Number (`syscall_nr`)**: Architecture ABI integer ID (e.g., 59 for `execve`, 105 for `setuid`).
2. **Process Identifier (`pid`)**: Linux thread/process ID from `bpf_get_current_pid_tgid()`.
3. **Process Name (`comm`)**: 16-byte process name string from `bpf_get_current_comm()`.
4. **Monotonic Kernel Timestamp (`timestamp_ns`)**: High-resolution nanoseconds from `bpf_ktime_get_ns()`.

### NOT Captured by Collector (Explicit Telemetry Boundaries):
1. **Syscall Arguments**: File paths, memory pointers, network addresses, ports, or permission mode flags are **not** inspected or logged.
   - *Consequence*: The system detects that an `openat` or `connect` occurred in an unusual sequence, but cannot inspect which file path or remote IP address was targeted.
2. **User Data & Payloads**: Raw data transferred via `read`, `write`, or `sendto` is not inspected.
   - *Benefit*: Preserves process privacy, protects secrets in memory, and maintains negligible overhead.
3. **Full Process Ancestry**: Parent-child trees (PPID hierarchy) beyond the immediate process context are not dynamically maintained inside the eBPF map.
4. **Namespace / Container Metadata**: While namespace-switching syscalls (`setns`, `unshare`, `pivot_root`) are captured by ID, Docker/Kubernetes container labels are not resolved in-kernel.

---

## 3. Anomaly Detection vs. Maliciousness

A core principle of host-based intrusion detection:
$$\text{Statistical Novelty} \neq \text{Malicious Intent}$$

- **What the Model Measures**: The 3-gram model measures statistical divergence from a recorded baseline. An unseen sequence has anomaly score $1.0000$ simply because it was absent during training.
- **Benign Novelty**: Software updates, newly installed utilities, unexpected error handling paths, or unusual compilation flags can trigger anomaly alerts despite being completely benign.
- **Why Rule-Based Severity Classification (Stage 22) was Introduced**: Because an anomaly score alone cannot differentiate between a harmless novel I/O sequence (`fstat` -> `lseek` -> `close`) and an exploit primitive (`socket` -> `connect` -> `execve`), the rule engine categorizes alerts into `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` to prioritize human analyst triage.

---

## 4. Modeling Limitations: 3-Gram Sliding Windows

### 4.1 Window Size ($N=3$)
- **Strengths**: Captures local control-flow transitions with low memory footprint and fast constant-time $O(1)$ lookups.
- **Limitations**: Cannot capture long-range temporal dependencies. An attacker who spaces malicious syscalls with thousands of routine `read`/`write` invocations (mimicry attacks) may bypass short-window detection.

### 4.2 Multi-Threading & Concurrency
- Sliding windows are maintained per PID. Multi-threaded processes sharing memory space generate distinct concurrent sliding windows per thread ID. Inter-thread race conditions or co-dependent threads are tracked independently.

### 4.3 Training Set Representativeness
- The detector's efficacy is strictly bounded by the completeness of the baseline training data. Training on insufficient or biased workloads will cause elevated alert rates when encountering standard production traffic.

---

## 5. Security and Operational Scope Boundaries

1. **Privilege Separation**:
   - The eBPF collector requires elevated privileges (`CAP_BPF`, `CAP_PERFMON`, or `sudo`) to load BPF bytecode and attach tracepoints.
   - The web dashboard and database engine run entirely unprivileged under standard user permissions, preventing frontend compromise from escalating to root.
2. **Denial of Service Resilience**:
   - In high-throughput environments (e.g. 50,000 syscalls/sec), BPF ring buffers may drop events if user-space consumers fall behind. The detector monitors dropped event counters.
