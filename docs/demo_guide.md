# Live Technical Demonstration Guide (Viva / Examiner Ready)

**Process Anomaly Detection Using System Calls with eBPF**  
*Step-by-Step Viva Presentation Protocol*

---

## 1. Overview & Setup

This demonstration allows an evaluator or viva committee to verify all 12 system actions in less than 5 minutes.

### Prerequisites:
- Web browser (Chrome, Firefox, Edge, Safari).
- Terminal with Python 3.

---

## 2. Step-by-Step 12-Action Demonstration Protocol

### Action 1: System Launch
Start the complete system in demonstration mode:
```bash
./run.sh --demo
```
*(Alternative: Start `./run.sh --dashboard-only` and run `python3 tools/demo_workload.py --rate 3 --stream` in another terminal).*

Observe terminal output:
- System prerequisite check passes.
- Dashboard initializes on `http://127.0.0.1:5000/`.
- Demo workload stream activates emitting benign and deviant sequences.

---

### Action 2: Open Web Dashboard
Navigate to `http://127.0.0.1:5000/` in your web browser.

**Talking Points**:
- The dashboard is built with vanilla HTML/CSS/JavaScript with zero third-party framework overhead.
- Operates entirely unprivileged without root access.

---

### Action 3: View Live Syscall Activity
Observe the **Throughput Chart** and the **Live Events Table**.
- Routine background events from `nginx`, `systemd-journal`, and `python3` stream into the feed with `NORMAL` status and low anomaly scores (< 0.05).
- Canvas chart updates dynamically every second showing events per second.

---

### Action 4: Observe Detected Anomalies
Watch the feed as deviant events arrive:
- Anomalous rows are visually distinguished with colored severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- The **Anomaly Counter** in the header increments in real time.
- The **Timeline Chart** displays red anomaly spikes against blue normal traffic.

---

### Action 5: Inspect Anomaly Explanations
Click on any suspicious row in the feed to open the **Forensic Detail Modal**:
- Observe the **3-Gram Sequence Breakdown**: e.g. `socket (41) -> connect (42) -> execve (59)`.
- Read the **Root Cause Explanation**:
  - *Unseen 3-Gram*: Sequence was never observed during normal baseline training.
  - *Statistically Deviant*: Sequence frequency fell below probability baseline.

---

### Action 6: Inspect Severity Classifications
In the **Security Triage Panel** at the top of the dashboard:
- Point out the distribution of severities:
  - **CRITICAL** (Red): Privilege escalation (`setuid`), remote shell (`execve` + `connect`), process injection (`ptrace` + `mprotect`).
  - **HIGH** (Orange): Process execution (`fork` -> `execve`), network binding (`socket` -> `bind`), permission alteration (`chmod`).
  - **MEDIUM** (Yellow): Directory wiping (`mkdir` -> `unlink`), unseen novelty sequences.
  - **LOW** (Blue): Routine I/O polling with marginal score near threshold (0.8350).
- Highlight the **Precedence Engine**: Rules trigger deterministically based on collected syscall primitives.

---

### Action 7: Inspect Process-Wise Behavioral Profiles
Click on the **Processes** tab in the top navigation bar:
- Search for `curl` or `nginx` using the search box.
- Filter by exact PID.
- Review total 3-grams, normal count, suspicious count, and calculated anomaly percentage.
- Note the **Process Monitoring Status**:
  - Explains the host cross-verification logic: checks `/proc/{pid}/comm` and `/proc/{pid}/cmdline` so old PIDs are not falsely claimed as running.
- Click a process row to open **Process Details**:
  - Review the top 3-gram distribution table showing exact sequence frequency counts.
  - Inspect the process activity timeline.

---

### Action 8: Navigate to Alert History
Click on the **Alert History** tab in the navigation bar:
- Shows persistent alerts stored in SQLite (`data/alerts.db`).
- Test multi-criteria search:
  - Filter by Severity: Select `CRITICAL`.
  - Filter by Incident Status: Select `NEW`.
  - Filter by Process: Enter `reverse-shell`.
- Demonstrate server-side pagination and bidirectional sorting by score, timestamp, or severity precedence.

---

### Action 9: Change an Incident Status
In the Alert History table:
- Find an alert row currently marked `NEW`.
- Click the status dropdown and change it to `INVESTIGATING`.
- Change another alert row to `RESOLVED`.
- Note that the status change immediately saves to the database via `POST /api/alert_history/update`.

---

### Action 10: Record Investigation Notes
In the same alert row:
- In the **Investigation Notes** input box, enter:
  `"Verified root cause: Unauthorized remote shell invocation during red-team exercise."`
- Click **Save**.
- Observe the confirmation indicator confirming the note has been committed to SQLite.

---

### Action 11: Restart the Dashboard
Simulate an unexpected server crash or planned maintenance:
- Go to the terminal running `./run.sh`.
- Press `Ctrl+C` to terminate the process.
- Observe clean shutdown of all managed services.
- Restart the system:
  ```bash
  ./run.sh --dashboard-only
  ```

---

### Action 12: Confirm Persistence
Return to the browser and refresh `http://127.0.0.1:5000/`:
- Click on **Alert History**.
- Locate the alert updated in Actions 9 and 10.
- **Verify**:
  - Status is still `INVESTIGATING` / `RESOLVED`.
  - Investigation note is 100% preserved exactly as typed.
  - Ingestion checkpoints ensured zero duplicate alerts were created during restart.

---

## 3. Interactive Viva Mode (Alternative)

If you prefer to step through the demonstration manually with evaluators:
```bash
./run.sh --dashboard-only
```
In a second terminal:
```bash
python3 tools/demo_workload.py --interactive
```
The script prompts you before emitting each severity level (`Enter to emit benign...`, `Enter to emit remote shell...`), allowing you to explain the underlying system call transition to examiners in real time.
