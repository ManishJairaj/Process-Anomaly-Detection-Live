#!/usr/bin/env python3
"""
database.py — Persistent SQLite Storage and Incident Management for Anomaly Alerts (Stage 20 & 21)

Manages:
- SQLite database creation and schema migrations in project-local data directory
- Durable ingestion of anomaly alerts with duplicate prevention across server restarts
- Incident status transitions (NEW, INVESTIGATING, RESOLVED, FALSE_ALARM)
- Persistent investigation notes and audit timestamps
- Server-side search, filtering, sorting, pagination, and CSV export
- Process-wise behavioral statistics, 3-gram frequencies, activity timelines, and active process verification (Stage 21)
"""

import os
import sys
import sqlite3
import datetime
import threading
from typing import Dict, Any, List, Optional, Tuple

try:
    from dashboard.severity import classify_severity, resolve_syscall_name, RULE_ENGINE_VERSION
except ImportError:
    from severity import classify_severity, resolve_syscall_name, RULE_ENGINE_VERSION

VALID_STATUSES = ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_ALARM')
VALID_SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

def format_syscall_seq(s1: int, s2: int, s3: int) -> str:
    n1 = resolve_syscall_name(s1)
    n2 = resolve_syscall_name(s2)
    n3 = resolve_syscall_name(s3)
    return f"{n1} ({s1}) -> {n2} ({s2}) -> {n3} ({s3})"

def is_process_running_on_host(pid: int, process_name: Optional[str] = None) -> bool:
    """
    Verifies if a process with the specified PID is currently running on the host system.
    Cross-checks process name against /proc/{pid}/comm and /proc/{pid}/cmdline to handle PID reuse.
    On non-Linux systems or when /proc is inaccessible, checks system facilities safely.
    """
    if pid is None or pid <= 0:
        return False
    try:
        proc_dir = f"/proc/{pid}"
        if os.path.isdir(proc_dir):
            if process_name:
                clean_name = os.path.basename(str(process_name)).strip().lower()
                # Check comm
                comm_path = os.path.join(proc_dir, "comm")
                if os.path.exists(comm_path):
                    with open(comm_path, "r", encoding="utf-8", errors="ignore") as f:
                        comm = f.read().strip().lower()
                    if comm and (comm == clean_name or clean_name.startswith(comm) or comm.startswith(clean_name)):
                        return True
                # Check cmdline
                cmdline_path = os.path.join(proc_dir, "cmdline")
                if os.path.exists(cmdline_path):
                    with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                        cmdline = f.read().lower()
                    if clean_name in cmdline:
                        return True
                # PID exists but belongs to an unrelated command (PID reuse!)
                return False
            return True
        elif sys.platform == "win32":
            # Safe Windows process verification
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
                if h_proc:
                    kernel32.CloseHandle(h_proc)
                    return True
                return False
            except Exception:
                return False
        return False
    except Exception:
        return False

class AlertDatabase:
    """Thread-safe SQLite database manager for anomaly alerts and process-wise analytics."""

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.lock = threading.Lock()
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection with WAL mode and row factory."""
        conn = sqlite3.connect(self.db_path, timeout=20.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def init_db(self) -> None:
        """Initialize database schema, tables, and indexes if they do not exist."""
        with self.lock:
            conn = self.get_connection()
            try:
                with conn:
                    # 1. Main alerts table (Stage 20 & 22)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS alerts (
                            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            event_timestamp INTEGER NOT NULL,
                            pid INTEGER NOT NULL,
                            process_name TEXT NOT NULL,
                            syscall_1 INTEGER NOT NULL,
                            syscall_2 INTEGER NOT NULL,
                            syscall_3 INTEGER NOT NULL,
                            anomaly_score REAL NOT NULL,
                            explanation TEXT NOT NULL,
                            incident_status TEXT NOT NULL DEFAULT 'NEW'
                                CHECK (incident_status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_ALARM')),
                            investigation_notes TEXT NOT NULL DEFAULT '',
                            source_dataset TEXT NOT NULL,
                            record_offset INTEGER DEFAULT NULL,
                            file_signature TEXT NOT NULL DEFAULT '',
                            created_at TEXT NOT NULL,
                            last_updated TEXT NOT NULL,
                            severity TEXT NOT NULL DEFAULT 'MEDIUM'
                                CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
                            severity_rule TEXT NOT NULL DEFAULT 'DEFAULT_CLASSIFICATION',
                            severity_reason TEXT NOT NULL DEFAULT '',
                            severity_rule_version TEXT NOT NULL DEFAULT '1.0.0',
                            CONSTRAINT unq_alert_file_offset UNIQUE (source_dataset, file_signature, record_offset)
                        );
                    """)

                    # Schema Migration for Stage 22: Add severity columns if migrating from earlier database
                    cur = conn.cursor()
                    cur.execute("PRAGMA table_info(alerts);")
                    existing_cols = {row["name"] for row in cur.fetchall()}
                    if existing_cols:
                        if "severity" not in existing_cols:
                            conn.execute("ALTER TABLE alerts ADD COLUMN severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'));")
                        if "severity_rule" not in existing_cols:
                            conn.execute("ALTER TABLE alerts ADD COLUMN severity_rule TEXT NOT NULL DEFAULT 'DEFAULT_CLASSIFICATION';")
                        if "severity_reason" not in existing_cols:
                            conn.execute("ALTER TABLE alerts ADD COLUMN severity_reason TEXT NOT NULL DEFAULT '';")
                        if "severity_rule_version" not in existing_cols:
                            conn.execute("ALTER TABLE alerts ADD COLUMN severity_rule_version TEXT NOT NULL DEFAULT '1.0.0';")

                    # Indexes for alerts table
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(incident_status);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_pid ON alerts(pid);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_process ON alerts(process_name);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(event_timestamp DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(anomaly_score DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_dataset);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_triage ON alerts(severity, incident_status);")

                    # Idempotent historical severity classification backfill
                    self._backfill_severity(conn)

                    # 2. Checkpoints table for transactionally consistent CSV ingestion (Stage 20)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
                            source_dataset TEXT PRIMARY KEY,
                            file_signature TEXT NOT NULL DEFAULT '',
                            last_byte_offset INTEGER NOT NULL DEFAULT 0,
                            last_line_number INTEGER NOT NULL DEFAULT 0,
                            last_event_timestamp INTEGER NOT NULL DEFAULT 0,
                            updated_at TEXT NOT NULL
                        );
                    """)

                    # 3. Process Summary Aggregate Table (Stage 21)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS process_summary (
                            pid INTEGER NOT NULL,
                            process_name TEXT NOT NULL,
                            source_dataset TEXT NOT NULL,
                            total_events INTEGER NOT NULL DEFAULT 0,
                            normal_events INTEGER NOT NULL DEFAULT 0,
                            suspicious_events INTEGER NOT NULL DEFAULT 0,
                            max_score REAL NOT NULL DEFAULT 0.0,
                            first_timestamp INTEGER NOT NULL,
                            last_timestamp INTEGER NOT NULL,
                            last_seen_epoch INTEGER NOT NULL,
                            PRIMARY KEY (pid, process_name, source_dataset)
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_name ON process_summary(process_name);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_summary(pid);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_last_ts ON process_summary(last_timestamp DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_total ON process_summary(total_events DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_susp ON process_summary(suspicious_events DESC);")

                    # 4. Process Top 3-Grams Frequency Table (Stage 21)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS process_ngrams (
                            pid INTEGER NOT NULL,
                            process_name TEXT NOT NULL,
                            source_dataset TEXT NOT NULL,
                            syscall_1 INTEGER NOT NULL,
                            syscall_2 INTEGER NOT NULL,
                            syscall_3 INTEGER NOT NULL,
                            frequency INTEGER NOT NULL DEFAULT 0,
                            suspicious_count INTEGER NOT NULL DEFAULT 0,
                            PRIMARY KEY (pid, process_name, source_dataset, syscall_1, syscall_2, syscall_3)
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_pngram_lookup ON process_ngrams(pid, process_name, frequency DESC);")

                    # 5. Process Activity Timeline Slices Table (Stage 21)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS process_timeline (
                            pid INTEGER NOT NULL,
                            process_name TEXT NOT NULL,
                            source_dataset TEXT NOT NULL,
                            time_bucket INTEGER NOT NULL,
                            normal_count INTEGER NOT NULL DEFAULT 0,
                            suspicious_count INTEGER NOT NULL DEFAULT 0,
                            PRIMARY KEY (pid, process_name, source_dataset, time_bucket)
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_ptimeline_lookup ON process_timeline(pid, process_name, time_bucket ASC);")

                    # 6. Process Recent Syscall Sequences Buffer (Stage 21)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS process_recent_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            pid INTEGER NOT NULL,
                            process_name TEXT NOT NULL,
                            source_dataset TEXT NOT NULL,
                            event_timestamp INTEGER NOT NULL,
                            syscall_1 INTEGER NOT NULL,
                            syscall_2 INTEGER NOT NULL,
                            syscall_3 INTEGER NOT NULL,
                            anomaly_score REAL NOT NULL,
                            is_suspicious INTEGER NOT NULL
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_prec_ev_lookup ON process_recent_events(pid, process_name, id DESC);")
            finally:
                conn.close()

    def _backfill_severity(self, conn: sqlite3.Connection) -> int:
        """
        Idempotently backfills severity classification for any existing alerts
        where severity_reason is empty or severity_rule is DEFAULT_CLASSIFICATION.
        Preserves incident_status, investigation_notes, created_at, last_updated,
        anomaly_score, and all event metadata.
        """
        cur = conn.cursor()
        cur.execute("""
            SELECT alert_id, syscall_1, syscall_2, syscall_3, anomaly_score, process_name
            FROM alerts
            WHERE severity_reason = '' OR severity_rule = 'DEFAULT_CLASSIFICATION'
        """)
        rows = cur.fetchall()
        if not rows:
            return 0

        updated_count = 0
        for r in rows:
            c = classify_severity(
                r["syscall_1"],
                r["syscall_2"],
                r["syscall_3"],
                r["anomaly_score"],
                r["process_name"]
            )
            cur.execute("""
                UPDATE alerts
                SET severity = ?, severity_rule = ?, severity_reason = ?, severity_rule_version = ?
                WHERE alert_id = ?
            """, (c.severity, c.rule_id, c.reason, c.rule_version, r["alert_id"]))
            updated_count += 1
        return updated_count

    # ==========================================================================
    # STAGE 20: ALERT MANAGEMENT METHODS
    # ==========================================================================

    def insert_alert(self, alert: Dict[str, Any]) -> Optional[int]:
        """
        Insert an anomaly alert into the database using parameterized SQL.
        If an alert with identical source file identity and byte offset exists,
        it is ignored to preserve any existing investigation notes and status.
        """
        status = alert.get("incident_status", "NEW")
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid incident_status '{status}'. Must be one of {VALID_STATUSES}")

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        created_at = alert.get("created_at") or now_str
        last_updated = alert.get("last_updated") or now_str
        record_offset = alert.get("record_offset")
        file_sig = alert.get("file_signature", "")

        # Stage 22: Severity Classification
        if "severity" in alert and "severity_rule" in alert and alert.get("severity_reason"):
            sev = str(alert["severity"])
            sev_rule = str(alert["severity_rule"])
            sev_reason = str(alert["severity_reason"])
            sev_ver = str(alert.get("severity_rule_version", RULE_ENGINE_VERSION))
        else:
            c = classify_severity(
                alert["syscall_1"],
                alert["syscall_2"],
                alert["syscall_3"],
                alert["anomaly_score"],
                alert.get("process_name")
            )
            sev = c.severity
            sev_rule = c.rule_id
            sev_reason = c.reason
            sev_ver = c.rule_version

        sql = """
            INSERT OR IGNORE INTO alerts (
                event_timestamp, pid, process_name,
                syscall_1, syscall_2, syscall_3,
                anomaly_score, explanation,
                incident_status, investigation_notes,
                source_dataset, record_offset, file_signature,
                created_at, last_updated,
                severity, severity_rule, severity_reason, severity_rule_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            int(alert["event_timestamp"]),
            int(alert["pid"]),
            str(alert["process_name"]),
            int(alert["syscall_1"]),
            int(alert["syscall_2"]),
            int(alert["syscall_3"]),
            round(float(alert["anomaly_score"]), 4),
            str(alert["explanation"]),
            status,
            str(alert.get("investigation_notes", "")),
            str(alert["source_dataset"]),
            record_offset,
            file_sig,
            created_at,
            last_updated,
            sev,
            sev_rule,
            sev_reason,
            sev_ver
        )

        with self.lock:
            conn = self.get_connection()
            try:
                with conn:
                    cur = conn.cursor()
                    cur.execute(sql, params)
                    if cur.rowcount > 0:
                        return cur.lastrowid
                    return None
            finally:
                conn.close()

    def ingest_batch(self, alerts: List[Dict[str, Any]], checkpoint: Optional[Dict[str, Any]] = None) -> int:
        """
        Transactionally insert a batch of anomaly alerts and optionally update
        the ingestion checkpoint in a single atomic transaction.
        """
        if not alerts and not checkpoint:
            return 0

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        inserted_count = 0

        with self.lock:
            conn = self.get_connection()
            try:
                with conn:
                    cur = conn.cursor()
                    insert_sql = """
                        INSERT OR IGNORE INTO alerts (
                            event_timestamp, pid, process_name,
                            syscall_1, syscall_2, syscall_3,
                            anomaly_score, explanation,
                            incident_status, investigation_notes,
                            source_dataset, record_offset, file_signature,
                            created_at, last_updated,
                            severity, severity_rule, severity_reason, severity_rule_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                    for a in alerts:
                        status = a.get("incident_status", "NEW")
                        if status not in VALID_STATUSES:
                            status = "NEW"

                        if "severity" in a and "severity_rule" in a and a.get("severity_reason"):
                            sev = str(a["severity"])
                            sev_rule = str(a["severity_rule"])
                            sev_reason = str(a["severity_reason"])
                            sev_ver = str(a.get("severity_rule_version", RULE_ENGINE_VERSION))
                        else:
                            c = classify_severity(
                                a["syscall_1"],
                                a["syscall_2"],
                                a["syscall_3"],
                                a["anomaly_score"],
                                a.get("process_name")
                            )
                            sev = c.severity
                            sev_rule = c.rule_id
                            sev_reason = c.reason
                            sev_ver = c.rule_version

                        params = (
                            int(a["event_timestamp"]),
                            int(a["pid"]),
                            str(a["process_name"]),
                            int(a["syscall_1"]),
                            int(a["syscall_2"]),
                            int(a["syscall_3"]),
                            round(float(a["anomaly_score"]), 4),
                            str(a["explanation"]),
                            status,
                            str(a.get("investigation_notes", "")),
                            str(a["source_dataset"]),
                            a.get("record_offset"),
                            str(a.get("file_signature", "")),
                            a.get("created_at") or now_str,
                            a.get("last_updated") or now_str,
                            sev,
                            sev_rule,
                            sev_reason,
                            sev_ver
                        )
                        cur.execute(insert_sql, params)
                        if cur.rowcount > 0:
                            inserted_count += 1

                    if checkpoint:
                        cp_sql = """
                            INSERT OR REPLACE INTO ingestion_checkpoints (
                                source_dataset, file_signature,
                                last_byte_offset, last_line_number,
                                last_event_timestamp, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        """
                        cur.execute(cp_sql, (
                            str(checkpoint["source_dataset"]),
                            str(checkpoint.get("file_signature", "")),
                            int(checkpoint.get("last_byte_offset", 0)),
                            int(checkpoint.get("last_line_number", 0)),
                            int(checkpoint.get("last_event_timestamp", 0)),
                            now_str
                        ))
            finally:
                conn.close()

        return inserted_count

    def get_checkpoint(self, source_dataset: str) -> Optional[Dict[str, Any]]:
        """Retrieve the ingestion checkpoint for a specific dataset."""
        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT * FROM ingestion_checkpoints WHERE source_dataset = ?",
                    (source_dataset,)
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve full details of an individual alert by its unique alert_id."""
        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
                row = cur.fetchone()
                if not row:
                    return None
                r = dict(row)
                r["sequence_str"] = format_syscall_seq(r["syscall_1"], r["syscall_2"], r["syscall_3"])
                return r
            finally:
                conn.close()

    def update_status(self, alert_id: int, new_status: str) -> Optional[Dict[str, Any]]:
        """Update incident status and refresh last_updated timestamp."""
        if new_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {VALID_STATUSES}")

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        with self.lock:
            conn = self.get_connection()
            try:
                with conn:
                    cur = conn.cursor()
                    cur.execute("""
                        UPDATE alerts
                        SET incident_status = ?, last_updated = ?
                        WHERE alert_id = ?
                    """, (new_status, now_str, alert_id))
                    if cur.rowcount == 0:
                        return None
                cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def update_notes(self, alert_id: int, notes: str) -> Optional[Dict[str, Any]]:
        """Update investigation notes for an alert and refresh last_updated timestamp."""
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        with self.lock:
            conn = self.get_connection()
            try:
                with conn:
                    cur = conn.cursor()
                    cur.execute("""
                        UPDATE alerts
                        SET investigation_notes = ?, last_updated = ?
                        WHERE alert_id = ?
                    """, (str(notes), now_str, alert_id))
                    if cur.rowcount == 0:
                        return None
                cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, int]:
        """Retrieve aggregate incident-management and severity statistics."""
        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN incident_status = 'NEW' THEN 1 ELSE 0 END) AS count_new,
                        SUM(CASE WHEN incident_status = 'INVESTIGATING' THEN 1 ELSE 0 END) AS count_investigating,
                        SUM(CASE WHEN incident_status = 'RESOLVED' THEN 1 ELSE 0 END) AS count_resolved,
                        SUM(CASE WHEN incident_status = 'FALSE_ALARM' THEN 1 ELSE 0 END) AS count_false_alarm,
                        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS count_critical,
                        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS count_high,
                        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS count_medium,
                        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS count_low,
                        SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') AND incident_status IN ('NEW', 'INVESTIGATING') THEN 1 ELSE 0 END) AS count_unresolved_high
                    FROM alerts
                """)
                row = cur.fetchone()
                if row:
                    return {
                        "total_alerts": row["total"] or 0,
                        "new_alerts": row["count_new"] or 0,
                        "investigating_alerts": row["count_investigating"] or 0,
                        "resolved_alerts": row["count_resolved"] or 0,
                        "false_alarms": row["count_false_alarm"] or 0,
                        "critical_alerts": row["count_critical"] or 0,
                        "high_alerts": row["count_high"] or 0,
                        "medium_alerts": row["count_medium"] or 0,
                        "low_alerts": row["count_low"] or 0,
                        "unresolved_high_priority": row["count_unresolved_high"] or 0
                    }
                return {
                    "total_alerts": 0, "new_alerts": 0, "investigating_alerts": 0,
                    "resolved_alerts": 0, "false_alarms": 0,
                    "critical_alerts": 0, "high_alerts": 0, "medium_alerts": 0, "low_alerts": 0,
                    "unresolved_high_priority": 0
                }
            finally:
                conn.close()

    def get_triage_stats(self) -> Dict[str, Any]:
        """Retrieve security triage summary including severity breakdown and top flagged processes."""
        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT
                        COUNT(*) AS total_alerts,
                        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS count_critical,
                        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS count_high,
                        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS count_medium,
                        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS count_low,
                        SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') AND incident_status IN ('NEW', 'INVESTIGATING') THEN 1 ELSE 0 END) AS unresolved_high
                    FROM alerts
                """)
                row = cur.fetchone()
                stats = {
                    "total_alerts": (row["total_alerts"] if row else 0) or 0,
                    "critical_alerts": (row["count_critical"] if row else 0) or 0,
                    "high_alerts": (row["count_high"] if row else 0) or 0,
                    "medium_alerts": (row["count_medium"] if row else 0) or 0,
                    "low_alerts": (row["count_low"] if row else 0) or 0,
                    "unresolved_high_priority": (row["unresolved_high"] if row else 0) or 0,
                }

                # Top flagged processes with unresolved high-priority alerts
                cur.execute("""
                    SELECT process_name,
                           COUNT(*) AS unresolved_count,
                           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
                           SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count
                    FROM alerts
                    WHERE severity IN ('CRITICAL', 'HIGH')
                      AND incident_status IN ('NEW', 'INVESTIGATING')
                    GROUP BY process_name
                    ORDER BY unresolved_count DESC, process_name ASC
                    LIMIT 5
                """)
                proc_rows = [dict(r) for r in cur.fetchall()]
                stats["top_flagged_processes"] = proc_rows
                return stats
            finally:
                conn.close()

    def get_alerts_paginated(
        self,
        page: int = 1,
        limit: int = 25,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        incident_status: Optional[str] = None,
        severity: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        start_time: Optional[Any] = None,
        end_time: Optional[Any] = None,
        sort_by: Optional[str] = None,
        order: str = "desc"
    ) -> Dict[str, Any]:
        """Query alerts with server-side filtering, parameterized queries, and pagination."""
        page = max(1, int(page))
        limit = max(1, min(200, int(limit)))
        offset = (page - 1) * limit
        order_dir = "ASC" if str(order).lower() == "asc" else "DESC"

        where_clauses = []
        params = []

        if process_name:
            clean_proc = process_name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where_clauses.append("process_name LIKE ? ESCAPE '\\'")
            params.append(f"%{clean_proc}%")

        if pid is not None:
            where_clauses.append("pid = ?")
            params.append(int(pid))

        if incident_status and incident_status in VALID_STATUSES:
            where_clauses.append("incident_status = ?")
            params.append(incident_status)

        if severity and str(severity).upper() in VALID_SEVERITIES:
            where_clauses.append("severity = ?")
            params.append(str(severity).upper())

        if min_score is not None:
            where_clauses.append("anomaly_score >= ?")
            params.append(float(min_score))

        if max_score is not None:
            where_clauses.append("anomaly_score <= ?")
            params.append(float(max_score))

        if start_time is not None:
            try:
                st_val = int(start_time)
                where_clauses.append("event_timestamp >= ?")
                params.append(st_val)
            except ValueError:
                where_clauses.append("created_at >= ?")
                params.append(str(start_time))

        if end_time is not None:
            try:
                et_val = int(end_time)
                where_clauses.append("event_timestamp <= ?")
                params.append(et_val)
            except ValueError:
                where_clauses.append("created_at <= ?")
                params.append(str(end_time))

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        if sort_by == "severity":
            if order_dir == "ASC":
                order_sql = "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END ASC, event_timestamp DESC"
            else:
                order_sql = "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END DESC, event_timestamp DESC"
        elif sort_by == "score":
            order_sql = f"anomaly_score {order_dir}, event_timestamp DESC"
        else:
            order_sql = f"event_timestamp {order_dir}, alert_id {order_dir}"

        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                count_query = f"SELECT COUNT(*) FROM alerts {where_sql}"
                cur.execute(count_query, params)
                total_count = cur.fetchone()[0]

                data_query = f"""
                    SELECT * FROM alerts
                    {where_sql}
                    ORDER BY {order_sql}
                    LIMIT ? OFFSET ?
                """
                cur.execute(data_query, params + [limit, offset])
                rows = [dict(r) for r in cur.fetchall()]

                for r in rows:
                    r["sequence_str"] = format_syscall_seq(r["syscall_1"], r["syscall_2"], r["syscall_3"])

                total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1

                return {
                    "alerts": rows,
                    "total": total_count,
                    "page": page,
                    "limit": limit,
                    "total_pages": total_pages
                }
            finally:
                conn.close()

    def export_filtered_rows(
        self,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        incident_status: Optional[str] = None,
        severity: Optional[str] = None,
        min_score: Optional[float] = None,
        sort_by: Optional[str] = None,
        order: str = "desc",
        max_rows: int = 50000
    ) -> List[Dict[str, Any]]:
        """Fetch filtered alerts for CSV export up to max_rows."""
        res = self.get_alerts_paginated(
            page=1,
            limit=max_rows,
            process_name=process_name,
            pid=pid,
            incident_status=incident_status,
            severity=severity,
            min_score=min_score,
            sort_by=sort_by,
            order=order
        )
        return res["alerts"]

    # ==========================================================================
    # STAGE 21: PROCESS-WISE MONITORING & BEHAVIORAL ANALYTICS
    # ==========================================================================

    def has_process_data(self, source_dataset: str) -> bool:
        """Check if process summary records exist for the specified dataset."""
        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT 1 FROM process_summary WHERE source_dataset = ? LIMIT 1",
                    (source_dataset,)
                )
                return cur.fetchone() is not None
            finally:
                conn.close()

    def ingest_process_batch(
        self,
        proc_batch: Dict[Tuple[int, str], Dict[str, Any]],
        recent_events_batch: List[Dict[str, Any]],
        source_dataset: str
    ) -> None:
        """
        Incrementally and transactionally update process aggregates, n-grams,
        timelines, and recent events buffer with bounded memory usage.
        """
        if not proc_batch and not recent_events_batch:
            return

        now_sec = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        with self.lock:
            conn = self.get_connection()
            try:
                with conn:
                    cur = conn.cursor()

                    # 1. Update Process Summary using UPSERT
                    summary_upsert = """
                        INSERT INTO process_summary (
                            pid, process_name, source_dataset,
                            total_events, normal_events, suspicious_events,
                            max_score, first_timestamp, last_timestamp, last_seen_epoch
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(pid, process_name, source_dataset) DO UPDATE SET
                            total_events = total_events + excluded.total_events,
                            normal_events = normal_events + excluded.normal_events,
                            suspicious_events = suspicious_events + excluded.suspicious_events,
                            max_score = MAX(max_score, excluded.max_score),
                            first_timestamp = MIN(first_timestamp, excluded.first_timestamp),
                            last_timestamp = MAX(last_timestamp, excluded.last_timestamp),
                            last_seen_epoch = excluded.last_seen_epoch;
                    """

                    for (pid, proc_name), data in proc_batch.items():
                        cur.execute(summary_upsert, (
                            pid, proc_name, source_dataset,
                            data["total_events"], data["normal_events"], data["suspicious_events"],
                            data["max_score"], data["first_timestamp"], data["last_timestamp"],
                            now_sec
                        ))

                        # 2. Update Process 3-Gram Frequencies
                        ngram_upsert = """
                            INSERT INTO process_ngrams (
                                pid, process_name, source_dataset,
                                syscall_1, syscall_2, syscall_3, frequency, suspicious_count
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(pid, process_name, source_dataset, syscall_1, syscall_2, syscall_3) DO UPDATE SET
                                frequency = frequency + excluded.frequency,
                                suspicious_count = suspicious_count + excluded.suspicious_count;
                        """
                        for (s1, s2, s3, is_susp), count in data.get("ngrams", {}).items():
                            cur.execute(ngram_upsert, (
                                pid, proc_name, source_dataset,
                                s1, s2, s3, count, count if is_susp else 0
                            ))

                        # 3. Update Activity Timeline Slices
                        timeline_upsert = """
                            INSERT INTO process_timeline (
                                pid, process_name, source_dataset,
                                time_bucket, normal_count, suspicious_count
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            ON CONFLICT(pid, process_name, source_dataset, time_bucket) DO UPDATE SET
                                normal_count = normal_count + excluded.normal_count,
                                suspicious_count = suspicious_count + excluded.suspicious_count;
                        """
                        for (bucket, kind), count in data.get("timeline", {}).items():
                            cur.execute(timeline_upsert, (
                                pid, proc_name, source_dataset,
                                bucket,
                                count if kind == "normal" else 0,
                                count if kind == "suspicious" else 0
                            ))

                    # 4. Insert Recent Events (capped ring buffer)
                    if recent_events_batch:
                        # Cap batch to recent 100 to ensure bounded memory
                        bounded_recent = recent_events_batch[-100:]
                        recent_insert = """
                            INSERT INTO process_recent_events (
                                pid, process_name, source_dataset, event_timestamp,
                                syscall_1, syscall_2, syscall_3, anomaly_score, is_suspicious
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """
                        for ev in bounded_recent:
                            cur.execute(recent_insert, (
                                ev["pid"], ev["process_name"], source_dataset,
                                ev["event_timestamp"], ev["syscall_1"], ev["syscall_2"],
                                ev["syscall_3"], ev["anomaly_score"], ev["is_suspicious"]
                            ))

                        # Prune excess events per process if buffer exceeds 100 rows
                        for (pid, proc_name) in proc_batch.keys():
                            cur.execute("""
                                DELETE FROM process_recent_events
                                WHERE pid = ? AND process_name = ? AND source_dataset = ?
                                  AND id NOT IN (
                                      SELECT id FROM process_recent_events
                                      WHERE pid = ? AND process_name = ? AND source_dataset = ?
                                      ORDER BY id DESC LIMIT 100
                                  )
                            """, (pid, proc_name, source_dataset, pid, proc_name, source_dataset))
            finally:
                conn.close()

    def get_processes_paginated(
        self,
        page: int = 1,
        limit: int = 25,
        search: Optional[str] = None,
        pid: Optional[int] = None,
        sort_by: str = "total",
        order: str = "desc"
    ) -> Dict[str, Any]:
        """
        Query process summary with server-side filtering, sorting, pagination,
        and host-verified active process state determination.
        """
        page = max(1, int(page))
        limit = max(1, min(200, int(limit)))
        offset = (page - 1) * limit
        order_dir = "ASC" if str(order).lower() == "asc" else "DESC"

        where_clauses = []
        params = []

        if search:
            clean_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where_clauses.append("process_name LIKE ? ESCAPE '\\'")
            params.append(f"%{clean_search}%")

        if pid is not None:
            where_clauses.append("pid = ?")
            params.append(int(pid))

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Map sort_by parameter safely
        sort_col = "total_events"
        if sort_by == "anomalies":
            sort_col = "suspicious_events"
        elif sort_by == "anomaly_pct":
            sort_col = "(CAST(suspicious_events AS REAL) / MAX(1, total_events))"
        elif sort_by == "latest":
            sort_col = "last_timestamp"

        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                count_query = f"SELECT COUNT(*) FROM process_summary {where_sql}"
                cur.execute(count_query, params)
                total_count = cur.fetchone()[0]

                data_query = f"""
                    SELECT * FROM process_summary
                    {where_sql}
                    ORDER BY {sort_col} {order_dir}, pid ASC
                    LIMIT ? OFFSET ?
                """
                cur.execute(data_query, params + [limit, offset])
                rows = [dict(r) for r in cur.fetchall()]

                # Enrich with host verified active status and anomaly percentage
                enriched = []
                for r in rows:
                    tot = r["total_events"]
                    susp = r["suspicious_events"]
                    rate = round((susp / tot * 100.0), 2) if tot > 0 else 0.0
                    is_active = is_process_running_on_host(r["pid"], r["process_name"])

                    enriched.append({
                        "pid": r["pid"],
                        "process_name": r["process_name"],
                        "source_dataset": r["source_dataset"],
                        "total_events": tot,
                        "normal_events": r["normal_events"],
                        "suspicious_events": susp,
                        "anomaly_percentage": rate,
                        "max_score": round(r["max_score"], 4),
                        "first_timestamp": r["first_timestamp"],
                        "last_timestamp": r["last_timestamp"],
                        "is_active": is_active,
                        "status": "ACTIVE" if is_active else "TERMINATED"
                    })

                total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1

                return {
                    "processes": enriched,
                    "total": total_count,
                    "page": page,
                    "limit": limit,
                    "total_pages": total_pages
                }
            finally:
                conn.close()

    def get_process_detail(self, pid: int, process_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve complete summary metrics for an individual process instance."""
        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                if process_name:
                    cur.execute(
                        "SELECT * FROM process_summary WHERE pid = ? AND process_name = ? ORDER BY last_timestamp DESC LIMIT 1",
                        (int(pid), str(process_name))
                    )
                else:
                    cur.execute(
                        "SELECT * FROM process_summary WHERE pid = ? ORDER BY last_timestamp DESC LIMIT 1",
                        (int(pid),)
                    )
                row = cur.fetchone()
                if not row:
                    return None

                r = dict(row)
                tot = r["total_events"]
                susp = r["suspicious_events"]
                rate = round((susp / tot * 100.0), 2) if tot > 0 else 0.0
                is_active = is_process_running_on_host(r["pid"], r["process_name"])

                return {
                    "pid": r["pid"],
                    "process_name": r["process_name"],
                    "source_dataset": r["source_dataset"],
                    "total_events": tot,
                    "normal_events": r["normal_events"],
                    "suspicious_events": susp,
                    "anomaly_percentage": rate,
                    "max_score": round(r["max_score"], 4),
                    "first_timestamp": r["first_timestamp"],
                    "last_timestamp": r["last_timestamp"],
                    "is_active": is_active,
                    "status": "ACTIVE" if is_active else "TERMINATED"
                }
            finally:
                conn.close()

    def get_process_recent_events(
        self,
        pid: int,
        process_name: Optional[str] = None,
        limit: int = 50,
        suspicious_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Retrieve recent syscall 3-gram sequences for the specified process."""
        limit = max(1, min(200, int(limit)))
        where_clauses = ["pid = ?"]
        params = [int(pid)]

        if process_name:
            where_clauses.append("process_name = ?")
            params.append(str(process_name))

        if suspicious_only:
            where_clauses.append("is_suspicious = 1")

        where_sql = "WHERE " + " AND ".join(where_clauses)

        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                query = f"""
                    SELECT * FROM process_recent_events
                    {where_sql}
                    ORDER BY id DESC
                    LIMIT ?
                """
                cur.execute(query, params + [limit])
                rows = [dict(r) for r in cur.fetchall()]

                for r in rows:
                    r["sequence_str"] = format_syscall_seq(r["syscall_1"], r["syscall_2"], r["syscall_3"])
                    r["is_suspicious"] = bool(r["is_suspicious"])
                return rows
            finally:
                conn.close()

    def get_process_alerts(
        self,
        pid: int,
        process_name: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve persistent anomaly alerts for the specified process."""
        limit = max(1, min(200, int(limit)))
        where_clauses = ["pid = ?"]
        params = [int(pid)]

        if process_name:
            where_clauses.append("process_name = ?")
            params.append(str(process_name))

        where_sql = "WHERE " + " AND ".join(where_clauses)

        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                query = f"""
                    SELECT * FROM alerts
                    {where_sql}
                    ORDER BY event_timestamp DESC, alert_id DESC
                    LIMIT ?
                """
                cur.execute(query, params + [limit])
                rows = [dict(r) for r in cur.fetchall()]

                for r in rows:
                    r["sequence_str"] = format_syscall_seq(r["syscall_1"], r["syscall_2"], r["syscall_3"])
                return rows
            finally:
                conn.close()

    def get_process_top_ngrams(
        self,
        pid: int,
        process_name: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Retrieve the most frequent syscall 3-grams for the specified process."""
        limit = max(1, min(50, int(limit)))
        where_clauses = ["pid = ?"]
        params = [int(pid)]

        if process_name:
            where_clauses.append("process_name = ?")
            params.append(str(process_name))

        where_sql = "WHERE " + " AND ".join(where_clauses)

        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                query = f"""
                    SELECT syscall_1, syscall_2, syscall_3, frequency, suspicious_count
                    FROM process_ngrams
                    {where_sql}
                    ORDER BY frequency DESC
                    LIMIT ?
                """
                cur.execute(query, params + [limit])
                rows = [dict(r) for r in cur.fetchall()]

                for r in rows:
                    r["sequence_str"] = format_syscall_seq(r["syscall_1"], r["syscall_2"], r["syscall_3"])
                return rows
            finally:
                conn.close()

    def get_process_timeline(
        self,
        pid: int,
        process_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve aggregated activity timeline buckets for the specified process."""
        where_clauses = ["pid = ?"]
        params = [int(pid)]

        if process_name:
            where_clauses.append("process_name = ?")
            params.append(str(process_name))

        where_sql = "WHERE " + " AND ".join(where_clauses)

        with self.lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                query = f"""
                    SELECT time_bucket, normal_count, suspicious_count
                    FROM process_timeline
                    {where_sql}
                    ORDER BY time_bucket ASC
                """
                cur.execute(query, params)
                rows = [dict(r) for r in cur.fetchall()]

                res = []
                for r in rows:
                    res.append({
                        "time_bucket": r["time_bucket"],
                        "normal": r["normal_count"],
                        "suspicious": r["suspicious_count"],
                        "total": r["normal_count"] + r["suspicious_count"]
                    })
                return res
            finally:
                conn.close()
