"""
WALLRUS - Logger

Dual-sink logging:
  1. JSON log file  → logs/wallrus_YYYYMMDD.json  (one JSON object per line)
  2. SQLite DB      → logs/wallrus.db              (queryable history)

Each log entry carries a UUID request_id for correlation between sinks.
Phase 2 anomaly scores are written to both sinks when available.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from wallrus.core.parser import HTTPRequest
from wallrus.core.engine import ScanResult


# ── Default log directory ──────────────────────────────────────────────────────
DEFAULT_LOG_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "logs"


class WAFLogger:
    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._json_path = self.log_dir / f"wallrus_{datetime.now():%Y%m%d}.json"
        self._db_path   = self.log_dir / "wallrus.db"

        self._init_db()

    # ── Public API ────────────────────────────────────────────────────────────
    def log(self, request: HTTPRequest, result: ScanResult) -> str:
        """
        Persist a scan event. Returns the generated request_id UUID string.
        """
        request_id = str(uuid.uuid4())
        result.request_id = request_id
        ts = datetime.utcnow().isoformat() + "Z"

        entry = self._build_entry(request, result, request_id, ts)

        self._write_json(entry)
        self._write_db(entry)

        return request_id

    def get_recent(self, limit: int = 20) -> list:
        """Return the most recent `limit` scan records from SQLite."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        cur  = conn.cursor()
        cur.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def get_stats(self) -> dict:
        """Return aggregate statistics from the SQLite database."""
        conn = sqlite3.connect(self._db_path)
        cur  = conn.cursor()

        stats = {}
        cur.execute("SELECT COUNT(*) FROM scans")
        stats["total_scans"] = cur.fetchone()[0]

        for verdict in ("BLOCKED", "FLAGGED", "CLEAN"):
            cur.execute("SELECT COUNT(*) FROM scans WHERE verdict=?", (verdict,))
            stats[verdict.lower()] = cur.fetchone()[0]

        cur.execute(
            "SELECT rule_id, COUNT(*) as cnt FROM matches "
            "GROUP BY rule_id ORDER BY cnt DESC LIMIT 5"
        )
        stats["top_rules"] = [{"rule": r[0], "count": r[1]}
                               for r in cur.fetchall()]
        conn.close()
        return stats

    # ── Private helpers ───────────────────────────────────────────────────────
    @staticmethod
    def _build_entry(request: HTTPRequest, result: ScanResult,
                     request_id: str, ts: str) -> dict:
        return {
            "request_id":    request_id,
            "timestamp":     ts,
            "verdict":       result.verdict,
            "risk_score":    result.risk_score,
            "scan_time_ms":  result.scan_time_ms,
            "anomaly_score": result.anomaly_score,
            "request": {
                "method":  request.method.value,
                "host":    request.host,
                "path":    request.path,
                "query":   request.query_string,
                "body":    request.body[:500] if request.body else "",
            },
            "matches": [
                {
                    "rule_id":     m.rule_id,
                    "rule_name":   m.rule_name,
                    "owasp":       m.owasp,
                    "severity":    m.severity,
                    "target":      m.target,
                    "matched":     m.matched_text,
                }
                for m in result.matches
            ],
        }

    def _write_json(self, entry: dict) -> None:
        with open(self._json_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _write_db(self, entry: dict) -> None:
        conn = sqlite3.connect(self._db_path)
        cur  = conn.cursor()

        cur.execute(
            """INSERT INTO scans
               (request_id, timestamp, verdict, risk_score, scan_time_ms,
                anomaly_score, method, host, path, query, body)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                entry["request_id"],
                entry["timestamp"],
                entry["verdict"],
                entry["risk_score"],
                entry["scan_time_ms"],
                entry["anomaly_score"],
                entry["request"]["method"],
                entry["request"]["host"],
                entry["request"]["path"],
                entry["request"]["query"],
                entry["request"]["body"],
            )
        )

        for m in entry["matches"]:
            cur.execute(
                """INSERT INTO matches
                   (request_id, rule_id, rule_name, owasp, severity, target, matched)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    entry["request_id"],
                    m["rule_id"], m["rule_name"],
                    m["owasp"],   m["severity"],
                    m["target"],  m["matched"],
                )
            )

        conn.commit()
        conn.close()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        cur  = conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id    TEXT NOT NULL,
                timestamp     TEXT NOT NULL,
                verdict       TEXT NOT NULL,
                risk_score    INTEGER,
                scan_time_ms  REAL,
                anomaly_score REAL,
                method        TEXT,
                host          TEXT,
                path          TEXT,
                query         TEXT,
                body          TEXT
            );
            CREATE TABLE IF NOT EXISTS matches (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id  TEXT NOT NULL,
                rule_id     TEXT,
                rule_name   TEXT,
                owasp       TEXT,
                severity    TEXT,
                target      TEXT,
                matched     TEXT
            );
        """)
        conn.commit()
        conn.close()
