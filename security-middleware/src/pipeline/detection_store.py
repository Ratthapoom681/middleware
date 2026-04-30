"""
Detection Alert Store.

Persists detection alerts to a local SQLite database for query,
acknowledgment, and lifecycle management via the REST API.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("detection.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detection_alerts (
    id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '{}',
    source_events TEXT NOT NULL DEFAULT '[]',
    triggered_at TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    resolved INTEGER NOT NULL DEFAULT 0,
    create_ticket INTEGER NOT NULL DEFAULT 0,
    created_epoch REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detection_triggered_at ON detection_alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_detection_severity ON detection_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_detection_rule_type ON detection_alerts(rule_type);
"""


class DetectionAlertStore:
    """SQLite-backed storage for detection alerts."""

    def __init__(self, db_path: str = "data/detection_alerts.db"):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database."""
        db_path = Path(self.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("Detection alert store initialized at %s", db_path)

    def save_alert(self, alert: Any) -> None:
        """Persist a detection alert."""
        if not self._conn:
            return

        evidence_json = json.dumps(alert.evidence, default=str) if isinstance(alert.evidence, dict) else str(alert.evidence)
        events_json = json.dumps(alert.source_events, default=str) if isinstance(alert.source_events, list) else str(alert.source_events)

        self._conn.execute(
            """
            INSERT OR REPLACE INTO detection_alerts
            (id, rule_name, rule_type, severity, description, evidence, source_events,
             triggered_at, acknowledged, resolved, create_ticket, created_epoch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.id,
                alert.rule_name,
                alert.rule_type,
                alert.severity,
                alert.description,
                evidence_json,
                events_json,
                alert.triggered_at,
                int(alert.acknowledged),
                int(alert.resolved),
                int(alert.create_ticket),
                time.time(),
            ),
        )
        self._conn.commit()
        logger.info(
            "Detection: alert persisted — rule='%s' severity=%s id=%s",
            alert.rule_name, alert.severity, alert.id,
        )

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        rule_type: str | None = None,
        severity: str | None = None,
        acknowledged: bool | None = None,
        resolved: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Query detection alerts with optional filters."""
        if not self._conn:
            return []

        conditions = []
        params: list[Any] = []

        if rule_type:
            conditions.append("rule_type = ?")
            params.append(rule_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            conditions.append("acknowledged = ?")
            params.append(int(acknowledged))
        if resolved is not None:
            conditions.append("resolved = ?")
            params.append(int(resolved))

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        cursor = self._conn.execute(
            f"""
            SELECT * FROM detection_alerts
            WHERE {where_clause}
            ORDER BY triggered_at DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )

        rows = cursor.fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        """Get a single alert by ID."""
        if not self._conn:
            return None

        cursor = self._conn.execute(
            "SELECT * FROM detection_alerts WHERE id = ?",
            (alert_id,),
        )
        row = cursor.fetchone()
        return self._row_to_dict(row) if row else None

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        if not self._conn:
            return False

        cursor = self._conn.execute(
            "UPDATE detection_alerts SET acknowledged = 1 WHERE id = ?",
            (alert_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved."""
        if not self._conn:
            return False

        cursor = self._conn.execute(
            "UPDATE detection_alerts SET resolved = 1, acknowledged = 1 WHERE id = ?",
            (alert_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def get_stats(self) -> dict[str, Any]:
        """Get aggregate statistics for detection alerts."""
        if not self._conn:
            return {"total": 0}

        stats: dict[str, Any] = {}

        cursor = self._conn.execute("SELECT COUNT(*) FROM detection_alerts")
        stats["total"] = cursor.fetchone()[0]

        cursor = self._conn.execute("SELECT COUNT(*) FROM detection_alerts WHERE acknowledged = 0 AND resolved = 0")
        stats["active"] = cursor.fetchone()[0]

        cursor = self._conn.execute("SELECT COUNT(*) FROM detection_alerts WHERE acknowledged = 1 AND resolved = 0")
        stats["acknowledged"] = cursor.fetchone()[0]

        cursor = self._conn.execute("SELECT COUNT(*) FROM detection_alerts WHERE resolved = 1")
        stats["resolved"] = cursor.fetchone()[0]

        # By severity
        severity_counts: dict[str, int] = {}
        cursor = self._conn.execute(
            "SELECT severity, COUNT(*) FROM detection_alerts WHERE resolved = 0 GROUP BY severity"
        )
        for row in cursor.fetchall():
            severity_counts[row[0]] = row[1]
        stats["by_severity"] = severity_counts

        # By rule type
        type_counts: dict[str, int] = {}
        cursor = self._conn.execute(
            "SELECT rule_type, COUNT(*) FROM detection_alerts WHERE resolved = 0 GROUP BY rule_type"
        )
        for row in cursor.fetchall():
            type_counts[row[0]] = row[1]
        stats["by_type"] = type_counts

        return stats

    def cleanup_expired(self, ttl_hours: int = 168) -> int:
        """Remove alerts older than the TTL."""
        if not self._conn:
            return 0

        cutoff = time.time() - (ttl_hours * 3600)
        cursor = self._conn.execute(
            "DELETE FROM detection_alerts WHERE created_epoch < ?",
            (cutoff,),
        )
        self._conn.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info("Detection: cleaned up %d expired alerts", count)
        return count

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a SQLite row to a dictionary."""
        d = dict(row)
        # Parse JSON fields
        try:
            d["evidence"] = json.loads(d.get("evidence", "{}"))
        except (json.JSONDecodeError, TypeError):
            d["evidence"] = {}
        try:
            d["source_events"] = json.loads(d.get("source_events", "[]"))
        except (json.JSONDecodeError, TypeError):
            d["source_events"] = []
        d["acknowledged"] = bool(d.get("acknowledged", 0))
        d["resolved"] = bool(d.get("resolved", 0))
        d["create_ticket"] = bool(d.get("create_ticket", 0))
        return d

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
