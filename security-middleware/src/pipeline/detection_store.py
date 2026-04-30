"""
Detection Alert Store.

Persists detection alerts to a local SQLite database for query,
acknowledgment, and lifecycle management via the REST API.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
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
    redmine_issue_id INTEGER,
    redmine_issue_exists INTEGER,
    redmine_issue_status TEXT,
    redmine_checked_at TEXT,
    created_epoch REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detection_triggered_at ON detection_alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_detection_severity ON detection_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_detection_rule_type ON detection_alerts(rule_type);

CREATE TABLE IF NOT EXISTS detection_events (
    id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    group_key TEXT NOT NULL,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    event_epoch REAL NOT NULL,
    event_data TEXT NOT NULL DEFAULT '{}',
    created_epoch REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detection_events_rule_group_epoch
    ON detection_events(rule_name, group_key, event_epoch);

CREATE TABLE IF NOT EXISTS wazuh_events (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    event_epoch REAL NOT NULL,
    finding_json TEXT NOT NULL DEFAULT '{}',
    created_epoch REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wazuh_events_event_epoch ON wazuh_events(event_epoch);

CREATE TABLE IF NOT EXISTS detection_cooldowns (
    rule_name TEXT NOT NULL,
    cooldown_key TEXT NOT NULL,
    triggered_epoch REAL NOT NULL,
    PRIMARY KEY (rule_name, cooldown_key)
);
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
        self._migrate_schema()
        self._conn.commit()
        logger.info("Detection alert store initialized at %s", db_path)

    def _migrate_schema(self) -> None:
        """Apply additive migrations for existing SQLite databases."""
        if not self._conn:
            return

        cursor = self._conn.execute("PRAGMA table_info(detection_alerts)")
        existing = {row["name"] for row in cursor.fetchall()}
        migrations = {
            "redmine_issue_id": "ALTER TABLE detection_alerts ADD COLUMN redmine_issue_id INTEGER",
            "redmine_issue_exists": "ALTER TABLE detection_alerts ADD COLUMN redmine_issue_exists INTEGER",
            "redmine_issue_status": "ALTER TABLE detection_alerts ADD COLUMN redmine_issue_status TEXT",
            "redmine_checked_at": "ALTER TABLE detection_alerts ADD COLUMN redmine_checked_at TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing:
                self._conn.execute(statement)

        # Create detection_cooldowns if it doesn't exist (it's in _SCHEMA but need to handle old DBs safely)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_cooldowns (
                rule_name TEXT NOT NULL,
                cooldown_key TEXT NOT NULL,
                triggered_epoch REAL NOT NULL,
                PRIMARY KEY (rule_name, cooldown_key)
            )
        """)

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
             triggered_at, acknowledged, resolved, create_ticket, redmine_issue_status, created_epoch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "ticket_pending" if alert.create_ticket else "ticket_disabled",
                time.time(),
            ),
        )
        self._conn.commit()
        logger.info(
            "Detection: alert persisted — rule='%s' severity=%s id=%s",
            alert.rule_name, alert.severity, alert.id,
        )

    def update_redmine_issue(
        self,
        alert_id: str,
        *,
        issue_id: int | None,
        exists: bool | None,
        status: str | None,
        resolved: bool | None = None,
    ) -> bool:
        """Update Redmine linkage/status for a detection alert."""
        if not self._conn:
            return False

        assignments = [
            "redmine_issue_id = ?",
            "redmine_issue_exists = ?",
            "redmine_issue_status = ?",
            "redmine_checked_at = ?",
        ]
        params: list[Any] = [
            issue_id,
            None if exists is None else int(exists),
            status,
            datetime.now(timezone.utc).isoformat(),
        ]
        if resolved is not None:
            assignments.extend(["resolved = ?", "acknowledged = ?"])
            params.extend([int(resolved), int(resolved)])

        params.append(alert_id)
        cursor = self._conn.execute(
            f"UPDATE detection_alerts SET {', '.join(assignments)} WHERE id = ?",
            params,
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def save_rule_event(
        self,
        *,
        rule_name: str,
        rule_type: str,
        group_key: str,
        event_epoch: float,
        finding: Any,
        event_data: dict[str, Any],
    ) -> None:
        """Persist a source event that contributed to a detection rule window."""
        if not self._conn:
            return

        source = getattr(getattr(finding, "source", None), "value", str(getattr(finding, "source", "")))
        source_id = str(getattr(finding, "source_id", ""))
        event_fingerprint = hashlib.sha256(
            json.dumps(event_data, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        event_id = f"{rule_name}:{source}:{source_id}:{float(event_epoch):.6f}:{event_fingerprint}"
        self._conn.execute(
            """
            INSERT OR IGNORE INTO detection_events
            (id, rule_name, rule_type, group_key, source, source_id, event_epoch, event_data, created_epoch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                rule_name,
                rule_type,
                group_key,
                source,
                source_id,
                float(event_epoch),
                json.dumps(event_data, default=str),
                time.time(),
            ),
        )
        self._conn.commit()

    def save_wazuh_event(self, finding: Any) -> None:
        """Persist the raw normalized Wazuh alert received from the webhook."""
        if not self._conn:
            return

        source_id = str(getattr(finding, "source_id", ""))
        event_id = f"wazuh:{source_id}"
        event_epoch = float(getattr(finding, "timestamp").timestamp())
        payload = finding.to_dict() if hasattr(finding, "to_dict") else {}
        self._conn.execute(
            """
            INSERT OR IGNORE INTO wazuh_events
            (id, source_id, event_epoch, finding_json, created_epoch)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event_id,
                source_id,
                event_epoch,
                json.dumps(payload, default=str),
                time.time(),
            ),
        )
        self._conn.commit()

    def count_wazuh_events(self) -> int:
        """Count stored raw Wazuh webhook events."""
        if not self._conn:
            return 0

        cursor = self._conn.execute("SELECT COUNT(*) FROM wazuh_events")
        return int(cursor.fetchone()[0])

    def count_rule_events(self, rule_name: str, group_key: str, start_epoch: float, end_epoch: float) -> int:
        """Count source events for a rule/group inside a time window."""
        if not self._conn:
            return 0

        cursor = self._conn.execute(
            """
            SELECT COUNT(*)
            FROM detection_events
            WHERE rule_name = ?
              AND group_key = ?
              AND event_epoch >= ?
              AND event_epoch <= ?
            """,
            (rule_name, group_key, float(start_epoch), float(end_epoch)),
        )
        return int(cursor.fetchone()[0])

    def get_rule_events(
        self,
        rule_name: str,
        group_key: str,
        start_epoch: float,
        end_epoch: float,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return source event payloads for a rule/group inside a time window."""
        if not self._conn:
            return []

        cursor = self._conn.execute(
            """
            SELECT event_data
            FROM detection_events
            WHERE rule_name = ?
              AND group_key = ?
              AND event_epoch >= ?
              AND event_epoch <= ?
            ORDER BY event_epoch DESC
            LIMIT ?
            """,
            (rule_name, group_key, float(start_epoch), float(end_epoch), int(limit)),
        )
        events: list[dict[str, Any]] = []
        for row in cursor.fetchall():
            try:
                events.append(json.loads(row["event_data"]))
            except (json.JSONDecodeError, TypeError):
                events.append({})
        events.reverse()
        return events

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
        event_cursor = self._conn.execute(
            "DELETE FROM detection_events WHERE created_epoch < ?",
            (cutoff,),
        )
        wazuh_cursor = self._conn.execute(
            "DELETE FROM wazuh_events WHERE created_epoch < ?",
            (cutoff,),
        )
        cooldown_cursor = self._conn.execute(
            "DELETE FROM detection_cooldowns WHERE triggered_epoch < ?",
            (cutoff,),
        )
        self._conn.commit()
        count = cursor.rowcount + event_cursor.rowcount + wazuh_cursor.rowcount + cooldown_cursor.rowcount
        if count > 0:
            logger.info("Detection: cleaned up %d expired alerts/events/cooldowns", count)
        return count

    def save_cooldown(self, rule_name: str, cooldown_key: str, triggered_epoch: float) -> None:
        """Persist a rule cooldown state."""
        if not self._conn:
            return

        self._conn.execute(
            """
            INSERT OR REPLACE INTO detection_cooldowns
            (rule_name, cooldown_key, triggered_epoch)
            VALUES (?, ?, ?)
            """,
            (rule_name, cooldown_key, float(triggered_epoch)),
        )
        self._conn.commit()

    def get_cooldown(self, rule_name: str, cooldown_key: str) -> float | None:
        """Retrieve the last triggered epoch for a rule cooldown key."""
        if not self._conn:
            return None

        cursor = self._conn.execute(
            "SELECT triggered_epoch FROM detection_cooldowns WHERE rule_name = ? AND cooldown_key = ?",
            (rule_name, cooldown_key),
        )
        row = cursor.fetchone()
        return float(row["triggered_epoch"]) if row else None

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
        if d.get("redmine_issue_exists") is not None:
            d["redmine_issue_exists"] = bool(d["redmine_issue_exists"])
        return d

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
