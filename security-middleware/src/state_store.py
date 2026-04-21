"""
Optional shared state backends for deduplication and checkpoints.

Local mode keeps the existing SQLite + JSON file behavior. Postgres mode
centralizes the dedup registry and incremental checkpoints for higher-volume
deployments and multi-instance safety.
"""

from __future__ import annotations

import importlib
import json
import logging
import re
from typing import Any

from src.config import StorageConfig

logger = logging.getLogger(__name__)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def create_state_store(config: StorageConfig) -> PostgresStateStore | None:
    """Create the configured shared state backend, if any."""
    if config.backend != "postgres":
        return None
    return PostgresStateStore(config)


class PostgresStateStore:
    """Shared Postgres storage for dedup state and checkpoints."""

    def __init__(self, config: StorageConfig, dbapi_module: Any | None = None):
        self.config = config
        self._dbapi = dbapi_module or _load_psycopg_module()
        self._schema = _quote_identifier(config.postgres_schema)
        self._dedup_table = _quote_identifier(config.dedup_table)
        self._checkpoint_table = _quote_identifier(config.checkpoint_table)
        self._ticket_state_table = _quote_identifier(config.ticket_state_table)
        self._outbound_queue_table = _quote_identifier(config.outbound_queue_table)
        self._dashboard_table = _quote_identifier("middleware_dashboard_events")
        self._conn = self._dbapi.connect(config.postgres_dsn)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the shared Postgres schema and tables."""
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema}")
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._schema}.{self._dedup_table} (
                        hash TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        title TEXT NOT NULL,
                        first_seen DOUBLE PRECISION NOT NULL,
                        last_seen DOUBLE PRECISION NOT NULL,
                        count INTEGER DEFAULT 1,
                        flushed_count INTEGER DEFAULT 0,
                        redmine_issue_id INTEGER,
                        issue_state TEXT DEFAULT 'open'
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS {self._dedup_index_name('last_seen')}
                    ON {self._schema}.{self._dedup_table} (last_seen)
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._schema}.{self._checkpoint_table} (
                        checkpoint_key TEXT PRIMARY KEY,
                        signature TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._schema}.{self._ticket_state_table} (
                        dedup_hash TEXT PRIMARY KEY,
                        redmine_issue_id INTEGER,
                        issue_state TEXT DEFAULT 'unknown',
                        tracker_id INTEGER,
                        subject TEXT,
                        ticket_exists BOOLEAN NOT NULL DEFAULT TRUE,
                        last_ticket_check_at TIMESTAMPTZ,
                        last_ticket_seen_at TIMESTAMPTZ,
                        last_delivery_status TEXT,
                        last_error TEXT,
                        payload TEXT NOT NULL DEFAULT '{{}}',
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS {self._ticket_state_index_name('last_ticket_check_at')}
                    ON {self._schema}.{self._ticket_state_table} (last_ticket_check_at)
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._schema}.{self._outbound_queue_table} (
                        job_id TEXT PRIMARY KEY,
                        dedup_hash TEXT NOT NULL,
                        action TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        payload TEXT NOT NULL,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        locked_at TIMESTAMPTZ,
                        locked_by TEXT,
                        last_error TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS {self._outbound_queue_index_name('status_next_attempt_at')}
                    ON {self._schema}.{self._outbound_queue_table} (status, next_attempt_at)
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS {self._outbound_queue_index_name('dedup_hash')}
                    ON {self._schema}.{self._outbound_queue_table} (dedup_hash)
                    """
                )
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._schema}.{self._dashboard_table} (
                        event_id TEXT PRIMARY KEY,
                        receive_time TIMESTAMPTZ NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS {self._dashboard_index_name('receive_time')}
                    ON {self._schema}.{self._dashboard_table} (receive_time DESC)
                    """
                )
        logger.info(
            "Postgres state store initialized (%s.%s / %s.%s / %s.%s / %s.%s / %s.%s)",
            self.config.postgres_schema,
            self.config.dedup_table,
            self.config.postgres_schema,
            self.config.checkpoint_table,
            self.config.postgres_schema,
            self.config.ticket_state_table,
            self.config.postgres_schema,
            self.config.outbound_queue_table,
            self.config.postgres_schema,
            "middleware_dashboard_events",
        )

    def _dedup_index_name(self, suffix: str) -> str:
        """Build a safe, deterministic index name."""
        raw_name = f"{self.config.dedup_table}_{suffix}_idx"
        if len(raw_name) > 60:
            raw_name = raw_name[:60]
        return _quote_identifier(raw_name)

    def _dashboard_index_name(self, suffix: str) -> str:
        """Build a safe dashboard index name."""
        raw_name = f"middleware_dashboard_events_{suffix}_idx"
        if len(raw_name) > 60:
            raw_name = raw_name[:60]
        return _quote_identifier(raw_name)

    def _ticket_state_index_name(self, suffix: str) -> str:
        """Build a safe ticket-state index name."""
        raw_name = f"{self.config.ticket_state_table}_{suffix}_idx"
        if len(raw_name) > 60:
            raw_name = raw_name[:60]
        return _quote_identifier(raw_name)

    def _outbound_queue_index_name(self, suffix: str) -> str:
        """Build a safe outbound-queue index name."""
        raw_name = f"{self.config.outbound_queue_table}_{suffix}_idx"
        if len(raw_name) > 60:
            raw_name = raw_name[:60]
        return _quote_identifier(raw_name)

    def get_recent_hashes(self, hash_values: list[str], cutoff: float) -> dict[str, tuple[int | None, str | None]]:
        """Fetch hashes seen within the TTL window."""
        if not hash_values:
            return {}

        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT hash, redmine_issue_id, issue_state
                FROM {self._schema}.{self._dedup_table}
                WHERE last_seen > %s AND hash = ANY(%s)
                """,
                (cutoff, list(dict.fromkeys(hash_values))),
            )
            return {row[0]: (row[1], row[2]) for row in cur.fetchall()}

    def get_all_hashes(self, hash_values: list[str]) -> set[str]:
        """Fetch hashes that exist regardless of TTL."""
        if not hash_values:
            return set()

        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT hash
                FROM {self._schema}.{self._dedup_table}
                WHERE hash = ANY(%s)
                """,
                (list(dict.fromkeys(hash_values)),),
            )
            return {row[0] for row in cur.fetchall()}

    def commit_new(self, records: list[tuple[Any, ...]]) -> None:
        """Upsert newly created findings after successful Redmine output."""
        if not records:
            return

        with self._conn:
            with self._conn.cursor() as cur:
                cur.executemany(
                    f"""
                    INSERT INTO {self._schema}.{self._dedup_table}
                    (hash, source, title, first_seen, last_seen, count, flushed_count, redmine_issue_id, issue_state)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (hash) DO UPDATE SET
                        source = EXCLUDED.source,
                        title = EXCLUDED.title,
                        first_seen = LEAST({self._schema}.{self._dedup_table}.first_seen, EXCLUDED.first_seen),
                        last_seen = GREATEST({self._schema}.{self._dedup_table}.last_seen, EXCLUDED.last_seen),
                        count = {self._schema}.{self._dedup_table}.count + EXCLUDED.count,
                        flushed_count = {self._schema}.{self._dedup_table}.flushed_count + EXCLUDED.flushed_count,
                        redmine_issue_id = COALESCE({self._schema}.{self._dedup_table}.redmine_issue_id, EXCLUDED.redmine_issue_id),
                        issue_state = EXCLUDED.issue_state
                    """,
                    records,
                )

    def commit_updates(self, records: list[tuple[Any, ...]]) -> None:
        """Persist repeat-finding issue mappings and lifecycle state."""
        if not records:
            return

        with self._conn:
            with self._conn.cursor() as cur:
                cur.executemany(
                    f"""
                    INSERT INTO {self._schema}.{self._dedup_table}
                    (hash, source, title, first_seen, last_seen, count, flushed_count, redmine_issue_id, issue_state)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (hash) DO UPDATE SET
                        redmine_issue_id = EXCLUDED.redmine_issue_id,
                        issue_state = EXCLUDED.issue_state,
                        last_seen = GREATEST({self._schema}.{self._dedup_table}.last_seen, EXCLUDED.last_seen),
                        count = {self._schema}.{self._dedup_table}.count + EXCLUDED.count
                    """,
                    records,
                )

    def cleanup_dedup(self, cutoff: float) -> int:
        """Purge expired dedup entries and return the deleted row count."""
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"DELETE FROM {self._schema}.{self._dedup_table} WHERE last_seen < %s",
                    (cutoff,),
                )
                return cur.rowcount or 0

    def get_dedup_stats(self) -> dict[str, int]:
        """Return simple dedup storage statistics."""
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {self._schema}.{self._dedup_table}")
            row = cur.fetchone()
        return {"total_tracked": int(row[0] if row else 0)}

    def load_checkpoint(self, checkpoint_key: str, expected_signature: str) -> dict[str, Any] | None:
        """Load a checkpoint payload when the signature still matches."""
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT signature, payload
                FROM {self._schema}.{self._checkpoint_table}
                WHERE checkpoint_key = %s
                """,
                (checkpoint_key,),
            )
            row = cur.fetchone()

        if not row:
            return None

        signature, payload = row
        if signature != expected_signature:
            logger.info("Postgres checkpoint signature changed for %s; ignoring stale checkpoint", checkpoint_key)
            return None

        if isinstance(payload, str):
            return json.loads(payload)
        return dict(payload)

    def save_checkpoint(self, checkpoint_key: str, signature: str, payload: dict[str, Any]) -> None:
        """Persist the latest checkpoint state."""
        serialized = json.dumps(payload, sort_keys=True)
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {self._schema}.{self._checkpoint_table}
                    (checkpoint_key, signature, payload, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (checkpoint_key) DO UPDATE SET
                        signature = EXCLUDED.signature,
                        payload = EXCLUDED.payload,
                        updated_at = NOW()
                    """,
                    (checkpoint_key, signature, serialized),
                )

    def save_ticket_state(
        self,
        dedup_hash: str,
        *,
        redmine_issue_id: int | None = None,
        issue_state: str | None = None,
        tracker_id: int | None = None,
        subject: str | None = None,
        ticket_exists: bool = True,
        last_ticket_check_at: str | None = None,
        last_ticket_seen_at: str | None = None,
        last_delivery_status: str | None = None,
        last_error: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Upsert the cached Redmine ticket state for a dedup hash."""
        if not dedup_hash:
            raise ValueError("ticket state requires a non-empty dedup_hash")

        serialized = json.dumps(payload or {}, sort_keys=True)
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {self._schema}.{self._ticket_state_table}
                    (
                        dedup_hash,
                        redmine_issue_id,
                        issue_state,
                        tracker_id,
                        subject,
                        ticket_exists,
                        last_ticket_check_at,
                        last_ticket_seen_at,
                        last_delivery_status,
                        last_error,
                        payload,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (dedup_hash) DO UPDATE SET
                        redmine_issue_id = EXCLUDED.redmine_issue_id,
                        issue_state = EXCLUDED.issue_state,
                        tracker_id = EXCLUDED.tracker_id,
                        subject = EXCLUDED.subject,
                        ticket_exists = EXCLUDED.ticket_exists,
                        last_ticket_check_at = EXCLUDED.last_ticket_check_at,
                        last_ticket_seen_at = EXCLUDED.last_ticket_seen_at,
                        last_delivery_status = EXCLUDED.last_delivery_status,
                        last_error = EXCLUDED.last_error,
                        payload = EXCLUDED.payload,
                        updated_at = NOW()
                    """,
                    (
                        dedup_hash,
                        redmine_issue_id,
                        issue_state or "unknown",
                        tracker_id,
                        subject,
                        ticket_exists,
                        last_ticket_check_at,
                        last_ticket_seen_at,
                        last_delivery_status,
                        last_error,
                        serialized,
                    ),
                )

    def get_ticket_state(self, dedup_hash: str) -> dict[str, Any] | None:
        """Return the cached ticket state for one dedup hash."""
        if not dedup_hash:
            return None

        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    dedup_hash,
                    redmine_issue_id,
                    issue_state,
                    tracker_id,
                    subject,
                    ticket_exists,
                    last_ticket_check_at,
                    last_ticket_seen_at,
                    last_delivery_status,
                    last_error,
                    payload
                FROM {self._schema}.{self._ticket_state_table}
                WHERE dedup_hash = %s
                """,
                (dedup_hash,),
            )
            row = cur.fetchone()

        if not row:
            return None

        return {
            "dedup_hash": row[0],
            "redmine_issue_id": row[1],
            "issue_state": row[2],
            "tracker_id": row[3],
            "subject": row[4],
            "ticket_exists": row[5],
            "last_ticket_check_at": row[6],
            "last_ticket_seen_at": row[7],
            "last_delivery_status": row[8],
            "last_error": row[9],
            "payload": json.loads(row[10]) if isinstance(row[10], str) else dict(row[10] or {}),
        }

    def enqueue_outbound_job(
        self,
        *,
        job_id: str,
        dedup_hash: str,
        action: str,
        payload: dict[str, Any],
        status: str = "pending",
        next_attempt_at: str | None = None,
    ) -> None:
        """Persist an outbound Redmine delivery job."""
        if not job_id or not dedup_hash or not action:
            raise ValueError("outbound queue jobs require job_id, dedup_hash, and action")

        serialized = json.dumps(payload or {}, sort_keys=True)
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {self._schema}.{self._outbound_queue_table}
                    (
                        job_id,
                        dedup_hash,
                        action,
                        status,
                        payload,
                        attempt_count,
                        next_attempt_at,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        0,
                        COALESCE(%s, NOW()),
                        NOW(),
                        NOW()
                    )
                    ON CONFLICT (job_id) DO UPDATE SET
                        dedup_hash = EXCLUDED.dedup_hash,
                        action = EXCLUDED.action,
                        status = EXCLUDED.status,
                        payload = EXCLUDED.payload,
                        next_attempt_at = EXCLUDED.next_attempt_at,
                        updated_at = NOW()
                    """,
                    (job_id, dedup_hash, action, status, serialized, next_attempt_at),
                )

    def claim_outbound_jobs(self, worker_id: str, limit: int = 10) -> list[dict[str, Any]]:
        """Claim a batch of ready outbound jobs for one worker."""
        safe_limit = max(1, int(limit))
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    WITH claimable AS (
                        SELECT job_id
                        FROM {self._schema}.{self._outbound_queue_table}
                        WHERE status IN ('pending', 'retry_scheduled')
                          AND next_attempt_at <= NOW()
                        ORDER BY next_attempt_at ASC, created_at ASC
                        LIMIT %s
                        FOR UPDATE SKIP LOCKED
                    )
                    UPDATE {self._schema}.{self._outbound_queue_table} AS jobs
                    SET
                        status = 'processing',
                        locked_at = NOW(),
                        locked_by = %s,
                        updated_at = NOW()
                    FROM claimable
                    WHERE jobs.job_id = claimable.job_id
                    RETURNING
                        jobs.job_id,
                        jobs.dedup_hash,
                        jobs.action,
                        jobs.status,
                        jobs.payload,
                        jobs.attempt_count,
                        jobs.next_attempt_at,
                        jobs.last_error
                    """,
                    (safe_limit, worker_id),
                )
                rows = cur.fetchall()

        claimed: list[dict[str, Any]] = []
        for row in rows:
            payload = row[4]
            claimed.append(
                {
                    "job_id": row[0],
                    "dedup_hash": row[1],
                    "action": row[2],
                    "status": row[3],
                    "payload": json.loads(payload) if isinstance(payload, str) else dict(payload or {}),
                    "attempt_count": row[5],
                    "next_attempt_at": row[6],
                    "last_error": row[7],
                }
            )
        return claimed

    def mark_outbound_job_succeeded(self, job_id: str) -> None:
        """Mark one outbound queue job as successfully delivered."""
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE {self._schema}.{self._outbound_queue_table}
                    SET
                        status = 'succeeded',
                        attempt_count = attempt_count + 1,
                        locked_at = NULL,
                        locked_by = NULL,
                        last_error = NULL,
                        updated_at = NOW()
                    WHERE job_id = %s
                    """,
                    (job_id,),
                )

    def mark_outbound_job_retry(self, job_id: str, last_error: str, next_attempt_at: str | None = None) -> None:
        """Reschedule one outbound queue job for retry."""
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE {self._schema}.{self._outbound_queue_table}
                    SET
                        status = 'retry_scheduled',
                        attempt_count = attempt_count + 1,
                        locked_at = NULL,
                        locked_by = NULL,
                        last_error = %s,
                        next_attempt_at = COALESCE(%s, NOW()),
                        updated_at = NOW()
                    WHERE job_id = %s
                    """,
                    (last_error, next_attempt_at, job_id),
                )

    def mark_outbound_job_failed(self, job_id: str, last_error: str) -> None:
        """Mark one outbound queue job as permanently failed."""
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    UPDATE {self._schema}.{self._outbound_queue_table}
                    SET
                        status = 'failed',
                        attempt_count = attempt_count + 1,
                        locked_at = NULL,
                        locked_by = NULL,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE job_id = %s
                    """,
                    (last_error, job_id),
                )

    def get_outbound_job_stats(self) -> dict[str, int]:
        """Return counts grouped by outbound queue status."""
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT status, COUNT(*)
                FROM {self._schema}.{self._outbound_queue_table}
                GROUP BY status
                """
            )
            rows = cur.fetchall()

        stats = {
            "pending": 0,
            "processing": 0,
            "retry_scheduled": 0,
            "succeeded": 0,
            "failed": 0,
        }
        for status, count in rows:
            stats[str(status)] = int(count)
        return stats

    def append_dashboard_event(self, record: dict[str, Any]) -> None:
        """Persist a dashboard event payload."""
        event_id = str(record.get("id") or "")
        receive_time = str(record.get("receive_time") or "")
        if not event_id or not receive_time:
            raise ValueError("Dashboard event record requires 'id' and 'receive_time'")

        serialized = json.dumps(record, sort_keys=True)
        with self._conn:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {self._schema}.{self._dashboard_table}
                    (event_id, receive_time, payload)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (event_id) DO UPDATE SET
                        receive_time = EXCLUDED.receive_time,
                        payload = EXCLUDED.payload
                    """,
                    (event_id, receive_time, serialized),
                )

    def get_dashboard_history(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return the most recent persisted dashboard events, newest first."""
        safe_limit = max(1, int(limit))
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT payload
                FROM {self._schema}.{self._dashboard_table}
                ORDER BY receive_time DESC
                LIMIT %s
                """,
                (safe_limit,),
            )
            rows = cur.fetchall()

        events: list[dict[str, Any]] = []
        for row in rows:
            payload = row[0]
            if isinstance(payload, str):
                events.append(json.loads(payload))
            else:
                events.append(dict(payload))
        return events

    def close(self) -> None:
        """Close the Postgres connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


def _load_psycopg_module() -> Any:
    """Import psycopg lazily so local-mode installs keep working."""
    try:
        return importlib.import_module("psycopg")
    except ImportError as exc:
        raise RuntimeError(
            "storage.backend is set to 'postgres' but the 'psycopg' package is not installed"
        ) from exc


def _quote_identifier(value: str) -> str:
    """Validate and quote a simple SQL identifier."""
    if not _IDENTIFIER_RE.match(value or ""):
        raise ValueError(f"Invalid SQL identifier: {value!r}")
    return f'"{value}"'
