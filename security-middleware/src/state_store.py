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
        logger.info(
            "Postgres state store initialized (%s.%s / %s.%s)",
            self.config.postgres_schema,
            self.config.dedup_table,
            self.config.postgres_schema,
            self.config.checkpoint_table,
        )

    def _dedup_index_name(self, suffix: str) -> str:
        """Build a safe, deterministic index name."""
        raw_name = f"{self.config.dedup_table}_{suffix}_idx"
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
                        first_seen = EXCLUDED.first_seen,
                        last_seen = EXCLUDED.last_seen,
                        count = EXCLUDED.count,
                        flushed_count = EXCLUDED.flushed_count,
                        redmine_issue_id = EXCLUDED.redmine_issue_id,
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
