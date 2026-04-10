"""
Deduplicator pipeline stage.

Tracks findings by their SHA-256 dedup hash in a SQLite database
and drops findings that have already been processed within the
configured TTL window.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

from src.config import DedupConfig
from src.models.finding import Finding

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_hashes (
    hash TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_last_seen ON seen_hashes(last_seen);
"""


class DeduplicatorStage:
    """
    Hash-based deduplication with TTL.

    Uses a SQLite database to track which findings have already been
    processed. Findings with a hash seen within the TTL window are
    dropped; others are passed through and recorded.
    """

    def __init__(self, config: DedupConfig):
        self.config = config
        self.enabled = config.enabled
        self.ttl_seconds = config.ttl_hours * 3600
        self._conn: sqlite3.Connection | None = None

        if self.enabled:
            self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database."""
        db_path = Path(self.config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(db_path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("Deduplicator: database initialized at %s", db_path)

    def process(self, findings: list[Finding]) -> list[Finding]:
        """
        Deduplicate findings.

        Returns only findings whose hash has NOT been seen within the TTL window.
        """
        if not self.enabled:
            logger.debug("Deduplicator: disabled, passing all %d findings", len(findings))
            return findings
        if not findings:
            return findings

        assert self._conn is not None
        now = time.time()
        cutoff = now - self.ttl_seconds
        new_findings: list[Finding] = []
        new_records: list[tuple[str, str, str, float, float, int]] = []
        duplicate_counts: dict[str, int] = {}
        duplicates = 0

        with self._conn:
            self._purge_expired(cutoff=cutoff, commit=False)
            seen_hashes = self._get_recent_hashes(
                [finding.dedup_hash for finding in findings],
                cutoff,
            )

            # Track hashes we accept in the current batch so same-batch duplicates are dropped.
            accepted_hashes = set(seen_hashes)

            for finding in findings:
                if finding.dedup_hash in accepted_hashes:
                    duplicates += 1
                    duplicate_counts[finding.dedup_hash] = (
                        duplicate_counts.get(finding.dedup_hash, 0) + 1
                    )
                    logger.debug(
                        "Deduplicator: duplicate dropped: %s (hash=%s)",
                        finding.title[:50],
                        finding.dedup_hash[:12],
                    )
                else:
                    accepted_hashes.add(finding.dedup_hash)
                    new_findings.append(finding)
                    new_records.append(
                        (
                            finding.dedup_hash,
                            finding.source.value,
                            finding.title[:200],
                            now,
                            now,
                            1,
                        )
                    )

            if new_records:
                self._conn.executemany(
                    """
                    INSERT OR REPLACE INTO seen_hashes
                    (hash, source, title, first_seen, last_seen, count)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    new_records,
                )

            if duplicate_counts:
                self._conn.executemany(
                    """
                    UPDATE seen_hashes
                    SET last_seen = ?, count = count + ?
                    WHERE hash = ?
                    """,
                    [(now, count, hash_value) for hash_value, count in duplicate_counts.items()],
                )

        if duplicates > 0:
            logger.info(
                "Deduplicator: %d new, %d duplicates dropped",
                len(new_findings),
                duplicates,
            )
        else:
            logger.debug("Deduplicator: all %d findings are new", len(new_findings))

        return new_findings

    def _get_recent_hashes(self, hash_values: list[str], cutoff: float) -> set[str]:
        """Fetch hashes seen within the active TTL window in a small number of queries."""
        assert self._conn is not None
        if not hash_values:
            return set()

        unique_hashes = list(dict.fromkeys(hash_values))
        seen_hashes: set[str] = set()

        # Keep the IN clause comfortably below SQLite's variable limit.
        chunk_size = 500
        for index in range(0, len(unique_hashes), chunk_size):
            chunk = unique_hashes[index:index + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cursor = self._conn.execute(
                f"""
                SELECT hash
                FROM seen_hashes
                WHERE last_seen > ? AND hash IN ({placeholders})
                """,
                [cutoff, *chunk],
            )
            seen_hashes.update(row[0] for row in cursor.fetchall())

        return seen_hashes

    def _is_duplicate(self, hash_value: str) -> bool:
        """Check if a hash exists in the database within the TTL window."""
        assert self._conn is not None
        cutoff = time.time() - self.ttl_seconds
        cursor = self._conn.execute(
            "SELECT 1 FROM seen_hashes WHERE hash = ? AND last_seen > ?",
            (hash_value, cutoff),
        )
        return cursor.fetchone() is not None

    def _record_hash(self, finding: Finding) -> None:
        """Record a new finding hash in the database."""
        assert self._conn is not None
        now = time.time()
        self._conn.execute(
            """
            INSERT OR REPLACE INTO seen_hashes (hash, source, title, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (finding.dedup_hash, finding.source.value, finding.title[:200], now, now),
        )
        self._conn.commit()

    def _update_count(self, hash_value: str) -> None:
        """Increment the seen count for an existing hash."""
        assert self._conn is not None
        now = time.time()
        self._conn.execute(
            "UPDATE seen_hashes SET last_seen = ?, count = count + 1 WHERE hash = ?",
            (now, hash_value),
        )
        self._conn.commit()

    def _purge_expired(self, cutoff: float | None = None, commit: bool = True) -> None:
        """Remove entries older than TTL."""
        assert self._conn is not None
        if cutoff is None:
            cutoff = time.time() - self.ttl_seconds
        cursor = self._conn.execute(
            "DELETE FROM seen_hashes WHERE last_seen < ?",
            (cutoff,),
        )
        if cursor.rowcount > 0:
            logger.info("Deduplicator: purged %d expired entries", cursor.rowcount)
        if commit:
            self._conn.commit()

    def get_stats(self) -> dict[str, int]:
        """Return database statistics."""
        if not self._conn:
            return {"total": 0}
        cursor = self._conn.execute("SELECT COUNT(*) FROM seen_hashes")
        total = cursor.fetchone()[0]
        return {"total_tracked": total}

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
