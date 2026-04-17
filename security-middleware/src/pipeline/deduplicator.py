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

_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS seen_hashes (
    hash TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER DEFAULT 1,
    flushed_count INTEGER DEFAULT 0
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

        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        
        cursor = self._conn.execute("PRAGMA user_version")
        version = cursor.fetchone()[0]

        if version < 1:
            self._conn.executescript(_SCHEMA_V1)
            try:
                self._conn.execute("ALTER TABLE seen_hashes ADD COLUMN flushed_count INTEGER DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            self._conn.execute("PRAGMA user_version = 1")
            version = 1

        if version < 2:
            try:
                self._conn.execute("ALTER TABLE seen_hashes ADD COLUMN redmine_issue_id INTEGER;")
            except sqlite3.OperationalError:
                pass
            try:
                self._conn.execute("ALTER TABLE seen_hashes ADD COLUMN issue_state TEXT DEFAULT 'open';")
            except sqlite3.OperationalError:
                pass
            self._conn.execute("PRAGMA user_version = 2")
            version = 2

        self._conn.commit()
        logger.info("Deduplicator: database initialized at %s (Version %d)", db_path, version)

    def process(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """
        Classify findings as new or repeat.

        Returns:
            Tuple of (new_findings, repeat_findings).
            - new_findings: never seen before, should be created in Redmine.
            - repeat_findings: seen within the TTL window, should update
              existing Redmine issues. Same-batch duplicates are collapsed
              into one representative Finding with occurrence_count set.

        New findings are NOT persisted to the database here.
        Call commit_new() after Redmine confirms success.
        """
        if not self.enabled:
            logger.debug("Deduplicator: disabled, passing all %d findings as new", len(findings))
            for finding in findings:
                finding.dedup_reason = "Deduplication disabled"
            return findings, []
        if not findings:
            return [], []

        assert self._conn is not None
        now = time.time()
        cutoff = now - self.ttl_seconds
        new_findings: list[Finding] = []
        # Collapse repeats by hash: hash -> (representative Finding, count)
        repeat_map: dict[str, tuple[Finding, int]] = {}

        with self._conn:
            all_known_hashes = self._get_all_hashes([finding.dedup_hash for finding in findings])
            
            self._purge_expired(cutoff=cutoff, commit=False)
            seen_dict = self._get_recent_hashes(
                [finding.dedup_hash for finding in findings],
                cutoff,
            )
            seen_hashes = set(seen_dict.keys())

            # Track hashes accepted as new within this batch
            accepted_hashes: set[str] = set()

            for finding in findings:
                h = finding.dedup_hash

                if h in seen_hashes:
                    # Map issue ID directly from local database
                    issue_id, issue_state = seen_dict[h]
                    finding.redmine_issue_id = issue_id
                    
                    # Known from a previous cycle — route to update path
                    finding.dedup_reason = "repeat_within_ttl"
                    if h in repeat_map:
                        repeat_map[h] = (repeat_map[h][0], repeat_map[h][1] + 1)
                    else:
                        repeat_map[h] = (finding, 1)
                elif h in accepted_hashes:
                    # Same-batch duplicate — collapse into repeat bucket
                    finding.dedup_reason = "same_batch_duplicate"
                    if h in repeat_map:
                        repeat_map[h] = (repeat_map[h][0], repeat_map[h][1] + 1)
                    else:
                        repeat_map[h] = (finding, 1)
                else:
                    # Genuinely new finding or expired TTL finding
                    if h in all_known_hashes:
                        finding.dedup_reason = "expired_hash"
                    else:
                        finding.dedup_reason = "new_hash"
                    accepted_hashes.add(h)
                    new_findings.append(finding)

            # Update counts in DB for already-tracked hashes
            db_updates = {h: count for h, (_, count) in repeat_map.items() if h in seen_hashes}
            if db_updates:
                self._conn.executemany(
                    """
                    UPDATE seen_hashes
                    SET last_seen = ?, count = count + ?
                    WHERE hash = ?
                    """,
                    [(now, count, hash_value) for hash_value, count in db_updates.items()],
                )

        # Build the repeat_findings list with occurrence_count stamped
        repeat_findings: list[Finding] = []
        for h, (finding, count) in repeat_map.items():
            finding.occurrence_count = count
            repeat_findings.append(finding)

        total_repeat = sum(f.occurrence_count for f in repeat_findings)
        if repeat_findings:
            logger.info(
                "Deduplicator: %d new, %d repeat (%d occurrences across %d unique hashes)",
                len(new_findings),
                total_repeat,
                total_repeat,
                len(repeat_findings),
            )
        else:
            logger.debug("Deduplicator: all %d findings are new", len(new_findings))

        return new_findings, repeat_findings

    def commit_new(self, findings: list[Finding]) -> None:
        """
        Persist successfully processed findings into the dedup registry.

        This method should ONLY be called after the output stage (Redmine)
        confirms that the findings were successfully created/updated.
        This prevents silent data loss during Redmine outages.
        """
        if not self._conn or not findings:
            return

        now = time.time()
        records = [
            (
                finding.dedup_hash,
                finding.source.value,
                finding.title[:200],
                now,
                now,
                1,
                1,  # flushed_count
                getattr(finding, 'redmine_issue_id', None),
                "open"
            )
            for finding in findings
        ]

        with self._conn:
            self._conn.executemany(
                """
                INSERT OR REPLACE INTO seen_hashes
                (hash, source, title, first_seen, last_seen, count, flushed_count, redmine_issue_id, issue_state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
        logger.info("Deduplicator: committed %d findings after successful output", len(findings))

    def commit_updates(self, findings: list[Finding]) -> None:
        """
        Commit successful update lifecycle checks back to the local database mapping.
        """
        if not self._conn or not findings:
            return

        now = time.time()
        records = [
            (
                getattr(finding, 'redmine_issue_id', None),
                "open",
                now,
                finding.dedup_hash
            )
            for finding in findings
        ]

        with self._conn:
            self._conn.executemany(
                """
                UPDATE seen_hashes
                SET redmine_issue_id = ?, issue_state = ?, last_seen = MAX(last_seen, ?)
                WHERE hash = ?
                """,
                records
            )
        logger.info("Deduplicator: committed mapped IDs for %d updated findings", len(findings))

    def _get_recent_hashes(self, hash_values: list[str], cutoff: float) -> dict[str, tuple[int|None, str|None]]:
        """Fetch hashes seen within the active TTL window in a small number of queries."""
        assert self._conn is not None
        if not hash_values:
            return {}

        unique_hashes = list(dict.fromkeys(hash_values))
        seen_hashes = {}

        # Keep the IN clause comfortably below SQLite's variable limit.
        chunk_size = 500
        for index in range(0, len(unique_hashes), chunk_size):
            chunk = unique_hashes[index:index + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cursor = self._conn.execute(
                f"""
                SELECT hash, redmine_issue_id, issue_state
                FROM seen_hashes
                WHERE last_seen > ? AND hash IN ({placeholders})
                """,
                [cutoff, *chunk],
            )
            for row in cursor.fetchall():
                seen_hashes[row[0]] = (row[1], row[2])

        return seen_hashes

    def _get_all_hashes(self, hash_values: list[str]) -> set[str]:
        """Fetch hashes that exist in the database regardless of TTL."""
        assert self._conn is not None
        if not hash_values:
            return set()

        unique_hashes = list(dict.fromkeys(hash_values))
        known_hashes: set[str] = set()

        chunk_size = 500
        for index in range(0, len(unique_hashes), chunk_size):
            chunk = unique_hashes[index:index + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cursor = self._conn.execute(
                f"""
                SELECT hash
                FROM seen_hashes
                WHERE hash IN ({placeholders})
                """,
                [*chunk],
            )
            known_hashes.update(row[0] for row in cursor.fetchall())

        return known_hashes

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
            INSERT OR REPLACE INTO seen_hashes (hash, source, title, first_seen, last_seen, count, redmine_issue_id, issue_state)
            VALUES (?, ?, ?, ?, ?, 1, ?, 'open')
            """,
            (finding.dedup_hash, finding.source.value, finding.title[:200], now, now, getattr(finding, 'redmine_issue_id', None)),
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
