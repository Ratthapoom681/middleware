"""
Tests for shared state backends.
"""

from __future__ import annotations

from src.config import StorageConfig
from src.state_store import PostgresStateStore


class _FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        self.conn.execute_calls.append((query, params))
        return self

    def executemany(self, query, records):
        self.conn.executemany_calls.append((query, list(records)))
        return self

    def fetchall(self):
        return []

    def fetchone(self):
        return (0,)


class _FakeConnection:
    def __init__(self):
        self.execute_calls = []
        self.executemany_calls = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        self.closed = True


class _FakeDbApi:
    def __init__(self):
        self.connection = _FakeConnection()

    def connect(self, dsn):
        self.dsn = dsn
        return self.connection


def test_postgres_commit_new_preserves_existing_counters_and_first_seen():
    fake_dbapi = _FakeDbApi()
    store = PostgresStateStore(
        StorageConfig(
            backend="postgres",
            postgres_dsn="postgresql://middleware:secret@db/security",
            postgres_schema="middleware",
            dedup_table="seen_hashes",
            checkpoint_table="checkpoints",
        ),
        dbapi_module=fake_dbapi,
    )

    store.commit_new(
        [
            ("abc", "wazuh", "Title", 1.0, 2.0, 1, 1, 123, "open"),
        ]
    )

    query, records = fake_dbapi.connection.executemany_calls[-1]
    assert "first_seen = LEAST" in query
    assert "last_seen = GREATEST" in query
    assert "count = " in query and "+ EXCLUDED.count" in query
    assert "flushed_count = " in query and "+ EXCLUDED.flushed_count" in query
    assert "COALESCE" in query
    assert records[0][0] == "abc"
