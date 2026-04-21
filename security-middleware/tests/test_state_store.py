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
        return list(self.conn.fetchall_result)

    def fetchone(self):
        return self.conn.fetchone_result


class _FakeConnection:
    def __init__(self):
        self.execute_calls = []
        self.executemany_calls = []
        self.closed = False
        self.fetchall_result = []
        self.fetchone_result = (0,)

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
            ticket_state_table="ticket_state",
            outbound_queue_table="outbound_jobs",
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


def test_postgres_init_creates_ticket_state_and_outbound_queue_tables():
    fake_dbapi = _FakeDbApi()
    PostgresStateStore(
        StorageConfig(
            backend="postgres",
            postgres_dsn="postgresql://middleware:secret@db/security",
            postgres_schema="middleware",
            dedup_table="seen_hashes",
            checkpoint_table="checkpoints",
            ticket_state_table="ticket_state",
            outbound_queue_table="outbound_jobs",
            ingest_event_table="ingest_events",
        ),
        dbapi_module=fake_dbapi,
    )

    init_sql = "\n".join(query for query, _ in fake_dbapi.connection.execute_calls)
    assert "CREATE TABLE IF NOT EXISTS \"middleware\".\"ticket_state\"" in init_sql
    assert "CREATE TABLE IF NOT EXISTS \"middleware\".\"outbound_jobs\"" in init_sql
    assert "CREATE TABLE IF NOT EXISTS \"middleware\".\"ingest_events\"" in init_sql
    assert "last_ticket_check_at" in init_sql
    assert "next_attempt_at" in init_sql


def test_postgres_save_ticket_state_upserts_delivery_metadata():
    fake_dbapi = _FakeDbApi()
    store = PostgresStateStore(
        StorageConfig(
            backend="postgres",
            postgres_dsn="postgresql://middleware:secret@db/security",
            postgres_schema="middleware",
            dedup_table="seen_hashes",
            checkpoint_table="checkpoints",
            ticket_state_table="ticket_state",
            outbound_queue_table="outbound_jobs",
        ),
        dbapi_module=fake_dbapi,
    )

    store.save_ticket_state(
        "hash-123",
        redmine_issue_id=101,
        issue_state="open",
        last_delivery_status="created",
        payload={"source": "wazuh"},
    )

    query, params = fake_dbapi.connection.execute_calls[-1]
    assert "INSERT INTO \"middleware\".\"ticket_state\"" in query
    assert "ON CONFLICT (dedup_hash) DO UPDATE SET" in query
    assert "last_delivery_status = EXCLUDED.last_delivery_status" in query
    assert params[0] == "hash-123"


def test_postgres_claim_outbound_jobs_uses_skip_locked_and_processing_transition():
    fake_dbapi = _FakeDbApi()
    fake_dbapi.connection.fetchall_result = [
        ("job-1", "hash-1", "create_ticket", "processing", "{\"title\": \"SSH brute force\"}", 0, "2026-04-21T00:00:00+00:00", None),
    ]
    store = PostgresStateStore(
        StorageConfig(
            backend="postgres",
            postgres_dsn="postgresql://middleware:secret@db/security",
            postgres_schema="middleware",
            dedup_table="seen_hashes",
            checkpoint_table="checkpoints",
            ticket_state_table="ticket_state",
            outbound_queue_table="outbound_jobs",
        ),
        dbapi_module=fake_dbapi,
    )

    claimed = store.claim_outbound_jobs("worker-a", limit=5)

    query, params = fake_dbapi.connection.execute_calls[-1]
    assert "FOR UPDATE SKIP LOCKED" in query
    assert "status = 'processing'" in query
    assert params == (5, "worker-a")
    assert claimed[0]["job_id"] == "job-1"
    assert claimed[0]["action"] == "create_ticket"


def test_postgres_append_and_claim_ingest_events_support_id_scoping():
    fake_dbapi = _FakeDbApi()
    fake_dbapi.connection.fetchall_result = [
        (
            "evt-1",
            "wazuh",
            "alert-1",
            "2026-04-21T00:00:00+00:00",
            "high",
            "5710",
            "web-01",
            "10.0.0.1",
            None,
            None,
            "{\"rule\": {\"id\": \"5710\"}}",
            "{\"source\": \"wazuh\", \"source_id\": \"alert-1\"}",
        ),
    ]
    store = PostgresStateStore(
        StorageConfig(
            backend="postgres",
            postgres_dsn="postgresql://middleware:secret@db/security",
            postgres_schema="middleware",
            dedup_table="seen_hashes",
            checkpoint_table="checkpoints",
            ticket_state_table="ticket_state",
            outbound_queue_table="outbound_jobs",
            ingest_event_table="ingest_events",
        ),
        dbapi_module=fake_dbapi,
    )

    store.append_ingest_events(
        [
            {
                "event_id": "evt-1",
                "source": "wazuh",
                "source_id": "alert-1",
                "event_timestamp": "2026-04-21T00:00:00+00:00",
                "severity": "high",
                "rule_id": "5710",
                "host": "web-01",
                "srcip": "10.0.0.1",
                "raw_payload": {"rule": {"id": "5710"}},
                "finding_payload": {"source": "wazuh", "source_id": "alert-1"},
            }
        ]
    )
    insert_query, records = fake_dbapi.connection.executemany_calls[-1]
    assert "INSERT INTO \"middleware\".\"ingest_events\"" in insert_query
    assert records[0][0] == "evt-1"

    claimed = store.claim_ingest_events("decision-a", limit=10, event_ids=["evt-1"])
    claim_query, claim_params = fake_dbapi.connection.execute_calls[-1]
    assert "FOR UPDATE SKIP LOCKED" in claim_query
    assert "event_id = ANY(%s)" in claim_query
    assert claim_params == (["evt-1"], 10, "decision-a")
    assert claimed[0]["event_id"] == "evt-1"
    assert claimed[0]["finding_payload"]["source_id"] == "alert-1"
