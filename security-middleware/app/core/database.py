"""
Database layer – async SQLite via the `databases` library.
Tables are created on startup via create_tables().
"""

import databases
import sqlalchemy
from app.config import settings

database = databases.Database(settings.DATABASE_URL)

metadata = sqlalchemy.MetaData()

# ── Findings table (stores processed alerts/vulns) ──
findings = sqlalchemy.Table(
    "findings",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("source", sqlalchemy.String(50)),          # wazuh | defectdojo
    sqlalchemy.Column("source_id", sqlalchemy.String(255)),      # original ID from source
    sqlalchemy.Column("dedup_hash", sqlalchemy.String(64), index=True),
    sqlalchemy.Column("severity", sqlalchemy.String(20)),
    sqlalchemy.Column("title", sqlalchemy.String(500)),
    sqlalchemy.Column("description", sqlalchemy.Text),
    sqlalchemy.Column("raw_data", sqlalchemy.Text),              # JSON blob
    sqlalchemy.Column("redmine_ticket_id", sqlalchemy.Integer, nullable=True),
    sqlalchemy.Column("status", sqlalchemy.String(30), default="new"),  # new|processing|delivered|failed
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, server_default=sqlalchemy.func.now()),
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime, server_default=sqlalchemy.func.now()),
)

# ── Audit log ──
audit_log = sqlalchemy.Table(
    "audit_log",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("action", sqlalchemy.String(100)),
    sqlalchemy.Column("module", sqlalchemy.String(50)),
    sqlalchemy.Column("user", sqlalchemy.String(100), default="system"),
    sqlalchemy.Column("detail", sqlalchemy.Text),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, server_default=sqlalchemy.func.now()),
)

# ── Settings store ──
settings_table = sqlalchemy.Table(
    "settings",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("section", sqlalchemy.String(50), unique=True),  # wazuh|defectdojo|redmine|pipeline|filter|dedup|enrichment|severity_map|storage|logging
    sqlalchemy.Column("config_json", sqlalchemy.Text),                 # JSON blob
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime, server_default=sqlalchemy.func.now()),
)

# ── Dead-letter queue ──
dead_letter = sqlalchemy.Table(
    "dead_letter",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("finding_id", sqlalchemy.Integer),
    sqlalchemy.Column("error", sqlalchemy.Text),
    sqlalchemy.Column("retry_count", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, server_default=sqlalchemy.func.now()),
)


async def create_tables():
    """Create all tables if they don't exist (SQLite)."""
    import os
    import sqlite3

    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    metadata.create_all(engine)
    engine.dispose()
    conn.close()
