"""Database backup logic — supports SQLite (file copy) and PostgreSQL (pg_dump / JSON fallback)."""

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

from app.config import settings
from app.core.logger import logger


# ── Helpers ──────────────────────────────────────────────────────────

BACKUP_DIR = os.path.join("data", "backups")
BACKUP_EXTENSIONS = (".db", ".sql", ".json")


def _is_postgres() -> bool:
    """Return True when the active DATABASE_URL points to PostgreSQL."""
    return settings.DATABASE_URL.startswith("postgresql")


def _sqlite_path() -> str:
    """Extract the filesystem path from a sqlite:/// URL."""
    path = settings.DATABASE_URL.replace("sqlite:///", "")
    if path.startswith("./"):
        path = path[2:]
    return path


def _pg_connection_parts() -> dict:
    """Parse a PostgreSQL DATABASE_URL into its component parts."""
    parsed = urlparse(settings.DATABASE_URL)
    return {
        "host": parsed.hostname or "localhost",
        "port": str(parsed.port or 5432),
        "user": parsed.username or "middleware",
        "password": parsed.password or "",
        "dbname": parsed.path.lstrip("/") or "middleware",
    }


def _ensure_backup_dir() -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")


# ── Create ───────────────────────────────────────────────────────────

async def create_backup(backup_type: str = "full") -> str:
    """Create a database backup. Strategy depends on the active backend."""
    logger.info("Creating backup with type: %s", backup_type)

    if backup_type == "config":
        return await _create_config_json_backup()

    if _is_postgres():
        return await _create_pg_backup()
    return await _create_sqlite_backup()


async def _create_sqlite_backup() -> str:
    """Copy the SQLite database file."""
    db_path = _sqlite_path()
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"SQLite database not found at: {db_path}")

    _ensure_backup_dir()
    backup_path = os.path.join(BACKUP_DIR, f"full_backup_{_timestamp()}.db")
    shutil.copy2(db_path, backup_path)

    logger.info("SQLite backup created: %s", backup_path)
    return backup_path


async def _create_pg_backup() -> str:
    """
    Backup PostgreSQL.
    First tries pg_dump (fast, native).  If pg_dump is unavailable in the
    container, falls back to a pure-Python JSON export via SQLAlchemy.
    """
    _ensure_backup_dir()

    # Try pg_dump first
    parts = _pg_connection_parts()
    backup_path = os.path.join(BACKUP_DIR, f"full_backup_{_timestamp()}.sql")

    env = os.environ.copy()
    env["PGPASSWORD"] = parts["password"]

    try:
        result = subprocess.run(
            [
                "pg_dump",
                "-h", parts["host"],
                "-p", parts["port"],
                "-U", parts["user"],
                "-d", parts["dbname"],
                "--no-owner",
                "--no-privileges",
                "-f", backup_path,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
            logger.info("PostgreSQL backup created (pg_dump): %s", backup_path)
            return backup_path
        # pg_dump failed — clean up partial file and fall through
        if os.path.exists(backup_path):
            os.remove(backup_path)
        logger.warning("pg_dump failed (rc=%s): %s — falling back to JSON export",
                        result.returncode, result.stderr.strip())
    except FileNotFoundError:
        logger.info("pg_dump not found in PATH — falling back to JSON export")
    except Exception as exc:
        logger.warning("pg_dump error: %s — falling back to JSON export", exc)

    # Fallback: pure-Python JSON export via SQLAlchemy
    return await _create_pg_json_backup()


async def _create_pg_json_backup() -> str:
    """Export all application tables to a JSON file using SQLAlchemy."""
    import sqlalchemy
    from app.core.database import metadata as app_metadata

    _ensure_backup_dir()
    backup_path = os.path.join(BACKUP_DIR, f"full_backup_{_timestamp()}.json")

    engine = sqlalchemy.create_engine(settings.DATABASE_URL)
    data: dict[str, list[dict]] = {}

    try:
        with engine.connect() as conn:
            for table in app_metadata.sorted_tables:
                rows = conn.execute(table.select()).fetchall()
                data[table.name] = [
                    {col.name: _serialise(row._mapping[col.name]) for col in table.columns}
                    for row in rows
                ]
    finally:
        engine.dispose()

    with open(backup_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    logger.info("PostgreSQL backup created (JSON export): %s", backup_path)
    return backup_path


async def _create_config_json_backup() -> str:
    """Export only the settings table to a JSON file using SQLAlchemy."""
    import sqlalchemy
    from app.core.database import metadata as app_metadata

    _ensure_backup_dir()
    backup_path = os.path.join(BACKUP_DIR, f"config_backup_{_timestamp()}.json")

    engine = sqlalchemy.create_engine(settings.DATABASE_URL)
    data: dict[str, list[dict]] = {}

    try:
        with engine.connect() as conn:
            # We specifically only target the 'settings' table
            table = app_metadata.tables.get("settings")
            if table is not None:
                rows = conn.execute(table.select()).fetchall()
                data[table.name] = [
                    {col.name: _serialise(row._mapping[col.name]) for col in table.columns}
                    for row in rows
                ]
            else:
                logger.warning("Settings table not found in metadata during config backup")
    finally:
        engine.dispose()

    with open(backup_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    logger.info("Config-only backup created: %s", backup_path)
    return backup_path


def _serialise(value):
    """Make a value JSON-friendly."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


# ── List ─────────────────────────────────────────────────────────────

async def list_backups() -> list[dict]:
    """List all available database backup files, newest first."""
    if not os.path.isdir(BACKUP_DIR):
        return []

    backups = []
    for filename in os.listdir(BACKUP_DIR):
        if not filename.endswith(BACKUP_EXTENSIONS):
            continue
        filepath = os.path.join(BACKUP_DIR, filename)
        stat = os.stat(filepath)
        backups.append({
            "filename": filename,
            "path": filepath,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })

    backups.sort(key=lambda b: b["created_at"], reverse=True)
    return backups


async def delete_all_backups(target_type: str = "all") -> int:
    """
    Delete database backup files in the backup directory.
    target_type: "all", "full", or "config"
    """
    if not os.path.isdir(BACKUP_DIR):
        return 0

    count = 0
    prefix_map = {
        "full": "full_backup_",
        "config": "config_backup_",
    }
    prefix = prefix_map.get(target_type)

    for filename in os.listdir(BACKUP_DIR):
        if filename.endswith(BACKUP_EXTENSIONS):
            # If target_type is not "all", check the prefix
            if prefix and not filename.startswith(prefix):
                continue

            filepath = os.path.join(BACKUP_DIR, filename)
            try:
                os.remove(filepath)
                count += 1
            except Exception as e:
                logger.error("Failed to delete backup %s: %s", filename, e)

    logger.info("Deleted %d backup files (type: %s)", count, target_type)
    return count


# ── Restore ──────────────────────────────────────────────────────────

async def load_backup(filename: str) -> str:
    """
    Restore a database backup.

    Supported formats:
      .db   → SQLite file-copy restore
      .sql  → PostgreSQL pg_dump restore (psql)
      .json → Pure-Python table-level restore via SQLAlchemy

    WARNING: This will overwrite the current database contents.
    A safety backup is created automatically before restoring.
    """
    # Sanitize filename
    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid backup filename")

    backup_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(backup_path):
        raise FileNotFoundError(f"Backup not found: {filename}")

    # Create a safety backup before restoring
    try:
        safety_path = await create_backup()
        # Rename the safety backup so it's clearly labelled
        if safety_path:
            base, ext = os.path.splitext(safety_path)
            new_name = f"{base}_prerestore{ext}"
            os.rename(safety_path, new_name)
            logger.info("Safety backup created before restore: %s", new_name)
    except Exception as exc:
        logger.warning("Could not create safety backup: %s — proceeding anyway", exc)

    if filename.endswith(".db"):
        await _restore_sqlite(backup_path)
    elif filename.endswith(".sql"):
        await _restore_pg_sql(backup_path)
    elif filename.endswith(".json"):
        await _restore_pg_json(backup_path)
    else:
        raise ValueError(f"Unsupported backup format: {filename}")

    return backup_path


async def _restore_sqlite(backup_path: str):
    """Restore an SQLite backup by overwriting the database file."""
    from app.core.database import database

    db_path = _sqlite_path()

    try:
        await database.disconnect()
    except Exception:
        pass

    shutil.copy2(backup_path, db_path)
    logger.info("SQLite database restored from: %s", backup_path)

    await database.connect()

    from app.settings.models import settings_manager
    await settings_manager.reload()


async def _restore_pg_sql(backup_path: str):
    """Restore a PostgreSQL backup from a pg_dump .sql file."""
    parts = _pg_connection_parts()
    env = os.environ.copy()
    env["PGPASSWORD"] = parts["password"]

    result = subprocess.run(
        [
            "psql",
            "-h", parts["host"],
            "-p", parts["port"],
            "-U", parts["user"],
            "-d", parts["dbname"],
            "-f", backup_path,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(f"psql restore failed: {result.stderr.strip()}")

    logger.info("PostgreSQL database restored from SQL dump: %s", backup_path)

    from app.settings.models import settings_manager
    await settings_manager.reload()


async def _restore_pg_json(backup_path: str):
    """Restore a PostgreSQL (or SQLite) database from a JSON export."""
    import sqlalchemy
    from app.core.database import metadata as app_metadata

    with open(backup_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = sqlalchemy.create_engine(settings.DATABASE_URL)

    try:
        with engine.begin() as conn:
            # Clear existing data in reverse dependency order
            for table in reversed(app_metadata.sorted_tables):
                if table.name in data:
                    conn.execute(table.delete())

            # Insert backup data in dependency order
            for table in app_metadata.sorted_tables:
                rows = data.get(table.name, [])
                if rows:
                    # Convert ISO strings back to datetime objects for relevant columns
                    dt_cols = [c.name for c in table.columns if isinstance(c.type, (sqlalchemy.DateTime, sqlalchemy.Date))]
                    if dt_cols:
                        for row in rows:
                            for col in dt_cols:
                                if row.get(col) and isinstance(row[col], str):
                                    try:
                                        # Use fromisoformat for speed, falls back to str if invalid
                                        row[col] = datetime.fromisoformat(row[col].replace('Z', '+00:00'))
                                    except (ValueError, TypeError):
                                        pass

                    conn.execute(table.insert(), rows)
                    
            if engine.dialect.name == "postgresql":
                for table in app_metadata.sorted_tables:
                    try:
                        conn.execute(sqlalchemy.text(f"SELECT setval(pg_get_serial_sequence('{table.name}', 'id'), coalesce(max(id),0) + 1, false) FROM {table.name};"))
                    except Exception:
                        pass
    finally:
        engine.dispose()

    logger.info("Database restored from JSON export: %s", backup_path)

    from app.settings.models import settings_manager
    await settings_manager.reload()
