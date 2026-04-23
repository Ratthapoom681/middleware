"""Database backup logic."""

import shutil
import os
from datetime import datetime, timezone
from app.config import settings
from app.core.logger import logger


async def create_backup() -> str:
    """Create a snapshot of the SQLite database."""
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if db_path.startswith("./"):
        db_path = db_path[2:]
    if not os.path.exists(db_path):
        return ""

    backup_dir = os.path.join("data", "backups")
    os.makedirs(backup_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"middleware_{ts}.db")
    shutil.copy2(db_path, backup_path)

    logger.info("Database backup created: %s", backup_path)
    return backup_path


async def list_backups() -> list[dict]:
    """List all available database backup files, newest first."""
    backup_dir = os.path.join("data", "backups")
    if not os.path.isdir(backup_dir):
        return []

    backups = []
    for filename in os.listdir(backup_dir):
        if not filename.endswith(".db"):
            continue
        filepath = os.path.join(backup_dir, filename)
        stat = os.stat(filepath)
        backups.append({
            "filename": filename,
            "path": filepath,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })

    backups.sort(key=lambda b: b["created_at"], reverse=True)
    return backups


async def load_backup(filename: str) -> str:
    """
    Restore a database backup by overwriting the current SQLite database.

    WARNING: This will disconnect and replace the active database.
    The application should be restarted after this operation.

    Returns the path of the restored backup on success.
    """
    # Sanitize filename
    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid backup filename")

    backup_dir = os.path.join("data", "backups")
    backup_path = os.path.join(backup_dir, filename)

    if not os.path.isfile(backup_path):
        raise FileNotFoundError(f"Backup not found: {filename}")

    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if db_path.startswith("./"):
        db_path = db_path[2:]

    # Create a safety backup of the current DB before restoring
    if os.path.exists(db_path):
        safety_dir = os.path.join("data", "backups")
        os.makedirs(safety_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safety_path = os.path.join(safety_dir, f"middleware_{ts}_prerestore.db")
        shutil.copy2(db_path, safety_path)
        logger.info("Safety backup created before restore: %s", safety_path)

    # Disconnect the database before overwriting
    from app.core.database import database
    try:
        await database.disconnect()
    except Exception:
        pass

    # Perform the restore
    shutil.copy2(backup_path, db_path)
    logger.info("Database restored from backup: %s", backup_path)

    # Reconnect
    await database.connect()

    # Reload settings into memory
    from app.settings.models import settings_manager
    await settings_manager.reload()

    return backup_path
