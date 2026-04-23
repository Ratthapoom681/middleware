"""Database backup logic."""

import shutil
import os
from datetime import datetime, timezone
from app.config import settings
from app.core.logger import logger


async def create_backup() -> str:
    """Create a snapshot of the SQLite database."""
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return ""

    backup_dir = os.path.join("data", "backups")
    os.makedirs(backup_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"middleware_{ts}.db")
    shutil.copy2(db_path, backup_path)

    logger.info("Database backup created: %s", backup_path)
    return backup_path
