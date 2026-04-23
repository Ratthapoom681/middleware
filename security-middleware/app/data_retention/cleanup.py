"""Old data cleanup logic."""

from datetime import datetime, timezone, timedelta
from app.core.database import database, findings, audit_log, dead_letter
from app.core.logger import logger


async def cleanup_old_data(retention_days: int = 90) -> int:
    """Delete findings, audit entries, and dead letters older than retention_days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    total_deleted = 0

    for table in (findings, audit_log, dead_letter):
        result = await database.execute(
            table.delete().where(table.c.created_at < cutoff)
        )
        total_deleted += result

    logger.info("Data cleanup: removed %d records older than %d days", total_deleted, retention_days)
    return total_deleted
