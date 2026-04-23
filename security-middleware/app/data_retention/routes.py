"""Data retention API routes."""

from fastapi import APIRouter
from app.data_retention import backup, cleanup, config

router = APIRouter()


@router.get("/status")
async def get_status():
    """Get retention policy status."""
    return {
        "retention_days": config.DEFAULT_RETENTION_DAYS,
        "backup_enabled": config.DEFAULT_BACKUP_ENABLED,
    }


@router.post("/backup")
async def trigger_backup():
    """Manually trigger a database backup."""
    path = await backup.create_backup()
    return {"backup_path": path}


@router.post("/cleanup")
async def trigger_cleanup(retention_days: int = config.DEFAULT_RETENTION_DAYS):
    """Manually trigger data cleanup."""
    deleted = await cleanup.cleanup_old_data(retention_days)
    return {"deleted_records": deleted}
