"""Data retention API routes."""

from fastapi import APIRouter, Query
from app.data_retention import backup, cleanup, config
from app.audit.models import log_action

router = APIRouter()


@router.get("/status")
async def get_status():
    """Get retention policy status."""
    return {
        "retention_days": config.DEFAULT_RETENTION_DAYS,
        "backup_enabled": config.DEFAULT_BACKUP_ENABLED,
    }


@router.post("/backup")
async def trigger_backup(type: str = Query("full")):
    """Manually trigger a database backup."""
    try:
        path = await backup.create_backup(backup_type=type)

        await log_action(
            module="data_retention",
            action="backup",
            detail=f"Manual {type} backup created: {path}",
        )

        return {"status": "ok", "backup_path": path, "type": type}
    except Exception as e:
        return {"status": "error", "message": f"Backup failed: {str(e)}"}


@router.get("/backups")
async def list_backups():
    """List all available database backups."""
    backups = await backup.list_backups()
    return {"backups": backups, "count": len(backups)}


@router.delete("/backups")
async def delete_backups(type: str = Query("all")):
    """Delete database backup files by type."""
    try:
        count = await backup.delete_all_backups(target_type=type)

        await log_action(
            module="data_retention",
            action="backup_cleanup",
            detail=f"Deleted {type} backups ({count} files)",
        )

        return {"status": "ok", "deleted_count": count, "type": type}
    except Exception as e:
        return {"status": "error", "message": f"Cleanup failed: {str(e)}"}


@router.post("/backups/restore/{filename}")
async def restore_backup(filename: str):
    """Restore a database backup. Creates a safety backup first."""
    try:
        restored_path = await backup.load_backup(filename)

        await log_action(
            module="data_retention",
            action="restore",
            detail=f"Database restored from backup: {filename}",
        )

        return {
            "status": "ok",
            "message": f"Database restored from {filename}",
            "restored_from": restored_path,
        }
    except FileNotFoundError:
        return {"status": "error", "message": f"Backup not found: {filename}"}
    except ValueError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": f"Restore failed: {str(e)}"}


@router.post("/cleanup")
async def trigger_cleanup(retention_days: int = config.DEFAULT_RETENTION_DAYS):
    """Manually trigger data cleanup."""
    deleted = await cleanup.cleanup_old_data(retention_days)

    await log_action(
        module="data_retention",
        action="cleanup",
        detail=f"Cleaned up {deleted} records older than {retention_days} days",
    )

    return {"deleted_records": deleted}
