"""Audit trail DB operations."""

from datetime import datetime, timezone
from app.core.database import database, audit_log


async def get_audit_entries(module: str = "all", action: str = "all", limit: int = 100) -> list[dict]:
    query = audit_log.select().order_by(audit_log.c.created_at.desc()).limit(limit)
    if module != "all":
        query = query.where(audit_log.c.module == module)
    if action != "all":
        query = query.where(audit_log.c.action == action)
    rows = await database.fetch_all(query)
    return [dict(r) for r in rows]


async def log_action(module: str, action: str, detail: str = "", user: str = "system"):
    await database.execute(
        audit_log.insert().values(
            module=module,
            action=action,
            detail=detail,
            user=user,
        )
    )
