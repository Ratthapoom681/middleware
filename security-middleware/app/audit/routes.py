"""Audit API routes."""

from fastapi import APIRouter
from app.audit import models

router = APIRouter()


@router.get("")
async def get_audit_log(module: str = "all", action: str = "all", limit: int = 100):
    """Get audit trail with optional filtering."""
    entries = await models.get_audit_entries(module, action, limit)
    return {"entries": entries, "count": len(entries)}
