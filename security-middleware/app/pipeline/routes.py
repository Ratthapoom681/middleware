"""Pipeline API routes."""

from fastapi import APIRouter
from app.pipeline import monitor, dead_letter

router = APIRouter()


@router.get("/status")
async def get_status():
    """Get pipeline health and metrics."""
    metrics = monitor.get_metrics()
    return {"status": "active", "metrics": metrics}


@router.get("/dead-letter")
async def get_dead_letters(limit: int = 50):
    """Get failed items from the dead-letter queue."""
    items = await dead_letter.get_dead_letters(limit)
    return {"items": items, "count": len(items)}
