"""Redmine API routes."""

from fastapi import APIRouter
from app.redmine.config import get_redmine_config
from app.redmine.schema import RedmineTicketCreate
from app.core.logger import logger

router = APIRouter()


@router.get("/status")
async def get_status():
    """Check Redmine connection status."""
    config = get_redmine_config()
    try:
        import httpx
        headers = {"X-Redmine-API-Key": config.get("api_key", "")}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{config['base_url']}/users/current.json",
                headers=headers,
                timeout=10,
            )
            connected = resp.status_code == 200
    except Exception as e:
        logger.warning("Redmine status check failed: %s", e)
        connected = False

    return {
        "connected": connected,
        "url": config.get("base_url", ""),
    }


@router.get("/tickets")
async def get_tickets(limit: int = 50):
    """List recent tickets from DB findings that have redmine_ticket_id."""
    from app.core.database import database, findings
    query = (
        findings.select()
        .where(findings.c.redmine_ticket_id.isnot(None))
        .order_by(findings.c.updated_at.desc())
        .limit(limit)
    )
    rows = await database.fetch_all(query)
    return {"tickets": [dict(r) for r in rows], "count": len(rows)}


@router.get("/trackers")
async def get_trackers():
    """Fetch available trackers from Redmine."""
    config = get_redmine_config()
    try:
        import httpx
        headers = {"X-Redmine-API-Key": config.get("api_key", "")}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{config['base_url']}/trackers.json",
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                trackers = [
                    {"id": t["id"], "name": t["name"]}
                    for t in data.get("trackers", [])
                ]
                return {"status": "ok", "trackers": trackers}
    except Exception as e:
        logger.warning("Redmine tracker fetch failed: %s", e)

    return {"status": "error", "message": "Failed to fetch trackers", "trackers": []}
