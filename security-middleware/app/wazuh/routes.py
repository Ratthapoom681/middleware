"""Wazuh API routes."""

from fastapi import APIRouter
from app.wazuh.config import get_wazuh_config
from app.core.logger import logger

router = APIRouter()


@router.get("/status")
async def get_status():
    """Check Wazuh connection status."""
    config = get_wazuh_config()
    try:
        import httpx
        async with httpx.AsyncClient(verify=config.get("verify_ssl", False)) as client:
            resp = await client.get(
                f"{config['base_url']}/security/user/authenticate",
                auth=(config.get("username", ""), config.get("password", "")),
                timeout=10,
            )
            connected = resp.status_code == 200
    except Exception as e:
        logger.warning("Wazuh status check failed: %s", e)
        connected = False

    return {
        "connected": connected,
        "url": config.get("base_url", ""),
    }


@router.get("/alerts")
async def get_alerts(limit: int = 100):
    """Fetch recent alerts (placeholder – reads from findings DB)."""
    from app.core.database import database, findings
    query = (
        findings.select()
        .where(findings.c.source == "wazuh")
        .order_by(findings.c.created_at.desc())
        .limit(limit)
    )
    rows = await database.fetch_all(query)
    return {"alerts": [dict(r) for r in rows], "count": len(rows)}
