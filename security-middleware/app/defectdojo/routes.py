"""DefectDojo API routes."""

from fastapi import APIRouter
from app.defectdojo.config import get_defectdojo_config
from app.core.logger import logger

router = APIRouter()


@router.get("/status")
async def get_status():
    """Check DefectDojo connection status."""
    config = get_defectdojo_config()
    try:
        import httpx
        headers = {"Authorization": config.get("api_key", "")}
        async with httpx.AsyncClient(verify=config.get("verify_ssl", False)) as client:
            resp = await client.get(
                f"{config['base_url']}/findings/?limit=1",
                headers=headers,
                timeout=10,
            )
            connected = resp.status_code == 200
            data = resp.json() if connected else {}
            finding_count = data.get("count", 0) if connected else 0
    except Exception as e:
        logger.warning("DefectDojo status check failed: %s", e)
        connected = False
        finding_count = 0

    return {
        "connected": connected,
        "url": config.get("base_url", ""),
        "finding_count": finding_count,
    }


@router.get("/findings")
async def get_findings(limit: int = 100):
    """Fetch recent findings from DB."""
    from app.core.database import database, findings
    query = (
        findings.select()
        .where(findings.c.source == "defectdojo")
        .order_by(findings.c.created_at.desc())
        .limit(limit)
    )
    rows = await database.fetch_all(query)
    return {"findings": [dict(r) for r in rows], "count": len(rows)}
