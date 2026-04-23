"""Log aggregator – unified view across all sources."""

from app.core.database import database, findings


async def get_aggregated_logs(source: str = "all", level: str = "all", limit: int = 100) -> list[dict]:
    """Fetch findings from all sources with optional filters."""
    query = findings.select().order_by(findings.c.created_at.desc()).limit(limit)

    if source != "all":
        query = query.where(findings.c.source == source)
    if level != "all":
        query = query.where(findings.c.severity == level)

    rows = await database.fetch_all(query)
    return [dict(r) for r in rows]


async def get_log_stats() -> dict:
    """Aggregate stats for the dashboard."""
    import sqlalchemy as sa

    total = await database.fetch_val(sa.select(sa.func.count()).select_from(findings))
    by_source = {}
    for source in ("wazuh", "defectdojo"):
        count = await database.fetch_val(
            sa.select(sa.func.count()).select_from(findings).where(findings.c.source == source)
        )
        by_source[source] = count or 0

    return {
        "total_findings": total or 0,
        "by_source": by_source,
    }
