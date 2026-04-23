"""Dead-letter queue – tracks failed findings for retry."""

from app.core.database import database, dead_letter


async def get_dead_letters(limit: int = 50) -> list[dict]:
    query = dead_letter.select().order_by(dead_letter.c.created_at.desc()).limit(limit)
    rows = await database.fetch_all(query)
    return [dict(r) for r in rows]


async def add_dead_letter(finding_id: int, error: str):
    await database.execute(
        dead_letter.insert().values(finding_id=finding_id, error=error)
    )
