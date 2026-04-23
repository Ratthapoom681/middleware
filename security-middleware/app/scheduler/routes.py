"""Scheduler API routes."""

from fastapi import APIRouter
from app.scheduler import jobs

router = APIRouter()


@router.get("/jobs")
async def list_jobs():
    """List all scheduled jobs."""
    return {"jobs": jobs.get_all_jobs()}


@router.post("/trigger/{job_name}")
async def trigger_job(job_name: str):
    """Manually trigger a scheduled job."""
    result = await jobs.trigger_job(job_name)
    return result
