"""Background job scheduler."""

from datetime import datetime, timezone
from app.core.logger import logger
from app.settings.models import settings_manager

_jobs = {
    "pipeline_poll": {
        "name": "pipeline_poll",
        "description": "Fetch new alerts from Wazuh and DefectDojo",
        "enabled": True,
        "last_run": None,
        "next_run": None,
    },
    "data_cleanup": {
        "name": "data_cleanup",
        "description": "Clean up old findings based on retention policy",
        "enabled": True,
        "last_run": None,
        "next_run": None,
    },
}


def get_all_jobs() -> list[dict]:
    """Return all scheduled job statuses."""
    return list(_jobs.values())


async def trigger_job(job_name: str) -> dict:
    """Manually trigger a scheduled job."""
    if job_name not in _jobs:
        return {"status": "error", "message": f"Unknown job: {job_name}"}

    _jobs[job_name]["last_run"] = datetime.now(timezone.utc).isoformat()
    logger.info("Job '%s' triggered manually", job_name)

    return {"status": "ok", "job": job_name, "message": f"Job '{job_name}' triggered"}
