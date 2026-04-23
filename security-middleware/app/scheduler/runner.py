"""
Background pipeline scheduler.

Runs the PipelineOrchestrator on a configurable interval as an
asyncio background task within the FastAPI application lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from app.settings.models import settings_manager
from app.core.pipeline.orchestrator import pipeline_orchestrator

logger = logging.getLogger(__name__)

# Reference to the running background task
_background_task: asyncio.Task | None = None


async def _pipeline_loop() -> None:
    """
    Background loop that periodically runs the pipeline.

    Reads `poll_interval` from SettingsManager each cycle so changes
    from the UI take effect immediately without a restart.
    """
    # Wait a few seconds after startup to let the DB fully initialise
    await asyncio.sleep(5)

    logger.info("Background pipeline scheduler started")

    while True:
        try:
            pipeline_cfg = settings_manager.get("pipeline")
            poll_interval = int(pipeline_cfg.get("poll_interval", 300))
            poll_interval = max(10, poll_interval)  # floor at 10s

            logger.info(
                "Pipeline scheduler: next run in %ds (at %s)",
                poll_interval,
                (datetime.now(timezone.utc)).strftime("%H:%M:%S UTC"),
            )

            await asyncio.sleep(poll_interval)

            # Rebuild clients on each cycle to pick up config changes
            pipeline_orchestrator.rebuild()
            stats = await pipeline_orchestrator.run_once()

            logger.info("Pipeline scheduler: cycle complete — %s", stats)

        except asyncio.CancelledError:
            logger.info("Pipeline scheduler: shutting down")
            raise
        except Exception:
            logger.exception("Pipeline scheduler: unhandled error, will retry next cycle")
            # Sleep a bit before retrying to avoid tight error loops
            await asyncio.sleep(30)


def start_background_pipeline() -> asyncio.Task:
    """
    Create and return the background asyncio task.

    Should be called from the FastAPI lifespan context manager.
    """
    global _background_task
    _background_task = asyncio.create_task(_pipeline_loop())
    return _background_task


async def trigger_immediate_run() -> dict:
    """
    Trigger an immediate pipeline run (used by the manual trigger API).

    This runs the orchestrator once outside of the regular schedule.
    """
    try:
        pipeline_orchestrator.rebuild()
        stats = await pipeline_orchestrator.run_once()
        return {"status": "ok", "stats": stats}
    except Exception as exc:
        logger.exception("Immediate pipeline run failed")
        return {"status": "error", "message": str(exc)}
