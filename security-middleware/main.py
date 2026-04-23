"""
Security Middleware – FastAPI Application Entry Point
Serves both the REST API and the frontend static files.

Usage:
    python main.py
    # or
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import json
from pathlib import Path

from app.config import settings
from app.core.database import database, create_tables
from app.core.logger import logger
from app.settings.models import settings_manager

# ── Route imports ──
from app.defectdojo.routes import router as defectdojo_router
from app.wazuh.routes import router as wazuh_router
from app.redmine.routes import router as redmine_router
from app.logs.routes import router as logs_router
from app.pipeline.routes import router as pipeline_router
from app.scheduler.routes import router as scheduler_router
from app.settings.routes import router as settings_router
from app.data_retention.routes import router as retention_router
from app.audit.routes import router as audit_router


async def _seed_settings_from_yaml():
    """Seed the settings table from config/config.yaml on first run."""
    import yaml
    from app.core.database import settings_table

    row = await database.fetch_one(settings_table.select().limit(1))
    if row is not None:
        return  # Settings already exist

    yaml_path = Path(__file__).parent / "config" / "config.yaml"
    if not yaml_path.exists():
        logger.info("No config.yaml found, using built-in defaults")
        return

    with open(yaml_path) as f:
        raw = yaml.safe_load(f) or {}

    sections = {}
    for key in ("wazuh", "defectdojo", "redmine", "storage", "logging"):
        if key in raw:
            sections[key] = raw[key]

    if "pipeline" in raw:
        p = raw["pipeline"]
        sections["pipeline"] = {
            "poll_interval": p.get("poll_interval", 300),
            "initial_lookback_minutes": p.get("initial_lookback_minutes", 1440),
        }
        for sub in ("filter", "dedup", "enrichment"):
            if sub in p:
                sections[sub] = p[sub]

    for section, config in sections.items():
        await database.execute(
            settings_table.insert().values(
                section=section,
                config_json=json.dumps(config),
            )
        )

    logger.info("Seeded %d settings sections from config.yaml", len(sections))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / Shutdown lifecycle."""
    logger.info("Starting Middleware server …")
    await database.connect()
    await create_tables()
    logger.info("Database connected & tables ready")

    # Seed settings from config.yaml on first run
    await _seed_settings_from_yaml()

    # Load all settings into memory
    await settings_manager.reload()
    logger.info("Settings loaded into SettingsManager")

    yield
    await database.disconnect()
    logger.info("Middleware server stopped")


app = FastAPI(
    title="Security Middleware",
    version="1.0.0",
    description="Wazuh + DefectDojo → Pipeline → Redmine",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routes ──
app.include_router(defectdojo_router, prefix="/api/defectdojo", tags=["DefectDojo"])
app.include_router(wazuh_router, prefix="/api/wazuh", tags=["Wazuh"])
app.include_router(redmine_router, prefix="/api/redmine", tags=["Redmine"])
app.include_router(logs_router, prefix="/api/logs", tags=["Logs"])
app.include_router(pipeline_router, prefix="/api/pipeline", tags=["Pipeline"])
app.include_router(scheduler_router, prefix="/api/scheduler", tags=["Scheduler"])
app.include_router(settings_router, prefix="/api/settings", tags=["Settings"])
app.include_router(retention_router, prefix="/api/data-retention", tags=["Data Retention"])
app.include_router(audit_router, prefix="/api/audit", tags=["Audit"])

# ── Serve Frontend ──
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,  # Dev only; Docker CMD bypasses __main__
    )
