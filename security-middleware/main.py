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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / Shutdown lifecycle."""
    logger.info("Starting Middleware server …")
    await database.connect()
    await create_tables()
    logger.info("Database connected & tables ready")

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
        reload=True,
    )
