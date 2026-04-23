"""Settings API routes."""

from fastapi import APIRouter
from app.settings import models
from app.settings.schema import SettingsUpdate
from app.core.websocket import ws_manager
from app.audit.models import log_action

router = APIRouter()


@router.get("")
async def get_all():
    """Get all settings."""
    sections = await models.get_all_settings()
    # Also include defaults for sections not yet in DB
    all_config = models.settings_manager.get_all()
    return {"settings": sections, "defaults": all_config}


@router.get("/{section}")
async def get_section(section: str):
    """Get a specific settings section (DB value merged with defaults)."""
    config = models.settings_manager.get(section)
    return {"section": section, "config": config}


@router.put("/{section}")
async def update_section(section: str, body: SettingsUpdate):
    """Update a settings section. Takes effect immediately."""
    result = await models.upsert_section(section, body.config)

    # Broadcast config change to all connected WebSocket clients
    await ws_manager.broadcast({
        "type": "config_updated",
        "section": section,
    })

    # Record the change in the audit log
    await log_action(
        module="settings",
        action="update",
        detail=f"Updated section: {section}",
    )

    return result

