"""DefectDojo-specific configuration helpers."""

from app.settings.models import settings_manager


def get_defectdojo_config() -> dict:
    return settings_manager.get("defectdojo")
