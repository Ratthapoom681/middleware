"""Redmine-specific configuration helpers."""

from app.settings.models import settings_manager


def get_redmine_config() -> dict:
    return settings_manager.get("redmine")
