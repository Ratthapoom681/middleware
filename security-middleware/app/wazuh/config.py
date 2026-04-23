"""Wazuh-specific configuration helpers."""

from app.settings.models import settings_manager


def get_wazuh_config() -> dict:
    """Return current Wazuh config from the live SettingsManager."""
    return settings_manager.get("wazuh")
