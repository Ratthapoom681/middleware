"""
Settings DB models – CRUD operations on the settings table.
Also exposes the SettingsManager singleton for real-time config.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.database import database, settings_table
from app.core.logger import logger


# ── DB CRUD ──────────────────────────────────────────────────────────

async def get_all_settings() -> list[dict]:
    """Return all settings sections."""
    query = settings_table.select()
    rows = await database.fetch_all(query)
    return [
        {
            "section": row["section"],
            "config": json.loads(row["config_json"]) if row["config_json"] else {},
            "updated_at": str(row["updated_at"]) if row["updated_at"] else None,
        }
        for row in rows
    ]


async def get_section(section: str) -> Optional[dict]:
    """Return a single section config."""
    query = settings_table.select().where(settings_table.c.section == section)
    row = await database.fetch_one(query)
    if row is None:
        return None
    return {
        "section": row["section"],
        "config": json.loads(row["config_json"]) if row["config_json"] else {},
        "updated_at": str(row["updated_at"]) if row["updated_at"] else None,
    }


async def upsert_section(section: str, config: dict[str, Any]) -> dict:
    """Insert or update a settings section and trigger hot-reload."""
    config_json = json.dumps(config)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    existing = await database.fetch_one(
        settings_table.select().where(settings_table.c.section == section)
    )

    if existing:
        await database.execute(
            settings_table.update()
            .where(settings_table.c.section == section)
            .values(config_json=config_json, updated_at=now)
        )
    else:
        await database.execute(
            settings_table.insert().values(
                section=section, config_json=config_json, updated_at=now
            )
        )

    # Hot-reload the SettingsManager
    await settings_manager.reload()
    logger.info("Settings section '%s' updated and reloaded", section)

    return {"section": section, "config": config, "updated_at": str(now)}


# ── SETTINGS MANAGER (in-memory live config) ─────────────────────────

# Default values for every section
_DEFAULTS: dict[str, dict] = {
    "wazuh": {
        "base_url": "",
        "username": "",
        "password": "",
        "indexer_url": "",
        "indexer_username": "",
        "indexer_password": "",
        "alerts_json_path": "",
        "min_level": 7,
        "verify_ssl": False,
    },
    "defectdojo": {
        "enabled": False,
        "base_url": "",
        "api_key": "",
        "verify_ssl": False,
        "severity_filter": [],
        "product_ids": [],
        "engagement_ids": [],
        "test_ids": [],
        "active": True,
        "verified": False,
        "updated_since_minutes": 0,
        "fetch_limit": 1000,
    },
    "redmine": {
        "base_url": "",
        "api_key": "",
        "project_id": "security",
        "tracker_id": 1,
        "enable_parent_issues": False,
        "parent_tracker_id": None,
        "dedup_custom_field_id": None,
        "priority_map": {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        },
        "routing_rules": [],
    },
    "pipeline": {
        "poll_interval": 300,
        "initial_lookback_minutes": 1440,
    },
    "filter": {
        "min_severity": "info",
        "exclude_rule_ids": [],
        "exclude_title_patterns": [],
        "include_hosts": [],
        "default_action": "keep",
        "json_rules": [],
    },
    "dedup": {
        "enabled": True,
        "db_path": "data/dedup.db",
        "ttl_hours": 168,
    },
    "enrichment": {
        "asset_inventory_enabled": False,
        "asset_inventory_path": "config/assets.yaml",
        "add_remediation_links": True,
    },
    "severity_map": {
        "wazuh_level_map": {},
        "defectdojo_severity_map": {},
    },
    "storage": {
        "backend": "local",
        "postgres_dsn": "",
        "postgres_schema": "public",
        "dedup_table": "middleware_seen_hashes",
        "checkpoint_table": "middleware_checkpoints",
        "ticket_state_table": "middleware_ticket_state",
        "outbound_queue_table": "middleware_outbound_queue",
        "ingest_event_table": "middleware_ingest_events",
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    },
}


class _SettingsManager:
    """
    In-memory singleton that holds the live configuration.
    Modules read from this instead of hitting the DB every time.
    Call reload() after any DB write to refresh.
    """

    def __init__(self):
        self._config: dict[str, dict] = {}
        self._loaded = False

    async def reload(self):
        """Reload all sections from the DB into memory."""
        sections = await get_all_settings()
        new_config: dict[str, dict] = {}

        for section_name, defaults in _DEFAULTS.items():
            new_config[section_name] = dict(defaults)

        for row in sections:
            section_name = row["section"]
            if section_name in new_config:
                new_config[section_name].update(row["config"])
            else:
                new_config[section_name] = row["config"]

        self._config = new_config
        self._loaded = True
        logger.info("SettingsManager reloaded (%d sections)", len(self._config))

    def get(self, section: str) -> dict:
        """Get a section's config dict. Returns defaults if not loaded."""
        if not self._loaded:
            return dict(_DEFAULTS.get(section, {}))
        return dict(self._config.get(section, _DEFAULTS.get(section, {})))

    def get_all(self) -> dict[str, dict]:
        """Return all sections."""
        if not self._loaded:
            return {k: dict(v) for k, v in _DEFAULTS.items()}
        return {k: dict(v) for k, v in self._config.items()}


settings_manager = _SettingsManager()
