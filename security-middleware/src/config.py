"""
Configuration loader.

Reads the YAML config file and provides typed access to all settings.
Supports environment variable overrides for sensitive values.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# Default config search paths
DEFAULT_CONFIG_PATHS = [
    Path("config/config.yaml"),
    Path("config.yaml"),
    Path("/etc/security-middleware/config.yaml"),
]


@dataclass
class WazuhConfig:
    base_url: str = "https://localhost:55000"
    indexer_url: str = "https://localhost:9200"
    username: str = "wazuh"
    password: str = "changeme"
    indexer_username: str = "admin"
    indexer_password: str = "admin"
    verify_ssl: bool = False
    min_level: int = 7
    # Path to Wazuh alerts.json file (if set, reads from file instead of Indexer API)
    alerts_json_path: str = ""


@dataclass
class DefectDojoConfig:
    enabled: bool = False
    base_url: str = "https://localhost:8080/api/v2"
    api_key: str = "Token changeme"
    verify_ssl: bool = True
    severity_filter: list[str] = field(default_factory=lambda: ["Critical", "High", "Medium"])


@dataclass
class RedmineConfig:
    base_url: str = "https://localhost:3000"
    api_key: str = "changeme"
    project_id: str = "security-incidents"
    tracker_id: int = 1
    dedup_custom_field_id: Optional[int] = None
    priority_map: dict[str, int] = field(default_factory=lambda: {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    })


@dataclass
class FilterConfig:
    min_severity: str = "low"
    exclude_rule_ids: list[str] = field(default_factory=list)
    include_hosts: list[str] = field(default_factory=list)
    exclude_title_patterns: list[str] = field(default_factory=list)


@dataclass
class DedupConfig:
    enabled: bool = True
    db_path: str = "data/dedup.db"
    ttl_hours: int = 168  # 7 days


@dataclass
class EnrichmentConfig:
    asset_inventory_enabled: bool = False
    asset_inventory_path: str = "config/assets.yaml"
    add_remediation_links: bool = True


@dataclass
class PipelineConfig:
    poll_interval: int = 300            # seconds between each poll cycle
    initial_lookback_minutes: int = 1440  # how far back to look on first poll (default 24h)
    filter: FilterConfig = field(default_factory=FilterConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


@dataclass
class AppConfig:
    """Root configuration object."""
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    defectdojo: DefectDojoConfig = field(default_factory=DefectDojoConfig)
    redmine: RedmineConfig = field(default_factory=RedmineConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Override config values with environment variables where set.

    Convention:
      WAZUH_BASE_URL      → wazuh.base_url
      WAZUH_USERNAME       → wazuh.username
      WAZUH_PASSWORD       → wazuh.password
      DEFECTDOJO_BASE_URL  → defectdojo.base_url
      DEFECTDOJO_API_KEY   → defectdojo.api_key
      REDMINE_BASE_URL     → redmine.base_url
      REDMINE_API_KEY      → redmine.api_key
    """
    env_map = {
        "WAZUH_BASE_URL": ("wazuh", "base_url"),
        "WAZUH_USERNAME": ("wazuh", "username"),
        "WAZUH_PASSWORD": ("wazuh", "password"),
        "DEFECTDOJO_BASE_URL": ("defectdojo", "base_url"),
        "DEFECTDOJO_API_KEY": ("defectdojo", "api_key"),
        "REDMINE_BASE_URL": ("redmine", "base_url"),
        "REDMINE_API_KEY": ("redmine", "api_key"),
    }

    for env_var, (section, key) in env_map.items():
        value = os.environ.get(env_var)
        if value is not None:
            if section not in raw:
                raw[section] = {}
            raw[section][key] = value
            logger.debug("Config override from env: %s", env_var)

    return raw


def _build_config(raw: dict[str, Any]) -> AppConfig:
    """Build typed AppConfig from raw dictionary."""
    wazuh = WazuhConfig(**raw.get("wazuh", {}))
    defectdojo = DefectDojoConfig(**raw.get("defectdojo", {}))
    redmine = RedmineConfig(**raw.get("redmine", {}))

    pipeline_raw = raw.get("pipeline", {})
    pipeline = PipelineConfig(
        poll_interval=pipeline_raw.get("poll_interval", 300),
        filter=FilterConfig(**pipeline_raw.get("filter", {})),
        dedup=DedupConfig(**pipeline_raw.get("dedup", {})),
        enrichment=EnrichmentConfig(**pipeline_raw.get("enrichment", {})),
    )

    logging_cfg = LoggingConfig(**raw.get("logging", {}))

    return AppConfig(
        wazuh=wazuh,
        defectdojo=defectdojo,
        redmine=redmine,
        pipeline=pipeline,
        logging=logging_cfg,
    )


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """
    Load configuration from YAML file with env var overrides.

    Args:
        config_path: Explicit path to config file. If None, searches
                     DEFAULT_CONFIG_PATHS.

    Returns:
        Fully populated AppConfig instance.

    Raises:
        FileNotFoundError: If no config file found.
    """
    path: Optional[Path] = None

    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
    else:
        for candidate in DEFAULT_CONFIG_PATHS:
            if candidate.exists():
                path = candidate
                break

    raw: dict[str, Any] = {}
    if path and path.exists():
        logger.info("Loading config from: %s", path)
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    else:
        logger.warning("No config file found, using defaults + env vars")

    raw = _apply_env_overrides(raw)
    config = _build_config(raw)

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.logging.level.upper(), logging.INFO),
        format=config.logging.format,
    )

    return config
