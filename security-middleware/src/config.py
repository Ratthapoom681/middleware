"""
Configuration loader.

Reads the YAML config file and provides typed access to all settings.
Supports environment variable overrides for sensitive values.
"""

from __future__ import annotations

import copy
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


def _normalize_bool(value: Any, default: bool) -> bool:
    """Coerce permissive config values into booleans."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _normalize_int(value: Any, default: int) -> int:
    """Coerce a scalar into an integer, preserving defaults on bad input."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_string_list(value: Any) -> list[str]:
    """Normalize YAML/JSON scalar-or-list inputs into a string list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(value).strip()] if str(value).strip() else []


def _normalize_int_list(value: Any) -> list[int]:
    """Normalize YAML/JSON scalar-or-list inputs into an integer list."""
    values = _normalize_string_list(value)
    normalized: list[int] = []
    for item in values:
        try:
            normalized.append(int(item))
        except (TypeError, ValueError):
            logger.warning("Ignoring non-integer DefectDojo scope value: %r", item)
    return normalized


def _normalize_routing_source(value: Any) -> str:
    """Collapse legacy routing aliases onto the canonical source keys."""
    normalized = str(value or "wazuh").strip().lower()
    if normalized == "dojo":
        return "defectdojo"
    return normalized or "wazuh"


def _normalize_raw_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply legacy aliases and compatibility shims before dataclass hydration."""
    normalized = copy.deepcopy(raw)

    if "dojo" in normalized and "defectdojo" not in normalized:
        normalized["defectdojo"] = normalized["dojo"]
    normalized.pop("dojo", None)

    defectdojo_raw = normalized.get("defectdojo", {})
    if isinstance(defectdojo_raw, dict):
        if "checkpoint_path" in defectdojo_raw and "cursor_path" not in defectdojo_raw:
            defectdojo_raw["cursor_path"] = defectdojo_raw["checkpoint_path"]
        defectdojo_raw.pop("checkpoint_path", None)

    redmine_raw = normalized.get("redmine", {})
    rules_raw = redmine_raw.get("routing_rules", [])
    if isinstance(rules_raw, list):
        for rule in rules_raw:
            if isinstance(rule, dict):
                rule["source"] = _normalize_routing_source(rule.get("source"))

    return normalized


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
    product_ids: list[int] = field(default_factory=list)
    engagement_ids: list[int] = field(default_factory=list)
    test_ids: list[int] = field(default_factory=list)
    active: bool = True
    verified: bool = True
    updated_since_minutes: int = 0
    fetch_limit: int = 1000
    cursor_path: str = "data/defectdojo_cursor.json"

    def __post_init__(self) -> None:
        self.enabled = _normalize_bool(self.enabled, False)
        self.verify_ssl = _normalize_bool(self.verify_ssl, True)
        self.severity_filter = _normalize_string_list(self.severity_filter)
        self.product_ids = _normalize_int_list(self.product_ids)
        self.engagement_ids = _normalize_int_list(self.engagement_ids)
        self.test_ids = _normalize_int_list(self.test_ids)
        self.active = _normalize_bool(self.active, True)
        self.verified = _normalize_bool(self.verified, True)
        self.updated_since_minutes = max(0, _normalize_int(self.updated_since_minutes, 0))
        self.fetch_limit = max(0, _normalize_int(self.fetch_limit, 1000))
        self.cursor_path = str(self.cursor_path or "data/defectdojo_cursor.json")


@dataclass
class RedmineRoutingRule:
    enabled: bool = True
    source: str = "wazuh"   # "wazuh", "defectdojo", "any"
    match_type: str = "exact"   # exact, prefix, regex
    match_value: str = ""
    tracker_id: Optional[int] = None
    use_parent: bool = False
    parent_tracker_id: Optional[int] = None

    def __post_init__(self) -> None:
        self.enabled = _normalize_bool(self.enabled, True)
        self.source = _normalize_routing_source(self.source)
        self.match_type = str(self.match_type or "exact").strip().lower() or "exact"
        self.match_value = str(self.match_value or "")
        self.use_parent = _normalize_bool(self.use_parent, False)
        self.tracker_id = None if self.tracker_id in ("", None) else _normalize_int(self.tracker_id, 0) or None
        self.parent_tracker_id = None if self.parent_tracker_id in ("", None) else _normalize_int(self.parent_tracker_id, 0) or None


@dataclass
class RedmineConfig:
    base_url: str = "https://localhost:3000"
    api_key: str = "changeme"
    project_id: str = "security-incidents"
    tracker_id: int = 1
    enable_parent_issues: bool = False
    parent_tracker_id: Optional[int] = None
    dedup_custom_field_id: Optional[int] = None
    routing_rules: list[RedmineRoutingRule] = field(default_factory=list)
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
    default_action: str = "keep"
    json_rules: list["JSONFilterRuleConfig"] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.min_severity = str(self.min_severity or "low").strip().lower() or "low"
        self.exclude_rule_ids = _normalize_string_list(self.exclude_rule_ids)
        self.include_hosts = _normalize_string_list(self.include_hosts)
        self.exclude_title_patterns = _normalize_string_list(self.exclude_title_patterns)

        self.default_action = str(self.default_action or "keep").strip().lower() or "keep"
        if self.default_action not in {"keep", "drop"}:
            raise ValueError("pipeline.filter.default_action must be 'keep' or 'drop'")

        normalized_rules: list[JSONFilterRuleConfig] = []
        for rule in self.json_rules or []:
            if isinstance(rule, JSONFilterRuleConfig):
                normalized_rules.append(rule)
            elif isinstance(rule, dict):
                normalized_rules.append(JSONFilterRuleConfig(**rule))
            else:
                raise ValueError("pipeline.filter.json_rules entries must be objects")
        self.json_rules = normalized_rules


@dataclass
class JSONFilterConditionConfig:
    path: str = ""
    op: str = "equals"
    value: Any = None

    def __post_init__(self) -> None:
        self.path = str(self.path or "").strip()
        if not self.path:
            raise ValueError("pipeline.filter.json_rules conditions require a non-empty path")

        self.op = str(self.op or "equals").strip().lower() or "equals"
        valid_ops = {
            "equals",
            "not_equals",
            "contains",
            "regex",
            "in",
            "not_in",
            "gt",
            "gte",
            "lt",
            "lte",
            "exists",
        }
        if self.op not in valid_ops:
            raise ValueError(
                f"pipeline.filter.json_rules condition operator '{self.op}' is not supported"
            )


@dataclass
class JSONFilterRuleConfig:
    name: str = ""
    enabled: bool = True
    source: str = "any"  # wazuh, defectdojo, any
    action: str = "drop"  # keep, drop
    match: str = "all"  # all, any
    conditions: list[JSONFilterConditionConfig] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.name = str(self.name or "").strip()
        self.enabled = _normalize_bool(self.enabled, True)
        self.source = str(self.source or "any").strip().lower() or "any"
        self.action = str(self.action or "drop").strip().lower() or "drop"
        self.match = str(self.match or "all").strip().lower() or "all"

        if self.source not in {"wazuh", "defectdojo", "any"}:
            raise ValueError("pipeline.filter.json_rules source must be 'wazuh', 'defectdojo', or 'any'")
        if self.action not in {"keep", "drop"}:
            raise ValueError("pipeline.filter.json_rules action must be 'keep' or 'drop'")
        if self.match not in {"all", "any"}:
            raise ValueError("pipeline.filter.json_rules match must be 'all' or 'any'")

        normalized_conditions: list[JSONFilterConditionConfig] = []
        for condition in self.conditions or []:
            if isinstance(condition, JSONFilterConditionConfig):
                normalized_conditions.append(condition)
            elif isinstance(condition, dict):
                normalized_conditions.append(JSONFilterConditionConfig(**condition))
            else:
                raise ValueError("pipeline.filter.json_rules conditions must be objects")
        self.conditions = normalized_conditions


@dataclass
class DedupConfig:
    enabled: bool = True
    db_path: str = "data/dedup.db"
    ttl_hours: int = 168  # 7 days


@dataclass
class StorageConfig:
    backend: str = "local"  # local or postgres
    postgres_dsn: str = ""
    postgres_schema: str = "public"
    dedup_table: str = "middleware_seen_hashes"
    checkpoint_table: str = "middleware_checkpoints"

    def __post_init__(self) -> None:
        self.backend = str(self.backend or "local").strip().lower() or "local"
        if self.backend not in {"local", "postgres"}:
            raise ValueError("storage.backend must be 'local' or 'postgres'")

        self.postgres_dsn = str(self.postgres_dsn or "").strip()
        self.postgres_schema = str(self.postgres_schema or "public").strip() or "public"
        self.dedup_table = str(self.dedup_table or "middleware_seen_hashes").strip() or "middleware_seen_hashes"
        self.checkpoint_table = str(self.checkpoint_table or "middleware_checkpoints").strip() or "middleware_checkpoints"


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
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    _loaded_path: str = ""


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Override config values with environment variables where set.

    Convention:
      WAZUH_BASE_URL      → wazuh.base_url
      WAZUH_USERNAME       → wazuh.username
      WAZUH_PASSWORD       → wazuh.password
      DEFECTDOJO_BASE_URL  → defectdojo.base_url
      DEFECTDOJO_API_KEY   → defectdojo.api_key
      STATE_BACKEND        → storage.backend
      STATE_POSTGRES_DSN   → storage.postgres_dsn
      REDMINE_BASE_URL     → redmine.base_url
      REDMINE_API_KEY      → redmine.api_key
    """
    env_map = {
        "WAZUH_BASE_URL": ("wazuh", "base_url"),
        "WAZUH_USERNAME": ("wazuh", "username"),
        "WAZUH_PASSWORD": ("wazuh", "password"),
        "DEFECTDOJO_BASE_URL": ("defectdojo", "base_url"),
        "DEFECTDOJO_API_KEY": ("defectdojo", "api_key"),
        "STATE_BACKEND": ("storage", "backend"),
        "STATE_POSTGRES_DSN": ("storage", "postgres_dsn"),
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

    normalized_raw = _normalize_raw_config(raw)

    wazuh = WazuhConfig(**normalized_raw.get("wazuh", {}))
    defectdojo = DefectDojoConfig(**normalized_raw.get("defectdojo", {}))
    redmine_raw = normalized_raw.get("redmine", {})
    rules_raw = redmine_raw.get("routing_rules", [])
    routing_rules = []
    for r in rules_raw:
        routing_rules.append(RedmineRoutingRule(**r))
    
    redmine = RedmineConfig(
        base_url=redmine_raw.get("base_url", "https://localhost:3000"),
        api_key=redmine_raw.get("api_key", "changeme"),
        project_id=redmine_raw.get("project_id", "security-incidents"),
        tracker_id=redmine_raw.get("tracker_id", 1),
        enable_parent_issues=redmine_raw.get("enable_parent_issues", False),
        parent_tracker_id=redmine_raw.get("parent_tracker_id"),
        dedup_custom_field_id=redmine_raw.get("dedup_custom_field_id"),
        priority_map=redmine_raw.get("priority_map", {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1
        }),
        routing_rules=routing_rules
    )

    pipeline_raw = normalized_raw.get("pipeline", {})
    pipeline = PipelineConfig(
        poll_interval=pipeline_raw.get("poll_interval", 300),
        initial_lookback_minutes=pipeline_raw.get("initial_lookback_minutes", 1440),
        filter=FilterConfig(**pipeline_raw.get("filter", {})),
        dedup=DedupConfig(**pipeline_raw.get("dedup", {})),
        enrichment=EnrichmentConfig(**pipeline_raw.get("enrichment", {})),
    )
    storage = StorageConfig(**normalized_raw.get("storage", {}))

    logging_cfg = LoggingConfig(**normalized_raw.get("logging", {}))

    return AppConfig(
        wazuh=wazuh,
        defectdojo=defectdojo,
        redmine=redmine,
        pipeline=pipeline,
        storage=storage,
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
    loaded_successfully = False

    if path and path.exists():
        logger.info("Loading config from: %s", path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
                loaded_successfully = True
        except yaml.YAMLError as e:
            logger.error("Failed to parse config file '%s': %s", path, e)
    else:
        logger.warning("No regular config file found.")

    # Fallback to backups if primary is missing or invalid (and not explicitly passed via CLI)
    if not loaded_successfully and not config_path:
        backup_dir = Path("config/backups")
        if backup_dir.exists() and backup_dir.is_dir():
            backups = list(backup_dir.glob("*.yaml"))
            if backups:
                # Sort by last modified time descending
                backups.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                backup_path = backups[0]
                logger.warning("Falling back to most recent backup config: %s", backup_path)
                try:
                    with open(backup_path, "r", encoding="utf-8") as f:
                        raw = yaml.safe_load(f) or {}
                        path = backup_path
                        loaded_successfully = True
                except yaml.YAMLError as e:
                    logger.error("Fallback backup config also failed to parse: %s", e)

    if not loaded_successfully:
        logger.warning("No loadable configuration found, using defaults + env vars")

    raw = _apply_env_overrides(raw)
    config = _build_config(raw)
    if path and loaded_successfully:
        config._loaded_path = str(path)

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.logging.level.upper(), logging.INFO),
        format=config.logging.format,
    )

    return config
