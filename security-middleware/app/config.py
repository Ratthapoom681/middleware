"""
Centralised configuration – loads .env and exposes a Settings object.
Only bootstrap values (DB, host, port, log) live here.
All integration config is stored in the DB settings table.

Also provides typed dataclass definitions that pipeline stages and source
clients require, along with a factory function to construct them from the
SettingsManager's plain-dict representation.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()

# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class _Settings:
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/db/middleware.db")

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "data/logs/middleware.log")


settings = _Settings()


# ── Typed Config Dataclasses ─────────────────────────────────────────
# These are consumed by pipeline stages and source clients.

@dataclass
class WazuhConfig:
    base_url: str = ""
    username: str = ""
    password: str = ""
    indexer_url: str = ""
    indexer_username: str = ""
    indexer_password: str = ""
    alerts_json_path: str = ""
    min_level: int = 7
    verify_ssl: bool = False
    webhook_api_key: str = ""
    polling_enabled: bool = True


@dataclass
class DefectDojoConfig:
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    verify_ssl: bool = False
    severity_filter: list[str] = field(default_factory=list)
    product_ids: list[int] = field(default_factory=list)
    engagement_ids: list[int] = field(default_factory=list)
    test_ids: list[int] = field(default_factory=list)
    active: bool = True
    verified: bool = False
    updated_since_minutes: int = 0
    fetch_limit: int = 1000
    cursor_path: str = "data/defectdojo_cursor.json"


@dataclass
class RoutingRuleConfig:
    enabled: bool = True
    source: str = "any"
    match_type: str = "exact"     # exact | prefix | regex
    match_value: str = ""
    tracker_id: Optional[int] = None
    use_parent: bool = False
    parent_tracker_id: Optional[int] = None


@dataclass
class RedmineConfig:
    base_url: str = ""
    api_key: str = ""
    project_id: str = "security"
    tracker_id: int = 1
    enable_parent_issues: bool = False
    parent_tracker_id: Optional[int] = None
    dedup_custom_field_id: Optional[int] = None
    priority_map: dict[str, int] = field(default_factory=lambda: {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    })
    routing_rules: list[RoutingRuleConfig] = field(default_factory=list)


@dataclass
class JSONFilterConditionConfig:
    path: str = ""
    op: str = "equals"       # equals | not_equals | contains | regex | in | not_in | gt | gte | lt | lte | exists
    value: Any = None


@dataclass
class JSONFilterRuleConfig:
    name: str = ""
    enabled: bool = True
    source: str = "any"
    match: str = "all"       # all | any
    action: str = "keep"     # keep | drop
    conditions: list[JSONFilterConditionConfig] = field(default_factory=list)


@dataclass
class FilterConfig:
    min_severity: str = "info"
    exclude_rule_ids: list[str] = field(default_factory=list)
    exclude_title_patterns: list[str] = field(default_factory=list)
    include_hosts: list[str] = field(default_factory=list)
    default_action: str = "keep"
    json_rules: list[JSONFilterRuleConfig] = field(default_factory=list)


@dataclass
class DedupConfig:
    enabled: bool = True
    db_path: str = "data/dedup.db"
    ttl_hours: int = 168


@dataclass
class EnrichmentConfig:
    asset_inventory_enabled: bool = False
    asset_inventory_path: str = "config/assets.yaml"
    add_remediation_links: bool = True


@dataclass
class StorageConfig:
    backend: str = "local"
    postgres_dsn: str = ""
    postgres_schema: str = "public"
    dedup_table: str = "middleware_seen_hashes"
    checkpoint_table: str = "middleware_checkpoints"
    ticket_state_table: str = "middleware_ticket_state"
    outbound_queue_table: str = "middleware_outbound_queue"
    ingest_event_table: str = "middleware_ingest_events"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


# ── Factory: SettingsManager dicts → typed configs ───────────────────

def _build_routing_rules(raw_rules: list[dict]) -> list[RoutingRuleConfig]:
    """Convert a list of plain dicts into typed RoutingRuleConfig objects."""
    result = []
    for r in raw_rules:
        if not isinstance(r, dict):
            continue
        result.append(RoutingRuleConfig(
            enabled=r.get("enabled", True),
            source=r.get("source", "any"),
            match_type=r.get("match_type", "exact"),
            match_value=r.get("match_value", ""),
            tracker_id=r.get("tracker_id"),
            use_parent=r.get("use_parent", False),
            parent_tracker_id=r.get("parent_tracker_id"),
        ))
    return result


def _build_json_filter_rules(raw_rules: list[dict]) -> list[JSONFilterRuleConfig]:
    """Convert a list of plain dicts into typed JSONFilterRuleConfig objects."""
    result = []
    for r in raw_rules:
        if not isinstance(r, dict):
            continue
        conditions = []
        for c in r.get("conditions", []):
            if isinstance(c, dict):
                conditions.append(JSONFilterConditionConfig(
                    path=c.get("path", ""),
                    op=c.get("op", "equals"),
                    value=c.get("value"),
                ))
        result.append(JSONFilterRuleConfig(
            name=r.get("name", ""),
            enabled=r.get("enabled", True),
            source=r.get("source", "any"),
            match=r.get("match", "all"),
            action=r.get("action", "keep"),
            conditions=conditions,
        ))
    return result


def build_typed_configs(manager) -> dict[str, Any]:
    """
    Convert SettingsManager's plain dicts into typed config dataclasses.

    Args:
        manager: An instance of SettingsManager (from app.settings.models).

    Returns:
        A dict with keys: wazuh, defectdojo, redmine, filter, dedup,
        enrichment, storage, pipeline, logging.
    """
    w = manager.get("wazuh")
    d = manager.get("defectdojo")
    r = manager.get("redmine")
    f = manager.get("filter")
    dd = manager.get("dedup")
    e = manager.get("enrichment")
    s = manager.get("storage")
    p = manager.get("pipeline")
    lg = manager.get("logging")

    wazuh = WazuhConfig(
        base_url=w.get("base_url", ""),
        username=w.get("username", ""),
        password=w.get("password", ""),
        indexer_url=w.get("indexer_url", ""),
        indexer_username=w.get("indexer_username", ""),
        indexer_password=w.get("indexer_password", ""),
        alerts_json_path=w.get("alerts_json_path", ""),
        min_level=int(w.get("min_level", 7)),
        verify_ssl=bool(w.get("verify_ssl", False)),
        webhook_api_key=w.get("webhook_api_key", ""),
        polling_enabled=bool(w.get("polling_enabled", True)),
    )

    defectdojo = DefectDojoConfig(
        enabled=bool(d.get("enabled", False)),
        base_url=d.get("base_url", ""),
        api_key=d.get("api_key", ""),
        verify_ssl=bool(d.get("verify_ssl", False)),
        severity_filter=d.get("severity_filter", []),
        product_ids=[int(x) for x in d.get("product_ids", []) if x],
        engagement_ids=[int(x) for x in d.get("engagement_ids", []) if x],
        test_ids=[int(x) for x in d.get("test_ids", []) if x],
        active=bool(d.get("active", True)),
        verified=bool(d.get("verified", False)),
        updated_since_minutes=int(d.get("updated_since_minutes", 0)),
        fetch_limit=int(d.get("fetch_limit", 1000)),
        cursor_path=d.get("cursor_path", "data/defectdojo_cursor.json"),
    )

    redmine = RedmineConfig(
        base_url=r.get("base_url", ""),
        api_key=r.get("api_key", ""),
        project_id=r.get("project_id", "security"),
        tracker_id=int(r.get("tracker_id", 1)),
        enable_parent_issues=bool(r.get("enable_parent_issues", False)),
        parent_tracker_id=r.get("parent_tracker_id"),
        dedup_custom_field_id=r.get("dedup_custom_field_id"),
        priority_map=r.get("priority_map", {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}),
        routing_rules=_build_routing_rules(r.get("routing_rules", [])),
    )

    filter_config = FilterConfig(
        min_severity=f.get("min_severity", "info"),
        exclude_rule_ids=f.get("exclude_rule_ids", []),
        exclude_title_patterns=f.get("exclude_title_patterns", []),
        include_hosts=f.get("include_hosts", []),
        default_action=f.get("default_action", "keep"),
        json_rules=_build_json_filter_rules(f.get("json_rules", [])),
    )

    dedup_config = DedupConfig(
        enabled=bool(dd.get("enabled", True)),
        db_path=dd.get("db_path", "data/dedup.db"),
        ttl_hours=int(dd.get("ttl_hours", 168)),
    )

    enrichment_config = EnrichmentConfig(
        asset_inventory_enabled=bool(e.get("asset_inventory_enabled", False)),
        asset_inventory_path=e.get("asset_inventory_path", "config/assets.yaml"),
        add_remediation_links=bool(e.get("add_remediation_links", True)),
    )

    storage_config = StorageConfig(
        backend=s.get("backend", "local"),
        postgres_dsn=s.get("postgres_dsn", ""),
        postgres_schema=s.get("postgres_schema", "public"),
        dedup_table=s.get("dedup_table", "middleware_seen_hashes"),
        checkpoint_table=s.get("checkpoint_table", "middleware_checkpoints"),
        ticket_state_table=s.get("ticket_state_table", "middleware_ticket_state"),
        outbound_queue_table=s.get("outbound_queue_table", "middleware_outbound_queue"),
        ingest_event_table=s.get("ingest_event_table", "middleware_ingest_events"),
    )

    logging_config = LoggingConfig(
        level=lg.get("level", "INFO"),
        format=lg.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s"),
    )

    return {
        "wazuh": wazuh,
        "defectdojo": defectdojo,
        "redmine": redmine,
        "filter": filter_config,
        "dedup": dedup_config,
        "enrichment": enrichment_config,
        "storage": storage_config,
        "pipeline": p,           # plain dict — only poll_interval and lookback are used
        "logging": logging_config,
    }
