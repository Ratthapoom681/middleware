"""
Tests for configuration normalization.
"""

from __future__ import annotations

from pathlib import Path

from src import config as config_module
from src.config import _build_config, load_config


def test_build_config_normalizes_legacy_dojo_aliases():
    config = _build_config({
        "dojo": {
            "base_url": "https://dojo.example.com/api/v2",
            "api_key": "Token abc",
        },
        "redmine": {
            "routing_rules": [
                {
                    "enabled": True,
                    "source": "dojo",
                    "match_type": "exact",
                    "match_value": "payments.example.com",
                    "tracker_id": 7,
                }
            ]
        },
    })

    assert config.defectdojo.base_url == "https://dojo.example.com/api/v2"
    assert config.redmine.routing_rules[0].source == "defectdojo"


def test_defectdojo_config_normalizes_scope_and_checkpoint_fields():
    config = _build_config({
        "defectdojo": {
            "product_ids": "10, 20",
            "engagement_ids": ["30", 40],
            "test_ids": 50,
            "active": "false",
            "verified": "true",
            "updated_since_minutes": "15",
            "fetch_limit": "250",
            "checkpoint_path": "data/custom_checkpoint.json",
        }
    })

    assert config.defectdojo.product_ids == [10, 20]
    assert config.defectdojo.engagement_ids == [30, 40]
    assert config.defectdojo.test_ids == [50]
    assert config.defectdojo.active is False
    assert config.defectdojo.verified is True
    assert config.defectdojo.updated_since_minutes == 15
    assert config.defectdojo.fetch_limit == 250
    assert config.defectdojo.cursor_path == "data/custom_checkpoint.json"


def test_filter_config_builds_advanced_json_rules():
    config = _build_config({
        "pipeline": {
            "filter": {
                "default_action": "drop",
                "json_rules": [
                    {
                        "name": "keep-fortigate-attacks",
                        "enabled": "true",
                        "source": "WAZUH",
                        "action": "keep",
                        "match": "all",
                        "conditions": [
                            {"path": "decoder.name", "op": "equals", "value": "fortigate-firewall-v6"},
                            {"path": "rule.groups", "op": "contains", "value": "attack"},
                        ],
                    }
                ],
            }
        }
    })

    assert config.pipeline.filter.default_action == "drop"
    assert len(config.pipeline.filter.json_rules) == 1
    rule = config.pipeline.filter.json_rules[0]
    assert rule.enabled is True
    assert rule.source == "wazuh"
    assert rule.action == "keep"
    assert rule.match == "all"
    assert rule.conditions[0].path == "decoder.name"
    assert rule.conditions[1].op == "contains"


def test_storage_config_builds_postgres_backend():
    config = _build_config({
        "storage": {
            "backend": "postgres",
            "postgres_dsn": "postgresql://middleware:secret@db/security",
            "postgres_schema": "middleware",
            "dedup_table": "seen_hashes",
            "checkpoint_table": "checkpoints",
        }
    })

    assert config.storage.backend == "postgres"
    assert config.storage.postgres_dsn == "postgresql://middleware:secret@db/security"
    assert config.storage.postgres_schema == "middleware"
    assert config.storage.dedup_table == "seen_hashes"
    assert config.storage.checkpoint_table == "checkpoints"


def test_load_config_resolves_relative_paths_from_project_root(workspace_tmp_dir, monkeypatch):
    project_root = workspace_tmp_dir
    config_dir = project_root / "config"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.yaml"
    config_path.write_text(
        """
wazuh:
  base_url: https://wazuh.example.local:55000
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(config_module, "PROJECT_ROOT", project_root)
    monkeypatch.chdir(Path.cwd().anchor)

    loaded = load_config("config/config.yaml")

    assert loaded.wazuh.base_url == "https://wazuh.example.local:55000"
    assert loaded._loaded_path == str(config_path.resolve())
