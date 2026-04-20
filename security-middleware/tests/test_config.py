"""
Tests for configuration normalization.
"""

from __future__ import annotations

from src.config import _build_config


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
