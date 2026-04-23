"""
Tests for the configuration web UI and API surface.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from app import dashboard_history as dashboard_history_module
from app.defectdojo.client import DefectDojoClient
from app import server


def test_config_api_round_trips_new_defectdojo_fields(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    backup_dir = workspace_tmp_dir / "backups"
    config_path.write_text(
        yaml.safe_dump(
            {
                "defectdojo": {
                    "enabled": True,
                    "base_url": "https://dojo.example.com/api/v2",
                    "api_key": "Token test",
                    "verify_ssl": False,
                    "severity_filter": ["High", "Medium"],
                    "product_ids": [10, 20],
                    "engagement_ids": [30],
                    "test_ids": [40, 50],
                    "active": True,
                    "verified": False,
                    "updated_since_minutes": 25,
                    "fetch_limit": 250,
                    "cursor_path": "data/test_checkpoint.json",
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "BACKUP_DIR", backup_dir)

    with server.app.test_client() as client:
        response = client.get("/api/config")
        payload = response.get_json()["config"]

        assert payload["defectdojo"]["product_ids"] == [10, 20]
        assert payload["defectdojo"]["engagement_ids"] == [30]
        assert payload["defectdojo"]["test_ids"] == [40, 50]
        assert payload["defectdojo"]["active"] is True
        assert payload["defectdojo"]["verified"] is False
        assert payload["defectdojo"]["updated_since_minutes"] == 25
        assert payload["defectdojo"]["fetch_limit"] == 250

        payload["defectdojo"]["product_ids"] = [99]
        payload["defectdojo"]["engagement_ids"] = [199]
        payload["defectdojo"]["test_ids"] = [299]
        payload["defectdojo"]["updated_since_minutes"] = 5
        payload["defectdojo"]["fetch_limit"] = 10
        save_response = client.post("/api/config", json=payload)

        assert save_response.get_json()["status"] == "ok"
        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert saved["defectdojo"]["product_ids"] == [99]
        assert saved["defectdojo"]["engagement_ids"] == [199]
        assert saved["defectdojo"]["test_ids"] == [299]
        assert saved["defectdojo"]["updated_since_minutes"] == 5
        assert saved["defectdojo"]["fetch_limit"] == 10


def test_defectdojo_scope_data_endpoint_returns_products_engagements_and_tests(monkeypatch):
    def fake_scope_data(self):
        return {
            "products": [{"id": 1, "name": "Payments"}],
            "engagements": [{"id": 2, "name": "Quarterly", "product_id": 1}],
            "tests": [{"id": 3, "name": "ZAP Weekly", "engagement_id": 2, "product_id": 1}],
        }

    monkeypatch.setattr(DefectDojoClient, "fetch_scope_data", fake_scope_data)

    with server.app.test_client() as client:
        response = client.post(
            "/api/defectdojo/scope-data",
            json={
                "defectdojo": {
                    "base_url": "https://dojo.example.com/api/v2",
                    "api_key": "Token test",
                }
            },
        )

        assert response.status_code == 200
        assert response.get_json() == {
            "status": "ok",
            "products": [{"id": 1, "name": "Payments"}],
            "engagements": [{"id": 2, "name": "Quarterly", "product_id": 1}],
            "tests": [{"id": 3, "name": "ZAP Weekly", "engagement_id": 2, "product_id": 1}],
        }


def test_defectdojo_finding_count_endpoint_returns_preview_summary(monkeypatch):
    def fake_count_summary(self):
        return {
            "matching_count": 120,
            "pending_count": 15,
            "checkpoint_applied": True,
            "processing_cap": 10,
            "estimated_processed_count": 10,
        }

    monkeypatch.setattr(DefectDojoClient, "get_finding_count_summary", fake_count_summary)

    with server.app.test_client() as client:
        response = client.post(
            "/api/defectdojo/finding-count",
            json={
                "defectdojo": {
                    "base_url": "https://dojo.example.com/api/v2",
                    "api_key": "Token test",
                }
            },
        )

        assert response.status_code == 200
        assert response.get_json() == {
            "status": "ok",
            "matching_count": 120,
            "pending_count": 15,
            "checkpoint_applied": True,
            "processing_cap": 10,
            "estimated_processed_count": 10,
        }


def test_config_api_round_trips_advanced_filter_rules(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    backup_dir = workspace_tmp_dir / "backups"
    config_path.write_text(
        yaml.safe_dump(
            {
                "pipeline": {
                    "filter": {
                        "min_severity": "info",
                        "default_action": "drop",
                        "json_rules": [
                            {
                                "name": "keep-fortigate-attacks",
                                "enabled": True,
                                "source": "wazuh",
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
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "BACKUP_DIR", backup_dir)

    with server.app.test_client() as client:
        response = client.get("/api/config")
        payload = response.get_json()["config"]

        assert payload["pipeline"]["filter"]["default_action"] == "drop"
        assert payload["pipeline"]["filter"]["json_rules"][0]["name"] == "keep-fortigate-attacks"

        payload["pipeline"]["filter"]["json_rules"][0]["conditions"].append(
            {"path": "data.count", "op": "gte", "value": 5000}
        )
        save_response = client.post("/api/config", json=payload)

        assert save_response.get_json()["status"] == "ok"
        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert saved["pipeline"]["filter"]["default_action"] == "drop"
        assert len(saved["pipeline"]["filter"]["json_rules"][0]["conditions"]) == 3


def test_config_api_round_trips_storage_backend(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    backup_dir = workspace_tmp_dir / "backups"
    config_path.write_text(
        yaml.safe_dump(
            {
                "storage": {
                    "backend": "postgres",
                    "postgres_dsn": "postgresql://middleware:secret@db/security",
                    "postgres_schema": "middleware",
                    "dedup_table": "seen_hashes",
                    "checkpoint_table": "checkpoints",
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "BACKUP_DIR", backup_dir)

    with server.app.test_client() as client:
        response = client.get("/api/config")
        payload = response.get_json()["config"]

        assert payload["storage"]["backend"] == "postgres"
        assert payload["storage"]["postgres_dsn"] == "postgresql://middleware:secret@db/security"

        payload["storage"]["postgres_schema"] = "analytics"
        payload["storage"]["dedup_table"] = "dedup_state"
        save_response = client.post("/api/config", json=payload)
        assert save_response.get_json()["status"] == "ok"

        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert saved["storage"]["backend"] == "postgres"
        assert saved["storage"]["postgres_schema"] == "analytics"
        assert saved["storage"]["dedup_table"] == "dedup_state"
        assert saved["storage"]["checkpoint_table"] == "checkpoints"


def test_config_api_round_trips_delivery_settings(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    backup_dir = workspace_tmp_dir / "backups"
    config_path.write_text(
        yaml.safe_dump(
            {
                "pipeline": {
                    "delivery": {
                        "async_enabled": True,
                        "worker_poll_interval": 10,
                        "worker_batch_size": 20,
                        "retry_delay_seconds": 60,
                        "recheck_ttl_minutes": 15,
                        "store_first_ingest": True,
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "BACKUP_DIR", backup_dir)

    with server.app.test_client() as client:
        response = client.get("/api/config")
        payload = response.get_json()["config"]

        assert payload["pipeline"]["delivery"]["async_enabled"] is True
        assert payload["pipeline"]["delivery"]["store_first_ingest"] is True

        save_response = client.post("/api/config", json=payload)
        assert save_response.get_json()["status"] == "ok"

        saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert saved["pipeline"]["delivery"]["async_enabled"] is True
        assert saved["pipeline"]["delivery"]["worker_batch_size"] == 20
        assert saved["pipeline"]["delivery"]["store_first_ingest"] is True


def test_static_ui_assets_reference_new_defectdojo_fields():
    html = (server.PROJECT_ROOT / "frontend" / "main" / "index.html").read_text(encoding="utf-8")
    js = (server.PROJECT_ROOT / "frontend" / "main" / "js" / "app.js").read_text(encoding="utf-8")

    for token in [
        "data-section=\"dashboard\"",
        "page-dashboard",
        "dashboard-range",
        "dashboard-metric",
        "dashboard-chart-type",
        "dashboard-bucket",
        "dashboard-chart",
        "dashboard-top-sources",
        "renderDashboard",
        "defectdojo-active",
        "defectdojo-verified",
        "defectdojo-updated_since_minutes",
        "defectdojo-fetch_limit",
        "defectdojo-product_ids",
        "defectdojo-engagement_ids",
        "defectdojo-test_ids",
        "syncDefectDojoScopeData",
        "previewDefectDojoFindingCount",
        "renderDefectDojoWarnings",
        "defectdojo-finding-count-summary",
        "filter-default_action",
        "filter-json_rules",
        "filter-example-fortigate",
        "filter-example-wazuh-drop",
        "filter-example-defectdojo",
        "getJsonTextareaValue",
        "loadJsonRuleExample",
        "storage-backend",
        "storage-postgres_dsn",
        "storage-postgres_schema",
        "storage-dedup_table",
        "storage-checkpoint_table",
    ]:
        assert token in html or token in js


def test_webhook_history_endpoint_reads_persisted_dashboard_history(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    backup_dir = workspace_tmp_dir / "backups"
    history_path = workspace_tmp_dir / "dashboard_events.jsonl"
    config_path.write_text(yaml.safe_dump({}), encoding="utf-8")

    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "BACKUP_DIR", backup_dir)
    monkeypatch.setattr(dashboard_history_module, "DEFAULT_LOCAL_HISTORY_PATH", history_path)

    history_store = dashboard_history_module.LocalDashboardHistoryStore(history_path)
    history_store.append_dashboard_event(
        {
            "id": "evt-1",
            "receive_time": "2026-04-20T01:00:00+00:00",
            "origin": "poll",
            "alert_count": 3,
            "source_counts": {"wazuh": 2, "defectdojo": 1},
            "findings": [],
            "stats": {"ingested": 3, "created": 1},
        }
    )

    with server.app.test_client() as client:
        response = client.get("/api/webhook/history")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["history"][0]["origin"] == "poll"
    assert payload["history"][0]["stats"]["ingested"] == 3
