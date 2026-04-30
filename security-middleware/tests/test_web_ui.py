"""
Tests for the configuration web UI and API surface.
"""

from __future__ import annotations

from types import SimpleNamespace

import responses
import yaml

from src.pipeline.detection_store import DetectionAlertStore
from src.sources.defectdojo_client import DefectDojoClient
from web import server


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


def test_static_ui_assets_reflect_webhook_only_wazuh_and_new_defectdojo_fields():
    html = (server.PROJECT_ROOT / "web" / "static" / "index.html").read_text(encoding="utf-8")
    js = (server.PROJECT_ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assets = html + js

    for token in [
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
        "rule-ticket-toggle",
        "Create Redmine Ticket",
        "check_redmine=1",
        "storage-backend",
        "storage-postgres_dsn",
        "storage-postgres_schema",
        "storage-dedup_table",
        "storage-checkpoint_table",
    ]:
        assert token in assets

    for removed_token in [
        "data-section=\"dashboard\"",
        "page-dashboard",
        "dashboard-range",
        "dashboard-metric",
        "dashboard-chart-type",
        "dashboard-bucket",
        "dashboard-chart",
        "dashboard-top-sources",
        "renderDashboard",
        "wazuh-indexer_url",
        "wazuh-indexer_username",
        "wazuh-indexer_password",
        "wazuh-alerts_json_path",
        "latestWebhookHistory",
        "/api/webhook/history",
        "Check Redmine</button>",
    ]:
        assert removed_token not in assets

    assert 'class="nav-item active" data-section="detection-rules"' in html
    assert '<h2 id="section-title">Detection Rules</h2>' in html
    assert '<div class="section-page active" id="page-detection-rules">' in html


def test_wazuh_webhook_processes_payload_through_pipeline(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    backup_dir = workspace_tmp_dir / "backups"
    config_path.write_text(
        yaml.safe_dump({"wazuh": {"min_level": 0}, "pipeline": {"filter": {"min_severity": "info"}}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "BACKUP_DIR", backup_dir)

    captured = {}

    class FakePipeline:
        def __init__(self, config):
            captured["config"] = config

        def _store_first_ingest_enabled(self):
            return False

        def process_batch(self, findings, event_context=None):
            captured["findings"] = findings
            captured["event_context"] = event_context
            return {
                "stats": {
                    "ingested": len(findings),
                    "filtered": 0,
                    "deduplicated": 0,
                    "created": 0,
                    "updated": 0,
                    "reopened": 0,
                    "recreated": 0,
                    "queued": 0,
                    "failed": 0,
                }
            }

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(server, "MiddlewarePipeline", FakePipeline)

    with server.app.test_client() as client:
        response = client.post(
            "/api/webhook/wazuh",
            json={
                "_index": "wazuh-alerts-4.x-2026.04.29",
                "_id": "yHCX2J0Byl_n48-Tu3Ro",
                "_source": {
                    "id": "1777455314.24749104",
                    "timestamp": "2026-04-29T09:35:14.476+0000",
                    "rule": {
                        "id": "81606",
                        "level": 4,
                        "description": "Fortigate: Login failed.",
                        "groups": ["fortigate", "syslog", "authentication_failed", "invalid_login"],
                    },
                    "agent": {"name": "wazuh-server", "id": "000"},
                    "decoder": {"name": "fortigate-firewall-v6"},
                    "data": {
                        "srcip": "85.11.187.20",
                        "dstip": "223.27.209.82",
                        "dstuser": "admin",
                        "devname": "BCH-FG80F_NS2",
                        "action": "login",
                        "status": "failed",
                    },
                },
                "fields": {"timestamp": ["2026-04-29T09:35:14.476Z"]},
            },
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["stats"]["ingested"] == 1
    assert captured["findings"][0].source.value == "wazuh"
    assert captured["findings"][0].source_id == "1777455314.24749104"
    assert captured["findings"][0].title == "Fortigate: Login failed."
    assert captured["findings"][0].host == "BCH-FG80F_NS2"
    assert captured["findings"][0].srcip == "85.11.187.20"
    assert captured["findings"][0].raw_data["data"]["status"] == "failed"
    assert captured["findings"][0].raw_data["_index"] == "wazuh-alerts-4.x-2026.04.29"
    assert captured["findings"][0].raw_data["_index_id"] == "yHCX2J0Byl_n48-Tu3Ro"
    assert captured["event_context"] == {
        "origin": "webhook",
        "alert_count": 1,
        "source_counts": {"wazuh": 1},
    }
    assert captured["closed"] is True


@responses.activate
def test_detection_alert_check_redmine_marks_missing_issue_resolved(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    detection_db = workspace_tmp_dir / "detection_alerts.db"
    config_path.write_text(
        yaml.safe_dump(
            {
                "redmine": {
                    "base_url": "http://redmine-test",
                    "api_key": "test-key",
                    "project_id": "security-incidents",
                    "tracker_id": 1,
                },
                "pipeline": {
                    "detection": {
                        "enabled": True,
                        "db_path": str(detection_db),
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "CONFIG_PATH", config_path)

    store = DetectionAlertStore(db_path=str(detection_db))
    try:
        store.save_alert(
            SimpleNamespace(
                id="alert-1",
                rule_name="Brute Force Login Detection",
                rule_type="brute_force",
                severity="high",
                description="Brute force detected",
                evidence={"source_ip": "10.0.0.50"},
                source_events=[],
                triggered_at="2026-04-30T01:00:00+00:00",
                acknowledged=False,
                resolved=False,
                create_ticket=True,
            )
        )
        assert store.update_redmine_issue(
            "alert-1",
            issue_id=501,
            exists=True,
            status="open",
            resolved=False,
        )
    finally:
        store.close()

    responses.add(
        responses.GET,
        "http://redmine-test/issues/501.json",
        status=404,
    )

    with server.app.test_client() as client:
        response = client.post("/api/detection/alerts/alert-1/check-redmine")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["redmine"]["exists"] is False
    assert payload["alert"]["resolved"] is True
    assert payload["alert"]["acknowledged"] is True
    assert payload["alert"]["redmine_issue_exists"] is False
    assert payload["alert"]["redmine_issue_status"] == "deleted"


@responses.activate
def test_detection_alert_list_auto_checks_redmine_and_marks_missing_issue_resolved(workspace_tmp_dir, monkeypatch):
    config_path = workspace_tmp_dir / "config.yaml"
    detection_db = workspace_tmp_dir / "detection_alerts_list.db"
    config_path.write_text(
        yaml.safe_dump(
            {
                "redmine": {
                    "base_url": "http://redmine-test",
                    "api_key": "test-key",
                    "project_id": "security-incidents",
                    "tracker_id": 1,
                },
                "pipeline": {
                    "detection": {
                        "enabled": True,
                        "db_path": str(detection_db),
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "CONFIG_PATH", config_path)

    store = DetectionAlertStore(db_path=str(detection_db))
    try:
        store.save_alert(
            SimpleNamespace(
                id="alert-auto-check",
                rule_name="Brute Force Login Detection",
                rule_type="brute_force",
                severity="high",
                description="Brute force detected",
                evidence={"source_ip": "10.0.0.50"},
                source_events=[],
                triggered_at="2026-04-30T01:00:00+00:00",
                acknowledged=False,
                resolved=False,
                create_ticket=True,
            )
        )
        store.update_redmine_issue(
            "alert-auto-check",
            issue_id=777,
            exists=True,
            status="open",
            resolved=False,
        )
    finally:
        store.close()

    responses.add(
        responses.GET,
        "http://redmine-test/issues/777.json",
        status=404,
    )

    with server.app.test_client() as client:
        response = client.get("/api/detection/alerts?check_redmine=1")

    assert response.status_code == 200
    alert = response.get_json()["alerts"][0]
    assert alert["id"] == "alert-auto-check"
    assert alert["resolved"] is True
    assert alert["acknowledged"] is True
    assert alert["redmine_issue_exists"] is False
    assert alert["redmine_issue_status"] == "deleted"
