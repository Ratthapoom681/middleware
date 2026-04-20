"""
Integration test for the full pipeline (with mocked API calls).
"""

import pytest
import responses

from src import dashboard_history as dashboard_history_module
from src.config import (
    AppConfig,
    WazuhConfig,
    DefectDojoConfig,
    RedmineConfig,
    PipelineConfig,
    FilterConfig,
    DedupConfig,
    EnrichmentConfig,
)
from src.main import MiddlewarePipeline


@pytest.fixture
def config(workspace_tmp_dir):
    """Create a test configuration."""
    return AppConfig(
        wazuh=WazuhConfig(
            base_url="http://wazuh-test:55000",
            indexer_url="http://wazuh-indexer-test:9200",
            username="test",
            password="test",
            verify_ssl=False,
            min_level=3,
        ),
        defectdojo=DefectDojoConfig(
            enabled=True,
            base_url="http://defectdojo-test/api/v2",
            api_key="Token test-key",
            verify_ssl=False,
        ),
        redmine=RedmineConfig(
            base_url="http://redmine-test",
            api_key="test-key",
            project_id="test-project",
            tracker_id=1,
        ),
        pipeline=PipelineConfig(
            poll_interval=60,
            filter=FilterConfig(min_severity="low"),
            dedup=DedupConfig(
                enabled=True,
                db_path=str(workspace_tmp_dir / "test_dedup.db"),
                ttl_hours=1,
            ),
            enrichment=EnrichmentConfig(
                asset_inventory_enabled=False,
                add_remediation_links=True,
            ),
        ),
    )


@responses.activate
def test_full_pipeline_cycle(config, workspace_tmp_dir, monkeypatch):
    """Test a complete pipeline cycle with mocked API responses."""
    monkeypatch.setattr(
        dashboard_history_module,
        "DEFAULT_LOCAL_HISTORY_PATH",
        workspace_tmp_dir / "dashboard_events.jsonl",
    )

    # Mock Wazuh auth
    responses.add(
        responses.POST,
        "http://wazuh-test:55000/security/user/authenticate",
        json={"data": {"token": "test-jwt-token"}},
        status=200,
    )

    # Mock Wazuh Indexer alerts
    responses.add(
        responses.POST,
        "http://wazuh-indexer-test:9200/wazuh-alerts-*/_search",
        json={
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {
                        "_id": "alert-001",
                        "_source": {
                            "@timestamp": "2026-04-09T10:00:00+00:00",
                            "rule": {
                                "id": "5710",
                                "level": 10,
                                "description": "SSH brute force attempt",
                                "groups": ["sshd", "authentication"],
                            },
                            "agent": {
                                "id": "001",
                                "name": "web-server-01",
                                "ip": "10.0.1.10",
                            },
                            "data": {},
                        },
                        "sort": ["2026-04-09T10:00:00+00:00", "alert-001"],
                    },
                    {
                        "_id": "alert-002",
                        "_source": {
                            "@timestamp": "2026-04-09T10:01:00+00:00",
                            "rule": {
                                "id": "100",
                                "level": 2,
                                "description": "Low level noise",
                                "groups": ["syslog"],
                            },
                            "agent": {
                                "id": "001",
                                "name": "web-server-01",
                                "ip": "10.0.1.10",
                            },
                            "data": {},
                        },
                        "sort": ["2026-04-09T10:01:00+00:00", "alert-002"],
                    },
                ],
            }
        },
        status=200,
    )

    # Mock DefectDojo findings
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={
            "count": 1,
            "next": None,
            "results": [
                {
                    "id": 42,
                    "title": "CVE-2024-1234 - Remote Code Execution",
                    "severity": "Critical",
                    "description": "A critical RCE vulnerability",
                    "date": "2026-04-09",
                    "active": True,
                    "duplicate": False,
                    "vulnerability_ids": [
                        {"vulnerability_id": "CVE-2024-1234"}
                    ],
                    "endpoints": [101],
                    "tags": ["webapp"],
                    "component_name": "openssl",
                    "component_version": "1.1.1",
                    "cvssv3_score": 9.8,
                },
            ],
        },
        status=200,
    )

    # Mock Redmine — search (no existing issues)
    responses.add(
        responses.GET,
        "http://redmine-test/issues.json",
        json={"issues": [], "total_count": 0},
        status=200,
    )

    # Mock Redmine — create issue (called for each finding)
    responses.add(
        responses.POST,
        "http://redmine-test/issues.json",
        json={"issue": {"id": 101}},
        status=201,
    )
    responses.add(
        responses.POST,
        "http://redmine-test/issues.json",
        json={"issue": {"id": 102}},
        status=201,
    )

    # Run pipeline
    pipeline = MiddlewarePipeline(config)
    result = pipeline.run_cycle()

    # Assertions
    assert result["ingested"] == 3          # 2 Wazuh + 1 DefectDojo
    assert result["filtered"] >= 1          # Low-level noise should be filtered
    assert result["created"] >= 1           # At least one Redmine issue created
    history = pipeline.dashboard_history.get_dashboard_history(limit=5)
    assert history
    assert history[0]["origin"] == "poll"
    assert history[0]["stats"]["ingested"] == 3

    # Cleanup
    pipeline.close()
