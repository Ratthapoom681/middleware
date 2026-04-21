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
    DeliveryConfig,
    EnrichmentConfig,
)
from src.main import MiddlewarePipeline
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.identity import hydrate_identity


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


class _FakeQueueStateStore:
    def __init__(self):
        self.jobs = []
        self.ticket_states = []
        self.closed = False

    def enqueue_outbound_job(self, **kwargs):
        self.jobs.append(kwargs)

    def save_ticket_state(self, dedup_hash, **kwargs):
        self.ticket_states.append((dedup_hash, kwargs))

    def close(self):
        self.closed = True


def test_process_batch_queues_wazuh_findings_when_async_delivery_enabled(config):
    config.pipeline.delivery = DeliveryConfig(async_enabled=True, worker_batch_size=10)
    pipeline = MiddlewarePipeline(config)
    pipeline.state_store = _FakeQueueStateStore()
    pipeline.config.pipeline.delivery.async_enabled = True

    finding = hydrate_identity(
        Finding(
            source=FindingSource.WAZUH,
            source_id="alert-queue-1",
            title="SSH brute force attempt",
            description="SSH brute force attempt detected",
            severity=Severity.HIGH,
            raw_severity="10",
            host="web-server-01",
            routing_key="web-server-01",
            rule_id="5710",
            rule_groups=["sshd", "authentication"],
            raw_data={"rule": {"id": "5710", "description": "SSH brute force attempt"}},
        )
    )

    outcome = pipeline.process_batch([finding])

    assert outcome["stats"]["queued"] == 1
    assert outcome["stats"]["created"] == 0
    assert pipeline.state_store.jobs[0]["action"] == "create_ticket"
    assert pipeline.state_store.jobs[0]["dedup_hash"] == finding.dedup_hash
    assert pipeline.state_store.ticket_states[0][1]["last_delivery_status"] == "queued"

    pipeline.close()
