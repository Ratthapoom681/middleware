"""
Tests for the Deduplicator pipeline stage.
"""

from __future__ import annotations

import pytest

from src.config import DedupConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.deduplicator import DeduplicatorStage
from src.pipeline.identity import hydrate_identity


def _make_wazuh_finding(
    title: str = "Test Alert",
    host: str = "server-01",
    source_id: str = "001",
) -> Finding:
    return hydrate_identity(
        Finding(
            source=FindingSource.WAZUH,
            source_id=source_id,
            title=title,
            description="Test",
            severity=Severity.HIGH,
            host=host,
            rule_id="5710",
        )
    )


def _make_defectdojo_finding(
    *,
    source_id: str,
    title: str,
    found_by: str,
    host: str = "",
    endpoints: list[str] | None = None,
    endpoint_url: str = "",
    plugin_id: str = "",
    cwe: str = "",
    param: str = "",
    cve_ids: list[str] | None = None,
) -> Finding:
    return hydrate_identity(
        Finding(
            source=FindingSource.DEFECTDOJO,
            source_id=source_id,
            title=title,
            description="Test",
            severity=Severity.HIGH,
            host=host,
            endpoints=endpoints or [],
            endpoint_url=endpoint_url,
            plugin_id=plugin_id,
            found_by=found_by,
            cwe=cwe,
            param=param,
            cve_ids=cve_ids or [],
        )
    )


@pytest.fixture
def dedup_stage(workspace_tmp_dir):
    """Create a DeduplicatorStage with a temp database."""
    config = DedupConfig(
        enabled=True,
        db_path=str(workspace_tmp_dir / "test_dedup.db"),
        ttl_hours=1,
    )
    stage = DeduplicatorStage(config)
    yield stage
    stage.close()


class TestDeduplicator:
    def test_first_occurrence_passes(self, dedup_stage):
        finding = _make_wazuh_finding()
        new_findings, repeat_findings = dedup_stage.process([finding])

        assert len(new_findings) == 1
        assert repeat_findings == []

    def test_duplicate_becomes_repeat_after_commit(self, dedup_stage):
        finding = _make_wazuh_finding()
        new_findings, _ = dedup_stage.process([finding])
        dedup_stage.commit_new(new_findings)

        duplicate = _make_wazuh_finding(source_id="002")
        new_findings, repeat_findings = dedup_stage.process([duplicate])

        assert new_findings == []
        assert len(repeat_findings) == 1
        assert repeat_findings[0].dedup_reason == "repeat_within_ttl"

    def test_duplicate_collapses_within_same_batch(self, dedup_stage):
        findings = [_make_wazuh_finding(source_id="001"), _make_wazuh_finding(source_id="002")]
        new_findings, repeat_findings = dedup_stage.process(findings)

        assert len(new_findings) == 1
        assert len(repeat_findings) == 1
        assert repeat_findings[0].dedup_reason == "same_batch_duplicate"

    def test_different_findings_pass(self, dedup_stage):
        f1 = _make_wazuh_finding(title="Alert A", host="server-01", source_id="001")
        f2 = _make_wazuh_finding(title="Alert B", host="server-02", source_id="002")

        new_findings, repeat_findings = dedup_stage.process([f1, f2])

        assert len(new_findings) == 2
        assert repeat_findings == []

    def test_same_title_different_host(self, dedup_stage):
        f1 = _make_wazuh_finding(title="Alert A", host="server-01", source_id="001")
        f2 = _make_wazuh_finding(title="Alert A", host="server-02", source_id="002")

        new_findings, repeat_findings = dedup_stage.process([f1, f2])

        assert len(new_findings) == 2
        assert repeat_findings == []

    def test_tenable_scan_dedups_same_asset_and_separates_different_assets(self, dedup_stage):
        finding_a = _make_defectdojo_finding(
            source_id="dd-1",
            title="SSL Certificate Expired",
            found_by="Tenable Scan",
            endpoints=["server-01"],
            plugin_id="51192",
            cve_ids=["CVE-2024-1111"],
        )
        finding_b = _make_defectdojo_finding(
            source_id="dd-2",
            title="SSL Certificate Expired",
            found_by="Tenable Scan",
            endpoints=["server-01"],
            plugin_id="51192",
            cve_ids=["CVE-2024-1111"],
        )
        finding_c = _make_defectdojo_finding(
            source_id="dd-3",
            title="SSL Certificate Expired",
            found_by="Tenable Scan",
            endpoints=["server-02"],
            plugin_id="51192",
            cve_ids=["CVE-2024-1111"],
        )

        same_asset_new, same_asset_repeat = dedup_stage.process([finding_a, finding_b])
        different_asset_new, different_asset_repeat = dedup_stage.process([finding_c])

        assert finding_a.dedup_hash == finding_b.dedup_hash
        assert finding_a.dedup_hash != finding_c.dedup_hash
        assert len(same_asset_new) == 1
        assert len(same_asset_repeat) == 1
        assert len(different_asset_new) == 1
        assert different_asset_repeat == []

    def test_zap_scan_dedups_same_endpoint_and_separates_different_endpoints(self, dedup_stage):
        finding_a = _make_defectdojo_finding(
            source_id="dd-10",
            title="Reflected XSS",
            found_by="ZAP Scan",
            host="app.example.com",
            endpoint_url="https://app.example.com/search",
            cwe="79",
            param="q",
        )
        finding_b = _make_defectdojo_finding(
            source_id="dd-11",
            title="Reflected XSS",
            found_by="ZAP Scan",
            host="app.example.com",
            endpoint_url="https://app.example.com/search",
            cwe="79",
            param="q",
        )
        finding_c = _make_defectdojo_finding(
            source_id="dd-12",
            title="Reflected XSS",
            found_by="ZAP Scan",
            host="app.example.com",
            endpoint_url="https://app.example.com/admin",
            cwe="79",
            param="q",
        )

        same_endpoint_new, same_endpoint_repeat = dedup_stage.process([finding_a, finding_b])
        different_endpoint_new, different_endpoint_repeat = dedup_stage.process([finding_c])

        assert finding_a.dedup_hash == finding_b.dedup_hash
        assert finding_a.dedup_hash != finding_c.dedup_hash
        assert len(same_endpoint_new) == 1
        assert len(same_endpoint_repeat) == 1
        assert len(different_endpoint_new) == 1
        assert different_endpoint_repeat == []

    def test_disabled(self, workspace_tmp_dir):
        config = DedupConfig(enabled=False, db_path=str(workspace_tmp_dir / "unused.db"))
        stage = DeduplicatorStage(config)

        finding = _make_wazuh_finding()
        first_pass, repeat_findings = stage.process([finding])
        second_pass, second_repeats = stage.process([finding])

        assert len(first_pass) == 1
        assert repeat_findings == []
        assert len(second_pass) == 1
        assert second_repeats == []
        stage.close()

    def test_stats(self, dedup_stage):
        assert dedup_stage.get_stats()["total_tracked"] == 0

        new_findings, _ = dedup_stage.process([_make_wazuh_finding(source_id="001")])
        dedup_stage.commit_new(new_findings)
        assert dedup_stage.get_stats()["total_tracked"] == 1

        new_findings, _ = dedup_stage.process([_make_wazuh_finding(title="Another", host="other", source_id="002")])
        dedup_stage.commit_new(new_findings)
        assert dedup_stage.get_stats()["total_tracked"] == 2

    def test_can_use_external_state_store_backend(self):
        class FakeStateStore:
            def __init__(self):
                self.records = {}
                self.closed = False

            def get_recent_hashes(self, hash_values, cutoff):
                return {
                    hash_value: (record.get("redmine_issue_id"), record.get("issue_state"))
                    for hash_value, record in self.records.items()
                    if hash_value in hash_values and record["last_seen"] > cutoff
                }

            def get_all_hashes(self, hash_values):
                return {hash_value for hash_value in hash_values if hash_value in self.records}

            def commit_new(self, records):
                for record in records:
                    self.records[record[0]] = {
                        "last_seen": record[4],
                        "redmine_issue_id": record[7],
                        "issue_state": record[8],
                    }

            def commit_updates(self, records):
                for record in records:
                    self.records[record[0]] = {
                        "last_seen": record[4],
                        "redmine_issue_id": record[7],
                        "issue_state": record[8],
                    }

            def cleanup_dedup(self, cutoff):
                before = len(self.records)
                self.records = {
                    hash_value: record
                    for hash_value, record in self.records.items()
                    if record["last_seen"] >= cutoff
                }
                return before - len(self.records)

            def get_dedup_stats(self):
                return {"total_tracked": len(self.records)}

            def close(self):
                self.closed = True

        state_store = FakeStateStore()
        stage = DeduplicatorStage(
            DedupConfig(enabled=True, db_path="unused.db", ttl_hours=1),
            state_store=state_store,
        )

        first = _make_wazuh_finding(source_id="001")
        new_findings, repeat_findings = stage.process([first])
        assert len(new_findings) == 1
        assert repeat_findings == []

        stage.commit_new(new_findings)
        duplicate = _make_wazuh_finding(source_id="002")
        new_findings, repeat_findings = stage.process([duplicate])

        assert new_findings == []
        assert len(repeat_findings) == 1
        assert stage.get_stats()["total_tracked"] == 1

        stage.close()
        assert state_store.closed is True
