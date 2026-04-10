"""
Tests for the Deduplicator pipeline stage.
"""

import os
import tempfile

import pytest
from src.config import DedupConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.deduplicator import DeduplicatorStage


def _make_finding(
    title: str = "Test Alert",
    host: str = "server-01",
    source_id: str = "001",
) -> Finding:
    return Finding(
        source=FindingSource.WAZUH,
        source_id=source_id,
        title=title,
        description="Test",
        severity=Severity.HIGH,
        host=host,
    )


@pytest.fixture
def dedup_stage(tmp_path):
    """Create a DeduplicatorStage with a temp database."""
    config = DedupConfig(
        enabled=True,
        db_path=str(tmp_path / "test_dedup.db"),
        ttl_hours=1,
    )
    stage = DeduplicatorStage(config)
    yield stage
    stage.close()


class TestDeduplicator:

    def test_first_occurrence_passes(self, dedup_stage):
        """First time a finding is seen, it should pass through."""
        findings = [_make_finding()]
        result = dedup_stage.process(findings)
        assert len(result) == 1

    def test_duplicate_dropped(self, dedup_stage):
        """Same finding seen twice should be dropped the second time."""
        finding = _make_finding()
        dedup_stage.process([finding])

        # Same finding again
        duplicate = _make_finding()
        result = dedup_stage.process([duplicate])
        assert len(result) == 0

    def test_duplicate_dropped_within_same_batch(self, dedup_stage):
        """Same finding repeated in one batch should only pass once."""
        findings = [_make_finding(), _make_finding()]
        result = dedup_stage.process(findings)
        assert len(result) == 1

    def test_different_findings_pass(self, dedup_stage):
        """Different findings should both pass."""
        f1 = _make_finding(title="Alert A", host="server-01")
        f2 = _make_finding(title="Alert B", host="server-02")

        result = dedup_stage.process([f1, f2])
        assert len(result) == 2

    def test_same_title_different_host(self, dedup_stage):
        """Same title on different hosts should be treated as unique."""
        f1 = _make_finding(title="Alert A", host="server-01")
        f2 = _make_finding(title="Alert A", host="server-02")

        result = dedup_stage.process([f1, f2])
        assert len(result) == 2

    def test_disabled(self, tmp_path):
        """When disabled, all findings should pass."""
        config = DedupConfig(enabled=False, db_path=str(tmp_path / "unused.db"))
        stage = DeduplicatorStage(config)

        finding = _make_finding()
        stage.process([finding])
        result = stage.process([finding])
        assert len(result) == 1
        stage.close()

    def test_stats(self, dedup_stage):
        """Stats should reflect tracked hashes."""
        assert dedup_stage.get_stats()["total_tracked"] == 0

        dedup_stage.process([_make_finding()])
        assert dedup_stage.get_stats()["total_tracked"] == 1

        dedup_stage.process([_make_finding(title="Another", host="other")])
        assert dedup_stage.get_stats()["total_tracked"] == 2
