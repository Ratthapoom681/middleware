"""
Tests for the Severity Mapper pipeline stage.
"""

import pytest
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.severity_mapper import SeverityMapperStage


PRIORITY_MAP = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _make_finding(source: FindingSource, raw_severity: str) -> Finding:
    return Finding(
        source=source,
        source_id="test-001",
        title="Test",
        description="Test",
        raw_severity=raw_severity,
    )


class TestSeverityMapper:

    def test_wazuh_level_critical(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.WAZUH, "15")]
        result = stage.process(findings)
        assert result[0].severity == Severity.CRITICAL
        assert result[0].enrichment["redmine_priority_id"] == 5

    def test_wazuh_level_high(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.WAZUH, "12")]
        result = stage.process(findings)
        assert result[0].severity == Severity.HIGH

    def test_wazuh_level_medium(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.WAZUH, "7")]
        result = stage.process(findings)
        assert result[0].severity == Severity.MEDIUM

    def test_wazuh_level_low(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.WAZUH, "4")]
        result = stage.process(findings)
        assert result[0].severity == Severity.LOW

    def test_wazuh_level_info(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.WAZUH, "2")]
        result = stage.process(findings)
        assert result[0].severity == Severity.INFO

    def test_defectdojo_critical(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.DEFECTDOJO, "Critical")]
        result = stage.process(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_defectdojo_medium(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.DEFECTDOJO, "Medium")]
        result = stage.process(findings)
        assert result[0].severity == Severity.MEDIUM

    def test_invalid_raw_severity(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [_make_finding(FindingSource.WAZUH, "invalid")]
        result = stage.process(findings)
        assert result[0].severity == Severity.INFO

    def test_priority_map_output(self):
        stage = SeverityMapperStage(PRIORITY_MAP)
        findings = [
            _make_finding(FindingSource.WAZUH, "15"),
            _make_finding(FindingSource.DEFECTDOJO, "Low"),
        ]
        result = stage.process(findings)
        assert result[0].enrichment["redmine_priority_id"] == 5
        assert result[1].enrichment["redmine_priority_id"] == 2
