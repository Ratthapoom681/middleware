"""
Tests for the Filter pipeline stage.
"""

import pytest
from src.config import FilterConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.filter import FilterStage


def _make_finding(
    title: str = "Test Alert",
    severity: Severity = Severity.HIGH,
    host: str = "server-01",
    rule_id: str | None = None,
) -> Finding:
    """Helper to create a test Finding."""
    return Finding(
        source=FindingSource.WAZUH,
        source_id="test-001",
        title=title,
        description="Test description",
        severity=severity,
        raw_severity=str(severity.numeric),
        host=host,
        rule_id=rule_id,
    )


class TestFilterStage:
    """Tests for FilterStage."""

    def test_passes_all_when_no_rules(self):
        """Findings should pass when no filter rules are configured."""
        config = FilterConfig(min_severity="info")
        stage = FilterStage(config)

        findings = [_make_finding(severity=Severity.INFO)]
        result = stage.process(findings)
        assert len(result) == 1

    def test_min_severity_drops_low(self):
        """Findings below min_severity should be dropped."""
        config = FilterConfig(min_severity="high")
        stage = FilterStage(config)

        findings = [
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.CRITICAL),
        ]
        result = stage.process(findings)
        assert len(result) == 2
        assert all(f.severity >= Severity.HIGH for f in result)

    def test_exclude_rule_ids(self):
        """Findings with excluded rule IDs should be dropped."""
        config = FilterConfig(
            min_severity="info",
            exclude_rule_ids=["550", "551"],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(rule_id="550"),
            _make_finding(rule_id="100"),
            _make_finding(rule_id="551"),
        ]
        result = stage.process(findings)
        assert len(result) == 1
        assert result[0].rule_id == "100"

    def test_include_hosts(self):
        """Only findings matching host patterns should pass."""
        config = FilterConfig(
            min_severity="info",
            include_hosts=["web-.*", "db-.*"],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(host="web-01"),
            _make_finding(host="db-master"),
            _make_finding(host="mail-server"),
        ]
        result = stage.process(findings)
        assert len(result) == 2

    def test_exclude_title_patterns(self):
        """Findings matching title exclusion patterns should be dropped."""
        config = FilterConfig(
            min_severity="info",
            exclude_title_patterns=["^Syscheck.*", ".*test.*"],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(title="Syscheck file integrity changed"),
            _make_finding(title="SSH brute force detected"),
            _make_finding(title="This is a test alert"),
        ]
        result = stage.process(findings)
        assert len(result) == 1
        assert result[0].title == "SSH brute force detected"

    def test_combined_rules(self):
        """Multiple filter rules should work together."""
        config = FilterConfig(
            min_severity="medium",
            exclude_rule_ids=["999"],
            exclude_title_patterns=["^Noise.*"],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(severity=Severity.HIGH, title="Real alert"),
            _make_finding(severity=Severity.LOW, title="Low severity"),
            _make_finding(severity=Severity.HIGH, title="Noise alert", rule_id="100"),
            _make_finding(severity=Severity.CRITICAL, rule_id="999"),
        ]
        result = stage.process(findings)
        assert len(result) == 1
        assert result[0].title == "Real alert"
