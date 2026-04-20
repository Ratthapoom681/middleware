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
    source: FindingSource = FindingSource.WAZUH,
    raw_data: dict | None = None,
) -> Finding:
    """Helper to create a test Finding."""
    return Finding(
        source=source,
        source_id="test-001",
        title=title,
        description="Test description",
        severity=severity,
        raw_severity=str(severity.numeric),
        host=host,
        rule_id=rule_id,
        raw_data=raw_data or {},
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

    def test_advanced_json_rules_can_keep_matching_fortigate_alerts(self):
        """Advanced rules should match nested Wazuh payload paths."""
        config = FilterConfig(
            min_severity="info",
            default_action="drop",
            json_rules=[
                {
                    "name": "keep-fortigate-attacks",
                    "source": "wazuh",
                    "action": "keep",
                    "match": "all",
                    "conditions": [
                        {"path": "decoder.name", "op": "equals", "value": "fortigate-firewall-v6"},
                        {"path": "rule.groups", "op": "contains", "value": "attack"},
                        {"path": "data.count", "op": "gte", "value": 5000},
                    ],
                }
            ],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(
                title="Fortigate attack detected.",
                raw_data={
                    "decoder": {"name": "fortigate-firewall-v6"},
                    "rule": {"groups": ["fortigate", "syslog", "attack"]},
                    "data": {"count": "7277", "srcip": "133.139.20.98"},
                },
            ),
            _make_finding(
                title="Other alert",
                raw_data={
                    "decoder": {"name": "fortigate-firewall-v6"},
                    "rule": {"groups": ["fortigate"]},
                    "data": {"count": "10"},
                },
            ),
        ]

        result = stage.process(findings)

        assert len(result) == 1
        assert result[0].title == "Fortigate attack detected."
        assert result[0].enrichment["matched_filter_rule"] == "keep-fortigate-attacks"

    def test_advanced_json_rules_can_drop_matching_payloads(self):
        """First matching JSON rule should be able to drop noisy findings."""
        config = FilterConfig(
            min_severity="info",
            json_rules=[
                {
                    "name": "drop-small-dns-anomaly",
                    "source": "wazuh",
                    "action": "drop",
                    "match": "all",
                    "conditions": [
                        {"path": "data.attack", "op": "equals", "value": "udp_dst_session"},
                        {"path": "data.service", "op": "equals", "value": "DNS"},
                        {"path": "data.count", "op": "lt", "value": 5000},
                    ],
                }
            ],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(
                title="Small DNS anomaly",
                raw_data={"data": {"attack": "udp_dst_session", "service": "DNS", "count": "4999"}},
            ),
            _make_finding(
                title="Large DNS anomaly",
                raw_data={"data": {"attack": "udp_dst_session", "service": "DNS", "count": "7277"}},
            ),
        ]

        result = stage.process(findings)

        assert len(result) == 1
        assert result[0].title == "Large DNS anomaly"

    def test_advanced_json_rules_respect_source_scope(self):
        """Wazuh-only JSON rules should not affect DefectDojo findings."""
        config = FilterConfig(
            min_severity="info",
            default_action="drop",
            json_rules=[
                {
                    "name": "wazuh-only-rule",
                    "source": "wazuh",
                    "action": "keep",
                    "match": "all",
                    "conditions": [{"path": "data.srcip", "op": "exists"}],
                }
            ],
        )
        stage = FilterStage(config)

        findings = [
            _make_finding(
                title="Wazuh alert",
                source=FindingSource.WAZUH,
                raw_data={"data": {"srcip": "10.0.0.1"}},
            ),
            _make_finding(
                title="DefectDojo finding",
                source=FindingSource.DEFECTDOJO,
                raw_data={"endpoints": ["https://app.example.com/login"]},
            ),
        ]

        result = stage.process(findings)

        assert len(result) == 1
        assert result[0].title == "Wazuh alert"
