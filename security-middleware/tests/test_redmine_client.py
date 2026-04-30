"""
Tests for the Redmine client.
"""

from __future__ import annotations

import json

import responses

from src.config import EnrichmentConfig, RedmineConfig
from src.models.finding import Finding, FindingSource, Severity
from src.output.redmine_client import RedmineClient
from src.pipeline.enricher import EnricherStage
from src.pipeline.identity import hydrate_identity


@responses.activate
def test_new_issue_description_includes_defectdojo_source_link():
    client = RedmineClient(
        RedmineConfig(
            base_url="http://redmine-test",
            api_key="test-key",
            project_id="security-incidents",
            tracker_id=1,
        )
    )
    finding = hydrate_identity(
        Finding(
            source=FindingSource.DEFECTDOJO,
            source_id="42",
            title="SQL Injection",
            description="Dangerous SQL injection finding",
            severity=Severity.HIGH,
            host="app.example.com",
            found_by="ZAP Scan",
            endpoint_url="https://app.example.com/login",
            cwe="89",
            param="username",
            enrichment={
                "source_url": "https://dojo.example.com/finding/42",
            },
        )
    )

    responses.add(
        responses.POST,
        "http://redmine-test/issues.json",
        json={"issue": {"id": 101}},
        status=201,
    )

    issue_id = client._create_issue(finding)

    assert issue_id == 101
    request_payload = json.loads(responses.calls[0].request.body)
    description = request_payload["issue"]["description"]
    assert '"View DefectDojo finding":https://dojo.example.com/finding/42' in description


@responses.activate
def test_new_issue_subject_keeps_source_prefix():
    client = RedmineClient(
        RedmineConfig(
            base_url="http://redmine-test",
            api_key="test-key",
            project_id="security-incidents",
            tracker_id=1,
        )
    )
    finding = hydrate_identity(
        Finding(
            source=FindingSource.WAZUH,
            source_id="1776657713.18890398",
            title="Fortigate attack detected.",
            description="Fortigate attack detected.",
            severity=Severity.HIGH,
            host="BCH-FG80F_NS2",
            raw_data={"rule": {"id": "81628"}},
        )
    )

    responses.add(
        responses.POST,
        "http://redmine-test/issues.json",
        json={"issue": {"id": 102}},
        status=201,
    )

    issue_id = client._create_issue(finding)

    assert issue_id == 102
    request_payload = json.loads(responses.calls[0].request.body)
    assert request_payload["issue"]["subject"] == "[HIGH] [WAZUH] Fortigate attack detected."


@responses.activate
def test_wazuh_issue_description_uses_readable_sections_and_keeps_raw_data():
    enricher = EnricherStage(EnrichmentConfig())
    client = RedmineClient(
        RedmineConfig(
            base_url="http://redmine-test",
            api_key="test-key",
            project_id="security-incidents",
            tracker_id=1,
        )
    )
    finding = hydrate_identity(
        Finding(
            source=FindingSource.WAZUH,
            source_id="1776657713.18890398",
            title="Fortigate attack detected.",
            description="Fortigate attack detected.",
            severity=Severity.HIGH,
            host="BCH-FG80F_NS2",
            srcip="133.139.20.98",
            rule_id="81628",
            rule_groups=["fortigate", "syslog", "attack"],
            raw_data={
                "rule": {
                    "id": "81628",
                    "level": 11,
                    "description": "Fortigate attack detected.",
                    "groups": ["fortigate", "syslog", "attack"],
                },
                "agent": {"id": "000", "name": "wazuh-server"},
                "manager": {"name": "wazuh-server"},
                "decoder": {"name": "fortigate-firewall-v6"},
                "full_log": "logver=700170682 action=\"detected\" attack=\"udp_dst_session\"",
                "location": "119.63.75.68",
                "data": {
                    "action": "detected",
                    "attack": "udp_dst_session",
                    "attackid": "285212775",
                    "count": "7277",
                    "devname": "BCH-FG80F_NS2",
                    "devid": "FGT80FTK21009527",
                    "dstcountry": "Thailand",
                    "dstip": "117.121.222.20",
                    "dstport": "53",
                    "eventtype": "anomaly",
                    "logid": "0720018432",
                    "msg": "anomaly: udp_dst_session repeats 7277 times",
                    "policyid": "1",
                    "policytype": "DoS-policy",
                    "proto": "17",
                    "service": "DNS",
                    "srccountry": "Japan",
                    "srcip": "133.139.20.98",
                    "srcport": "41117",
                },
            },
        )
    )
    enricher.process([finding])

    responses.add(
        responses.POST,
        "http://redmine-test/issues.json",
        json={"issue": {"id": 103}},
        status=201,
    )

    issue_id = client._create_issue(finding)

    assert issue_id == 103
    request_payload = json.loads(responses.calls[0].request.body)
    description = request_payload["issue"]["description"]
    assert "h3. Alert Summary" in description
    assert "h3. What Happened" in description
    assert "h3. Primary Evidence" in description
    assert "h3. Network Context" in description
    assert "h3. Detection Context" in description
    assert "udp_dst_session" in description
    assert "h3. Raw Alert Data" in description


@responses.activate
def test_check_issue_reports_missing_redmine_issue():
    client = RedmineClient(
        RedmineConfig(
            base_url="http://redmine-test",
            api_key="test-key",
            project_id="security-incidents",
            tracker_id=1,
        )
    )

    responses.add(
        responses.GET,
        "http://redmine-test/issues/404.json",
        status=404,
    )

    assert client.check_issue(404) == {
        "exists": False,
        "issue_id": 404,
        "status": "deleted",
        "is_closed": None,
    }


@responses.activate
def test_check_issue_reports_existing_redmine_issue_status():
    client = RedmineClient(
        RedmineConfig(
            base_url="http://redmine-test",
            api_key="test-key",
            project_id="security-incidents",
            tracker_id=1,
        )
    )

    responses.add(
        responses.GET,
        "http://redmine-test/issues/77.json",
        json={"issue": {"id": 77, "status": {"name": "Closed", "is_closed": True}}},
        status=200,
    )

    assert client.check_issue(77) == {
        "exists": True,
        "issue_id": 77,
        "status": "Closed",
        "is_closed": True,
    }
