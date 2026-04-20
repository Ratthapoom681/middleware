"""
Tests for the Redmine client.
"""

from __future__ import annotations

import json

import responses

from src.config import RedmineConfig
from src.models.finding import Finding, FindingSource, Severity
from src.output.redmine_client import RedmineClient
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
