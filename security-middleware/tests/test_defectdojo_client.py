"""
Tests for the DefectDojo client normalization behavior.
"""

from pathlib import Path
from uuid import uuid4

import responses

from src.config import DefectDojoConfig
from src.models.finding import Severity
from src.sources.defectdojo_client import DefectDojoClient


def test_lowercase_severity_maps_correctly():
    client = DefectDojoClient(
        DefectDojoConfig(
            base_url="http://defectdojo-test/api/v2",
            api_key="Token test-key",
            verify_ssl=False,
        )
    )

    raw_finding = {
        "id": 42,
        "title": "Lowercase severity finding",
        "severity": "high",
        "description": "Example finding",
        "date": "2026-04-09",
        "tags": ["webapp"],
        "test_type_name": "SAST",
        "vulnerability_ids": [],
    }

    finding = client._finding_to_model(raw_finding)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.raw_severity == "high"
    assert finding.tags == ["webapp", "scan:SAST"]
    assert raw_finding["tags"] == ["webapp"]


def test_tenable_plugin_id_comes_from_vulnerability_ids():
    client = DefectDojoClient(
        DefectDojoConfig(
            base_url="http://defectdojo-test/api/v2",
            api_key="Token test-key",
            verify_ssl=False,
        )
    )

    raw_finding = {
        "id": 43,
        "title": "Nessus plugin finding",
        "severity": "High",
        "description": "Plugin-backed Tenable finding",
        "date": "2026-04-09",
        "test_type_name": "Nessus Scan",
        "endpoints": ["server-01"],
        "vulnerability_ids": [
            {"vulnerability_id": "CVE-2024-9999", "source": "NVD"},
            {"vulnerability_id": "19506", "source": "Nessus Plugin"},
        ],
    }

    finding = client._finding_to_model(raw_finding)

    assert finding is not None
    assert finding.found_by == "Nessus Scan"
    assert finding.plugin_id == "19506"
    assert finding.cve_ids == ["CVE-2024-9999"]
    assert "|19506|" in finding.dedup_key


@responses.activate
def test_fetch_limit_is_enforced_without_losing_paginated_updates():
    cursor_path = Path("data") / f"test_defectdojo_cursor_{uuid4().hex}.json"
    cursor_path.parent.mkdir(parents=True, exist_ok=True)
    client = DefectDojoClient(
        DefectDojoConfig(
            base_url="http://defectdojo-test/api/v2",
            api_key="Token test-key",
            verify_ssl=False,
            updated_since_minutes=60,
            fetch_limit=1,
            cursor_path=str(cursor_path),
        )
    )

    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={
            "count": 2,
            "next": "http://defectdojo-test/api/v2/findings/?limit=100&offset=100",
            "results": [
                {
                    "id": 1,
                    "title": "First updated finding",
                    "severity": "High",
                    "description": "First page finding",
                    "date": "2026-04-09",
                    "last_status_update": "2026-04-09T10:00:00Z",
                    "vulnerability_ids": [],
                    "tags": [],
                }
            ],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={
            "count": 2,
            "next": None,
            "results": [
                {
                    "id": 2,
                    "title": "Second updated finding",
                    "severity": "Medium",
                    "description": "Second page finding",
                    "date": "2026-04-09",
                    "last_status_update": "2026-04-09T10:01:00Z",
                    "vulnerability_ids": [],
                    "tags": [],
                }
            ],
        },
        status=200,
    )

    first_batch = client.fetch_findings()

    assert [finding.source_id for finding in first_batch] == ["1"]
    assert len(responses.calls) == 1
    assert cursor_path.exists()

    first_request = responses.calls[0].request
    assert "last_status_update=" in first_request.url
    assert "ordering=last_status_update%2Cid" in first_request.url
    assert "limit=1" in first_request.url

    responses.reset()
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={
            "count": 2,
            "next": "http://defectdojo-test/api/v2/findings/?limit=1&offset=1",
            "results": [
                {
                    "id": 1,
                    "title": "First updated finding",
                    "severity": "High",
                    "description": "First page finding",
                    "date": "2026-04-09",
                    "last_status_update": "2026-04-09T10:00:00Z",
                    "vulnerability_ids": [],
                    "tags": [],
                }
            ],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={
            "count": 2,
            "next": None,
            "results": [
                {
                    "id": 2,
                    "title": "Second updated finding",
                    "severity": "Medium",
                    "description": "Second page finding",
                    "date": "2026-04-09",
                    "last_status_update": "2026-04-09T10:01:00Z",
                    "vulnerability_ids": [],
                    "tags": [],
                }
            ],
        },
        status=200,
    )

    second_batch = client.fetch_findings()

    assert [finding.source_id for finding in second_batch] == ["2"]
    assert len(responses.calls) == 2

    second_request = responses.calls[0].request
    assert "last_status_update=2026-04-09T10%3A00%3A00Z" in second_request.url

    cursor_path.unlink(missing_ok=True)
