"""
Tests for the DefectDojo client normalization behavior.
"""

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
