"""
Tests for the DefectDojo client normalization behavior.
"""

from __future__ import annotations

import json
from uuid import uuid4

import responses

from src.config import DefectDojoConfig
from src.models.finding import Severity
from src.sources.defectdojo_client import DefectDojoAPIError, DefectDojoClient


def _make_client(**overrides) -> DefectDojoClient:
    return DefectDojoClient(
        DefectDojoConfig(
            base_url="http://defectdojo-test/api/v2",
            api_key="Token test-key",
            verify_ssl=False,
            **overrides,
        )
    )


def test_lowercase_severity_maps_correctly():
    client = _make_client()
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


def test_expanded_endpoint_objects_are_canonicalized_consistently():
    client = _make_client()
    raw_finding = {
        "id": 43,
        "title": "Expanded endpoint finding",
        "severity": "High",
        "description": "Endpoint-backed finding",
        "date": "2026-04-09",
        "test_type_name": "ZAP Scan",
        "endpoints": [
            {
                "protocol": "HTTPS",
                "host": "App.EXAMPLE.com",
                "port": "443",
                "path": "login",
                "url": "https://App.EXAMPLE.com/login?next=/dashboard",
            },
            "https://app.example.com/login",
        ],
        "vulnerability_ids": [],
        "cwe": 79,
        "param": "username",
    }

    finding = client._finding_to_model(raw_finding)

    assert finding is not None
    assert finding.host == "app.example.com"
    assert finding.endpoint_url == "https://app.example.com/login"
    assert finding.endpoints == ["https://app.example.com/login"]
    assert finding.enrichment["normalized_endpoints"] == [
        {
            "host": "app.example.com",
            "protocol": "https",
            "port": "443",
            "path": "/login",
            "url": "https://app.example.com/login",
            "canonical": "https://app.example.com/login",
        }
    ]


def test_tenable_plugin_id_prefers_structured_vulnerability_ids():
    client = _make_client()
    raw_finding = {
        "id": 44,
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


def test_tenable_plugin_id_falls_back_to_vulnerability_id_and_tags():
    client = _make_client()
    raw_finding = {
        "id": 45,
        "title": "Tenable fallback finding",
        "severity": "High",
        "description": "Plugin ID lives outside vulnerability_ids",
        "date": "2026-04-09",
        "test_type_name": "Tenable Scan",
        "endpoints": ["server-01"],
        "vulnerability_id": "12345",
        "vulnerability_ids": [
            {"vulnerability_id": "CVE-2024-1111", "source": "NVD"},
        ],
        "tags": ["team:red", "plugin:12345"],
    }

    finding = client._finding_to_model(raw_finding)

    assert finding is not None
    assert finding.plugin_id == "12345"
    assert finding.cve_ids == ["CVE-2024-1111"]


@responses.activate
def test_fetch_limit_uses_checkpoint_and_does_not_advance_until_committed(workspace_tmp_dir):
    cursor_path = workspace_tmp_dir / f"defectdojo_cursor_{uuid4().hex}.json"
    client = _make_client(
        updated_since_minutes=60,
        fetch_limit=1,
        cursor_path=str(cursor_path),
    )

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

    first_batch = client.fetch_findings()

    assert [finding.source_id for finding in first_batch] == ["1"]
    assert len(responses.calls) == 1
    assert not cursor_path.exists()
    assert client.get_pending_checkpoint()["last_id"] == 1

    first_request = responses.calls[0].request
    assert "last_status_update=" in first_request.url
    assert "ordering=last_status_update%2Cid" in first_request.url
    assert "limit=1" in first_request.url

    client.commit_pending_checkpoint()
    assert cursor_path.exists()
    persisted = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert persisted["last_id"] == 1

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


@responses.activate
def test_fetch_scope_data_returns_products_engagements_and_tests():
    client = _make_client()

    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/products/",
        json={
            "count": 1,
            "next": None,
            "results": [{"id": 10, "name": "Payments"}],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/engagements/",
        json={
            "count": 1,
            "next": None,
            "results": [{"id": 20, "name": "Q2 External", "product": 10}],
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/tests/",
        json={
            "count": 1,
            "next": None,
            "results": [{"id": 30, "title": "ZAP Weekly", "engagement": 20, "product": 10}],
        },
        status=200,
    )

    scope_data = client.fetch_scope_data()

    assert scope_data == {
        "products": [{"id": 10, "name": "Payments"}],
        "engagements": [{"id": 20, "name": "Q2 External", "product_id": 10}],
        "tests": [{"id": 30, "name": "ZAP Weekly", "engagement_id": 20, "product_id": 10}],
    }


@responses.activate
def test_fetch_scope_data_raises_helpful_error_on_non_json_response():
    client = _make_client()

    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/products/",
        body="""
<!DOCTYPE html>
<html>
  <body>login required</body>
</html>
""",
        content_type="text/html",
        status=200,
    )

    try:
        client.fetch_scope_data()
        assert False, "Expected fetch_scope_data() to raise DefectDojoAPIError"
    except DefectDojoAPIError as exc:
        message = str(exc)
        assert "non-JSON content" in message
        assert "/products/" in message
        assert "Base URL points to the UI/login page" in message


@responses.activate
def test_get_finding_count_summary_uses_current_filters_without_checkpoint():
    client = _make_client(
        active=True,
        verified=False,
        updated_since_minutes=30,
        fetch_limit=25,
        product_ids=[10],
    )

    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={"count": 37, "next": None, "results": []},
        status=200,
    )

    summary = client.get_finding_count_summary()

    assert summary == {
        "matching_count": 37,
        "pending_count": 37,
        "checkpoint_applied": False,
        "processing_cap": 25,
        "estimated_processed_count": 25,
    }

    request_url = responses.calls[0].request.url
    assert "verified=false" in request_url
    assert "test__engagement__product=10" in request_url
    assert "last_status_update=" in request_url


@responses.activate
def test_get_finding_count_summary_reports_pending_findings_after_checkpoint(workspace_tmp_dir):
    cursor_path = workspace_tmp_dir / f"defectdojo_cursor_{uuid4().hex}.json"
    cursor_path.write_text(
        json.dumps(
            {
                "signature": json.dumps(
                    {
                        "active": True,
                        "base_url": "http://defectdojo-test/api/v2",
                        "engagement_ids": [],
                        "product_ids": [],
                        "severity_filter": ["Critical", "High", "Medium"],
                        "test_ids": [],
                        "verified": True,
                    },
                    sort_keys=True,
                ),
                "last_id": 12,
                "last_status_update": "2026-04-09T10:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    client = _make_client(fetch_limit=10, cursor_path=str(cursor_path))

    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={"count": 120, "next": None, "results": []},
        status=200,
    )
    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/findings/",
        json={"count": 15, "next": None, "results": []},
        status=200,
    )

    summary = client.get_finding_count_summary()

    assert summary == {
        "matching_count": 120,
        "pending_count": 15,
        "checkpoint_applied": True,
        "processing_cap": 10,
        "estimated_processed_count": 10,
    }

    assert "last_status_update=" not in responses.calls[0].request.url
    assert "last_status_update=2026-04-09T10%3A00%3A00Z" in responses.calls[1].request.url


@responses.activate
def test_test_connection_rejects_html_login_page():
    client = _make_client()

    responses.add(
        responses.GET,
        "http://defectdojo-test/api/v2/user_contact_infos/",
        body="""
<!DOCTYPE html>
<html>
  <head><title>DefectDojo</title></head>
</html>
""",
        content_type="text/html",
        status=200,
    )

    assert client.test_connection() is False


def test_checkpoint_store_can_replace_local_cursor_file():
    class FakeCheckpointStore:
        def __init__(self):
            self.payloads = {}

        def load_checkpoint(self, checkpoint_key, expected_signature):
            entry = self.payloads.get(checkpoint_key)
            if not entry or entry["signature"] != expected_signature:
                return None
            return dict(entry["payload"])

        def save_checkpoint(self, checkpoint_key, signature, payload):
            self.payloads[checkpoint_key] = {
                "signature": signature,
                "payload": dict(payload),
            }

    checkpoint_store = FakeCheckpointStore()
    client = DefectDojoClient(
        DefectDojoConfig(
            base_url="http://defectdojo-test/api/v2",
            api_key="Token test-key",
            verify_ssl=False,
            cursor_path="state/defectdojo.json",
        ),
        checkpoint_store=checkpoint_store,
    )

    assert client._load_cursor() is None

    client._pending_checkpoint = {
        "last_status_update": "2026-04-09T10:00:00Z",
        "last_id": 99,
        "signature": client._cursor_signature(),
    }
    client.commit_pending_checkpoint()

    loaded = client._load_cursor()
    assert loaded == {
        "last_status_update": "2026-04-09T10:00:00Z",
        "last_id": 99,
    }
    assert "defectdojo:state/defectdojo.json" in checkpoint_store.payloads
