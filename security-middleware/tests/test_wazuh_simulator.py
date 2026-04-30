"""
Tests for Fortigate Wazuh integration simulation payloads.
"""

from __future__ import annotations

from pathlib import Path

from tools.simulate_wazuh_integration import build_alert, default_count_for_use_case, load_sample


SAMPLE_PATH = Path(__file__).resolve().parent.parent / "samples" / "wazuh_fortigate_failed_login_indexer_hit.json"


def _source(payload: dict) -> dict:
    return payload["_source"]


def test_simulator_defaults_match_detection_thresholds():
    assert default_count_for_use_case("brute-force") == 5
    assert default_count_for_use_case("abnormal-port") == 1
    assert default_count_for_use_case("impossible-travel") == 2
    assert default_count_for_use_case("port-scan") == 16


def test_simulator_builds_fortigate_brute_force_indexer_hit():
    sample = load_sample(SAMPLE_PATH)
    payload = build_alert(
        sample,
        global_index=1,
        scenario="brute-force",
        scenario_index=1,
        srcip="85.11.187.20",
        agent_name="wazuh-server",
        payload_format="indexer",
    )

    alert = _source(payload)
    assert payload["_index"].startswith("wazuh-alerts-4.x-")
    assert alert["data"]["status"] == "failed"
    assert alert["data"]["srcip"] == "85.11.187.20"
    assert "authentication_failed" in alert["rule"]["groups"]
    assert alert["decoder"]["name"] == "fortigate-firewall-v6"


def test_simulator_builds_port_use_cases_with_required_dstport():
    sample = load_sample(SAMPLE_PATH)
    abnormal = _source(build_alert(
        sample,
        global_index=1,
        scenario="abnormal-port",
        scenario_index=1,
        srcip="85.11.187.20",
        agent_name="wazuh-server",
        payload_format="indexer",
    ))
    port_scan = _source(build_alert(
        sample,
        global_index=2,
        scenario="port-scan",
        scenario_index=16,
        srcip="85.11.187.20",
        agent_name="wazuh-server",
        payload_format="indexer",
    ))

    assert abnormal["data"]["dstport"] == "4444"
    assert port_scan["data"]["dstport"] == "20016"


def test_simulator_builds_impossible_travel_country_pair():
    sample = load_sample(SAMPLE_PATH)
    first = _source(build_alert(
        sample,
        global_index=1,
        scenario="impossible-travel",
        scenario_index=1,
        srcip="85.11.187.20",
        agent_name="wazuh-server",
        payload_format="indexer",
    ))
    second = _source(build_alert(
        sample,
        global_index=2,
        scenario="impossible-travel",
        scenario_index=2,
        srcip="85.11.187.20",
        agent_name="wazuh-server",
        payload_format="indexer",
    ))

    assert first["data"]["dstuser"] == "admin"
    assert second["data"]["dstuser"] == "admin"
    assert first["GeoLocation"]["country_name"] == "Bulgaria"
    assert second["GeoLocation"]["country_name"] == "Thailand"
