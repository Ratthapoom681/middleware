"""
Pipeline Identity Processing.

Handles isolated identity resolution mapping per security source configuration.
Maintains separated `dedup_hash` derivation and `routing_key` formatting strategies.
"""

import hashlib
from typing import Any

from app.models.finding import Finding, FindingSource

# Hash version bumped to v2 to enforce new srcip/endpoint separation schema.
DEDUP_NAMESPACE = "v3"


def _normalized_text(value: Any) -> str:
    """Normalize a string token for stable identity composition."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalized_csv(values: list[str]) -> str:
    """Normalize and sort list values for deterministic identity keys."""
    normalized = sorted({
        normalized_value
        for value in values
        for normalized_value in [_normalized_text(value)]
        if normalized_value
    })
    return ",".join(normalized)


def _normalized_endpoints(finding: Finding) -> str:
    """Build a stable endpoint list for DefectDojo identities."""
    return _normalized_csv(finding.endpoints)


def _defectdojo_profile(finding: Finding) -> str:
    """Select the scanner-aware identity profile for a DefectDojo finding."""
    found_by = _normalized_text(finding.found_by)
    if "zap" in found_by:
        return "zap"
    if "tenable" in found_by or "nessus" in found_by:
        return "tenable"
    return "generic"


def _generic_asset_key(finding: Finding, normalized_endpoints: str) -> str:
    """Choose a stable asset/component discriminator for non-specialized scanners."""
    if normalized_endpoints:
        return normalized_endpoints
    if _normalized_text(finding.host):
        return _normalized_text(finding.host)
    component_key = f"{_normalized_text(finding.component)}:{_normalized_text(finding.component_version)}"
    if component_key != ":":
        return component_key
    return _normalized_text(finding.title)


def _generate_wazuh_identity(finding: Finding) -> str:
    """Build canonical deduplication signature structure for Wazuh security events."""
    key_parts = [
        finding.source.value,
        finding.rule_id or "0",
        _normalized_text(finding.title),
        _normalized_text(finding.host),
        _normalized_text(finding.srcip),
        _normalized_csv(finding.cve_ids),
    ]
    return "|".join(key_parts)


def _generate_defectdojo_identity(finding: Finding) -> str:
    """Build canonical deduplication signature structure for DefectDojo vulnerability scans."""

    normalized_endpoints = _normalized_endpoints(finding)
    found_by = _normalized_text(finding.found_by)
    title = _normalized_text(finding.title)
    cves = _normalized_csv(finding.cve_ids)
    profile = _defectdojo_profile(finding)

    if profile == "zap":
        key_parts = [
            finding.source.value,
            found_by,
            _normalized_text(finding.endpoint_url) or _normalized_text(finding.host),
            _normalized_text(finding.cwe),
            _normalized_text(finding.param),
            title,
        ]
        return "|".join(key_parts)

    if profile == "tenable":
        key_parts = [
            finding.source.value,
            found_by,
            normalized_endpoints or _normalized_text(finding.host),
            _normalized_text(finding.plugin_id),
            cves,
            title,
        ]
        return "|".join(key_parts)

    key_parts = [
        finding.source.value,
        found_by,
        _generic_asset_key(finding, normalized_endpoints),
        _normalized_text(finding.component),
        _normalized_text(finding.component_version),
        cves,
        title,
    ]
    return "|".join(key_parts)


def hydrate_identity(finding: Finding) -> Finding:
    """
    Populate derived identity boundaries (`routing_key`, `dedup_key`, `dedup_hash`) into tracking states.
    """
    # 1. Deduplication Generation
    if finding.source == FindingSource.WAZUH:
        raw_key = _generate_wazuh_identity(finding)
        # Default agent hierarchy pre-determined in finding.host is strictly correct for routing.
        routing_key = finding.host
    elif finding.source == FindingSource.DEFECTDOJO:
        raw_key = _generate_defectdojo_identity(finding)
        routing_key = finding.host or finding.endpoint_url or (finding.endpoints[0] if finding.endpoints else "unknown")
    else:
        # Failsafe identity
        raw_key = f"unknown|{finding.title}|{finding.host}"
        routing_key = finding.host

    finding.dedup_key = raw_key
    
    # Namespaced cryptographic reduction natively protects migrations while shielding storage constraints
    signature_payload = f"{DEDUP_NAMESPACE}|{raw_key}"
    finding.dedup_hash = hashlib.sha256(signature_payload.encode("utf-8")).hexdigest()
    
    finding.routing_key = routing_key
    
    return finding
