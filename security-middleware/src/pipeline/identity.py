"""
Pipeline Identity Processing.

Handles isolated identity resolution mapping per security source configuration.
Maintains separated `dedup_hash` derivation and `routing_key` formatting strategies.
"""

import hashlib
from src.models.finding import Finding, FindingSource

# Hash version bumped to v2 to enforce new srcip/endpoint separation schema.
DEDUP_NAMESPACE = "v2"


def _generate_wazuh_identity(finding: Finding) -> str:
    """Build canonical deduplication signature structure for Wazuh security events."""
    key_parts = [
        finding.source.value,
        finding.rule_id or "0",
        finding.title.strip().lower(),
        finding.host.strip().lower(),
        finding.srcip.strip().lower(),
        ",".join(sorted(finding.cve_ids)),
    ]
    return "|".join(key_parts)


def _generate_defectdojo_identity(finding: Finding) -> str:
    """Build canonical deduplication signature structure for DefectDojo vulnerability scans."""
    
    normalized_endpoints = ",".join(sorted([e.strip().lower() for e in finding.endpoints if e.strip()]))
    
    # --- ZAP Scan Context ---
    if "zap" in finding.found_by.lower():
        key_parts = [
            finding.source.value,
            finding.found_by.strip().lower(),
            finding.endpoint_url.strip().lower() or finding.host.strip().lower(),
            finding.cwe.strip(),
            finding.param.strip().lower(),
            finding.title.strip().lower(),
        ]
        return "|".join(key_parts)
        
    # --- Tenable Scan Context ---
    if "tenable" in finding.found_by.lower() or "nessus" in finding.found_by.lower():
        key_parts = [
            finding.source.value,
            finding.found_by.strip().lower(),
            normalized_endpoints or finding.host.strip().lower(),
            finding.plugin_id.strip().lower(),
            ",".join(sorted(finding.cve_ids)),
            finding.title.strip().lower(),
        ]
        return "|".join(key_parts)
    
    # --- Generic Scanner Fallback Context ---
    # If no endpoints physically parse, fall back to the component context to avoid blanket grouping.
    # If no components exist, fall back to the raw title string.
    asset_block = normalized_endpoints
    if not asset_block:
        asset_block = f"{finding.component.strip().lower()}:{finding.component_version.strip().lower()}"
    if asset_block == ":":
         asset_block = finding.title.strip().lower()

    key_parts = [
        finding.source.value,
        finding.found_by.strip().lower(),
        finding.title.strip().lower(),
        finding.component.strip().lower(),
        finding.component_version.strip().lower(),
        asset_block,
        ",".join(sorted(finding.cve_ids)),
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
        # Primary endpoint handles interface fallback context natively.
        routing_key = finding.endpoints[0] if finding.endpoints else (finding.host or "unknown")
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
