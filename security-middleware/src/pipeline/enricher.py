"""
Enricher pipeline stage.

Adds contextual information to findings before they become tickets:
- Asset metadata from a static inventory
- Remediation links
- CVSS scoring context
- Formatted description for Redmine
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from src.config import EnrichmentConfig
from src.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Known remediation link templates
REMEDIATION_TEMPLATES: dict[str, str] = {
    "CVE": "https://nvd.nist.gov/vuln/detail/{cve_id}",
    "MITRE": "https://attack.mitre.org/techniques/{technique_id}/",
}


class EnricherStage:
    """
    Enriches findings with additional context before ticket creation.
    """

    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self._asset_inventory: dict[str, dict[str, Any]] = {}

        if config.asset_inventory_enabled:
            self._load_asset_inventory()

    def _load_asset_inventory(self) -> None:
        """Load asset inventory from YAML file."""
        path = Path(self.config.asset_inventory_path)
        if not path.exists():
            logger.warning("Enricher: asset inventory not found at %s", path)
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            self._asset_inventory = data.get("assets", {})
            logger.info("Enricher: loaded %d assets from inventory", len(self._asset_inventory))
        except Exception as e:
            logger.error("Enricher: failed to load asset inventory: %s", e)

    def process(self, findings: list[Finding]) -> list[Finding]:
        """Enrich all findings with additional context."""
        for finding in findings:
            self._enrich_finding(finding)

        logger.info("Enricher: enriched %d findings", len(findings))
        return findings

    def _enrich_finding(self, finding: Finding) -> None:
        """Add enrichment data to a single finding."""

        # 1. Asset metadata
        if self._asset_inventory and finding.host:
            asset_info = self._lookup_asset(finding.host)
            if asset_info:
                finding.enrichment["asset"] = asset_info

        # 2. Remediation links
        if self.config.add_remediation_links:
            links = self._build_remediation_links(finding)
            if links:
                finding.enrichment["remediation_links"] = links

        # 3. Severity context
        finding.enrichment["severity_label"] = self._severity_label(finding.severity)

        # 4. Build formatted Redmine description
        finding.enrichment["redmine_description"] = self._format_redmine_description(finding)

    def _lookup_asset(self, host: str) -> Optional[dict[str, Any]]:
        """Look up asset metadata by hostname or IP."""
        host_lower = host.lower()
        for key, info in self._asset_inventory.items():
            if key.lower() == host_lower:
                return info
            # Check aliases
            aliases = [a.lower() for a in info.get("aliases", [])]
            if host_lower in aliases:
                return info
        return None

    @staticmethod
    def _build_remediation_links(finding: Finding) -> list[str]:
        """Generate remediation links based on CVE IDs and tags."""
        links: list[str] = []

        # NVD links for CVEs
        for cve_id in finding.cve_ids:
            links.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

        # MITRE ATT&CK links for technique IDs in tags
        for tag in finding.tags:
            if tag.upper().startswith("T") and tag[1:].replace(".", "").isdigit():
                links.append(f"https://attack.mitre.org/techniques/{tag}/")

        return links

    @staticmethod
    def _severity_label(severity: Severity) -> str:
        """Return a human-friendly severity label with emoji."""
        labels = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🔵 LOW",
            Severity.INFO: "⚪ INFO",
        }
        return labels.get(severity, "⚪ UNKNOWN")

    def _format_redmine_description(self, finding: Finding) -> str:
        """
        Build a rich Redmine-compatible description (Textile format).
        """
        parts: list[str] = []

        # Header
        parts.append(f"h2. {finding.enrichment.get('severity_label', finding.severity.value.upper())}")
        parts.append("")

        # Source info
        parts.append(f"|_. Source|{finding.source.value.upper()}|")
        parts.append(f"|_. Source ID|{finding.source_id}|")
        parts.append(f"|_. Host|{finding.host or 'N/A'}|")
        parts.append(f"|_. Timestamp|{finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}|")
        if finding.cvss is not None:
            parts.append(f"|_. CVSS Score|{finding.cvss}|")
        if finding.cve_ids:
            parts.append(f"|_. CVE IDs|{', '.join(finding.cve_ids)}|")
        if finding.rule_id:
            parts.append(f"|_. Rule ID|{finding.rule_id}|")
        parts.append("")

        # Description body
        parts.append("h3. Description")
        parts.append("")
        parts.append(finding.description)
        parts.append("")

        # Asset info (if enriched)
        asset_info = finding.enrichment.get("asset")
        if asset_info:
            parts.append("h3. Asset Information")
            parts.append("")
            for key, value in asset_info.items():
                if key != "aliases":
                    parts.append(f"|_. {key.replace('_', ' ').title()}|{value}|")
            parts.append("")

        # Remediation links
        links = finding.enrichment.get("remediation_links", [])
        if links:
            parts.append("h3. References")
            parts.append("")
            for link in links:
                parts.append(f"* {link}")
            parts.append("")

        # Dedup hash (for tracking)
        parts.append(f"---")
        parts.append(f"_Dedup Hash: @{finding.dedup_hash}@_")

        return "\n".join(parts)
