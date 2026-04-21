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
from src.models.finding import Finding, FindingSource, Severity

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
        if finding.source == FindingSource.WAZUH:
            return self._format_wazuh_redmine_description(finding)
        return self._format_default_redmine_description(finding)

    def _format_default_redmine_description(self, finding: Finding) -> str:
        """Build the default Redmine description for non-Wazuh findings."""
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

    def _format_wazuh_redmine_description(self, finding: Finding) -> str:
        """Build a Wazuh-focused Redmine description that surfaces the key signal quickly."""
        parts: list[str] = []
        alert = finding.raw_data or {}
        rule = alert.get("rule", {}) if isinstance(alert, dict) else {}
        agent = alert.get("agent", {}) if isinstance(alert, dict) else {}
        manager = alert.get("manager", {}) if isinstance(alert, dict) else {}
        data = alert.get("data", {}) if isinstance(alert, dict) else {}

        def add_row(label: str, value: Any) -> None:
            if value in (None, "", [], {}):
                return
            parts.append(f"|_. {label}|{value}|")

        def first_non_empty(*values: Any) -> str:
            for value in values:
                if value not in (None, ""):
                    return str(value)
            return ""

        parts.append(f"h2. {finding.enrichment.get('severity_label', finding.severity.value.upper())}")
        parts.append("")

        parts.append("h3. Alert Summary")
        parts.append("")
        add_row("Title", finding.title)
        add_row("Source", finding.source.value.upper())
        add_row("Rule ID", finding.rule_id or rule.get("id"))
        add_row("Rule Level", first_non_empty(rule.get("level"), finding.raw_severity))
        add_row("Agent", first_non_empty(agent.get("name"), finding.host))
        add_row("Manager", manager.get("name"))
        add_row("Device", first_non_empty(data.get("devname"), data.get("devid"), finding.routing_key))
        add_row("Severity", finding.severity.value.upper())
        add_row("Timestamp", finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
        parts.append("")

        parts.append("h3. What Happened")
        parts.append("")
        parts.append(rule.get("description") or finding.title)
        parts.append("")

        message = first_non_empty(data.get("msg"), alert.get("full_log"))
        if message:
            parts.append("h3. Primary Evidence")
            parts.append("")
            parts.append(f"<pre>{message}</pre>")
            parts.append("")

        parts.append("h3. Network Context")
        parts.append("")
        add_row("Source IP", first_non_empty(data.get("srcip"), finding.srcip))
        add_row("Source Country", data.get("srccountry"))
        add_row("Source Port", data.get("srcport"))
        add_row("Destination IP", data.get("dstip"))
        add_row("Destination Country", data.get("dstcountry"))
        add_row("Destination Port", data.get("dstport"))
        add_row("Protocol", first_non_empty(data.get("proto"), data.get("protocol")))
        add_row("Service", data.get("service"))
        add_row("Action", data.get("action"))
        parts.append("")

        parts.append("h3. Detection Context")
        parts.append("")
        add_row("Decoder", alert.get("decoder", {}).get("name") if isinstance(alert.get("decoder"), dict) else "")
        add_row("Groups", ", ".join(finding.rule_groups) if finding.rule_groups else "")
        add_row("Attack", data.get("attack"))
        add_row("Attack ID", data.get("attackid"))
        add_row("Count", data.get("count"))
        add_row("Policy ID", data.get("policyid"))
        add_row("Policy Type", data.get("policytype"))
        add_row("Event Type", data.get("eventtype"))
        add_row("Log ID", data.get("logid"))
        add_row("Location", alert.get("location"))
        parts.append("")

        asset_info = finding.enrichment.get("asset")
        if asset_info:
            parts.append("h3. Asset Information")
            parts.append("")
            for key, value in asset_info.items():
                if key != "aliases":
                    add_row(key.replace("_", " ").title(), value)
            parts.append("")

        links = finding.enrichment.get("remediation_links", [])
        if links:
            parts.append("h3. References")
            parts.append("")
            for link in links:
                parts.append(f"* {link}")
            parts.append("")

        parts.append("---")
        parts.append(f"_Dedup Hash: @{finding.dedup_hash}@_")
        return "\n".join(parts)
