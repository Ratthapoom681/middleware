"""
Severity Mapper pipeline stage.

Maps source-native severity values to a unified scale and then
to Redmine priority IDs. This ensures consistent prioritization
regardless of whether the finding came from Wazuh or DefectDojo.
"""

from __future__ import annotations

import logging
from typing import Any

from app.models.finding import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

# Wazuh alert level → unified severity
WAZUH_LEVEL_THRESHOLDS: list[tuple[int, Severity]] = [
    (15, Severity.CRITICAL),
    (12, Severity.HIGH),
    (7, Severity.MEDIUM),
    (4, Severity.LOW),
    (0, Severity.INFO),
]

# DefectDojo severity string → unified severity
DEFECTDOJO_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class SeverityMapperStage:
    """
    Normalizes severity from different sources into a unified scale
    and maps it to Redmine priority IDs.
    """

    def __init__(self, priority_map: dict[str, int]):
        """
        Args:
            priority_map: Maps unified severity value → Redmine priority ID.
                          Example: {"critical": 5, "high": 4, ...}
        """
        self.priority_map = priority_map

    def process(self, findings: list[Finding]) -> list[Finding]:
        """Map severity for all findings."""
        for finding in findings:
            finding.severity = self._map_severity(finding)
            # Store the Redmine priority ID in enrichment for the output stage
            finding.enrichment["redmine_priority_id"] = self.get_redmine_priority(finding.severity)

        logger.info(
            "SeverityMapper: mapped %d findings — %s",
            len(findings),
            self._severity_summary(findings),
        )
        return findings

    def _map_severity(self, finding: Finding) -> Severity:
        """Determine unified severity based on source and raw_severity."""
        if finding.source == FindingSource.WAZUH:
            return self._map_wazuh_level(finding.raw_severity)
        elif finding.source == FindingSource.DEFECTDOJO:
            return self._map_defectdojo_severity(finding.raw_severity)
        else:
            return finding.severity

    @staticmethod
    def _map_wazuh_level(raw: str) -> Severity:
        """Map Wazuh numeric level (0–15) to unified severity."""
        try:
            level = int(raw)
        except (ValueError, TypeError):
            return Severity.INFO

        for threshold, severity in WAZUH_LEVEL_THRESHOLDS:
            if level >= threshold:
                return severity
        return Severity.INFO

    @staticmethod
    def _map_defectdojo_severity(raw: str) -> Severity:
        """Map DefectDojo severity string to unified severity."""
        if raw is None:
            return Severity.INFO
        return DEFECTDOJO_SEVERITY_MAP.get(str(raw).strip().lower(), Severity.INFO)

    def get_redmine_priority(self, severity: Severity) -> int:
        """Get the Redmine priority ID for a unified severity."""
        return self.priority_map.get(severity.value, 1)

    @staticmethod
    def _severity_summary(findings: list[Finding]) -> str:
        """Build a summary string of severity distribution."""
        counts: dict[str, int] = {}
        for f in findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
