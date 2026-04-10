"""
DefectDojo API client.

Connects to DefectDojo's REST API v2 and fetches active findings.
Each finding is converted into a unified Finding object.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

from src.config import DefectDojoConfig
from src.models.finding import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

# DefectDojo severity → unified severity mapping
DD_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class DefectDojoClient:
    """Client for the DefectDojo REST API v2."""

    def __init__(self, config: DefectDojoConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers.update({
            "Authorization": config.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def fetch_findings(self, limit: int = 100) -> list[Finding]:
        """
        Fetch active findings from DefectDojo.

        Args:
            limit: Maximum number of findings to fetch per page.

        Returns:
            List of Finding objects converted from DefectDojo findings.
        """
        findings: list[Finding] = []
        url = f"{self.base_url}/findings/"
        params: dict[str, Any] = {
            "active": "true",
            "duplicate": "false",
            "limit": limit,
            "offset": 0,
        }

        # Filter by severity
        if self.config.severity_filter:
            params["severity"] = ",".join(self.config.severity_filter)

        try:
            while True:
                response = self.session.get(url, params=params, timeout=60)
                response.raise_for_status()
                data = response.json()

                results = data.get("results", [])
                logger.info(
                    "DefectDojo: fetched %d findings (offset %d)",
                    len(results),
                    params["offset"],
                )

                for dd_finding in results:
                    finding = self._finding_to_model(dd_finding)
                    if finding:
                        findings.append(finding)

                # Pagination
                if data.get("next"):
                    params["offset"] += limit
                else:
                    break

        except RequestException as e:
            logger.error("DefectDojo: failed to fetch findings: %s", e)

        logger.info("DefectDojo: total findings fetched: %d", len(findings))
        return findings

    def _finding_to_model(self, dd_finding: dict[str, Any]) -> Optional[Finding]:
        """Convert a single DefectDojo finding to a Finding."""
        try:
            severity_str = dd_finding.get("severity", "Info")
            severity_key = str(severity_str).strip().lower()
            severity = DD_SEVERITY_MAP.get(severity_key, Severity.INFO)

            # Extract CVE IDs from vulnerability_ids
            cve_ids = []
            for vuln_id in dd_finding.get("vulnerability_ids", []):
                vid = vuln_id.get("vulnerability_id", "")
                if vid.startswith("CVE-"):
                    cve_ids.append(vid)

            # Extract host/endpoint info
            endpoints = dd_finding.get("endpoints", [])
            host = ""
            if endpoints:
                # Endpoints are IDs in DDefectDojo — use first one as reference
                host = str(endpoints[0])

            # Parse dates
            date_str = dd_finding.get("date", "")
            try:
                timestamp = datetime.strptime(date_str, "%Y-%m-%d")
            except (ValueError, TypeError):
                timestamp = datetime.utcnow()

            # Build rich description
            desc_parts = [
                dd_finding.get("description", "No description"),
                "",
                f"**Severity:** {severity_str}",
                f"**Component:** {dd_finding.get('component_name', 'N/A')} "
                f"{dd_finding.get('component_version', '')}",
            ]

            if dd_finding.get("cvssv3"):
                desc_parts.append(f"**CVSS v3:** {dd_finding['cvssv3']}")
            if dd_finding.get("mitigation"):
                desc_parts.append(f"\n**Mitigation:**\n{dd_finding['mitigation']}")
            if dd_finding.get("references"):
                desc_parts.append(f"\n**References:**\n{dd_finding['references']}")

            # Tags
            tags = list(dd_finding.get("tags", []))
            if dd_finding.get("test_type_name"):
                tags.append(f"scan:{dd_finding['test_type_name']}")

            return Finding(
                source=FindingSource.DEFECTDOJO,
                source_id=str(dd_finding.get("id", "unknown")),
                title=dd_finding.get("title", "DefectDojo Finding"),
                description="\n".join(desc_parts),
                severity=severity,
                raw_severity=severity_str,
                host=host,
                cvss=dd_finding.get("cvssv3_score"),
                cve_ids=list(set(cve_ids)),
                tags=tags,
                timestamp=timestamp,
                raw_data=dd_finding,
            )

        except Exception as e:
            logger.warning("DefectDojo: failed to parse finding: %s", e)
            return None

    def test_connection(self) -> bool:
        """Test connectivity to the DefectDojo API."""
        try:
            response = self.session.get(
                f"{self.base_url}/user_contact_infos/",
                params={"limit": 1},
                timeout=10,
            )
            response.raise_for_status()
            logger.info("DefectDojo: connection test successful")
            return True
        except Exception as e:
            logger.error("DefectDojo: connection test failed: %s", e)
            return False
