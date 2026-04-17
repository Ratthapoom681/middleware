"""
DefectDojo API client.

Connects to DefectDojo's REST API v2 and fetches active findings.
Each finding is converted into a unified Finding object.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

from src.config import DefectDojoConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.identity import hydrate_identity

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
        self.cursor_path = Path(config.cursor_path)
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
        cursor_state = self._load_cursor()
        page_limit = limit
        if self.config.fetch_limit > 0:
            page_limit = min(limit, self.config.fetch_limit)
        params: dict[str, Any] = {
            "active": "true" if self.config.active else "false",
            "verified": "true" if self.config.verified else "false",
            "duplicate": "false",
            "limit": page_limit,
            "offset": 0,
            # Stable ascending ordering lets us checkpoint on (timestamp, id).
            "ordering": "last_status_update,id",
        }

        if self.config.product_ids:
            params["test__engagement__product"] = ",".join(map(str, self.config.product_ids))
        if self.config.engagement_ids:
            params["test__engagement"] = ",".join(map(str, self.config.engagement_ids))
        if self.config.test_ids:
            params["test"] = ",".join(map(str, self.config.test_ids))
            
        if cursor_state:
            params["last_status_update"] = cursor_state["last_status_update"]
        elif self.config.updated_since_minutes > 0:
            past_time = datetime.utcnow() - timedelta(minutes=self.config.updated_since_minutes)
            params["last_status_update"] = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Filter by severity
        if self.config.severity_filter:
            params["severity"] = ",".join(self.config.severity_filter)

        next_cursor_state = cursor_state
        try:
            while True:
                response = self.session.get(url, params=params, timeout=60)
                response.raise_for_status()

                # Check if response is actually JSON
                content_type = response.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    logger.error(
                        "DefectDojo: expected JSON but got '%s'. Response body (first 500 chars): %s",
                        content_type, response.text[:500]
                    )
                    break

                try:
                    data = response.json()
                except ValueError as e:
                    logger.error(
                        "DefectDojo: failed to parse JSON. Response (first 500 chars): %s",
                        response.text[:500]
                    )
                    break

                results = data.get("results", [])
                logger.info(
                    "DefectDojo: fetched %d findings (offset %d)",
                    len(results),
                    params["offset"],
                )

                reached_limit = False
                for dd_finding in results:
                    if cursor_state and not self._is_after_cursor(dd_finding, cursor_state):
                        continue

                    finding = self._finding_to_model(dd_finding)
                    if finding:
                        findings.append(finding)
                        cursor_candidate = self._make_cursor_state(dd_finding)
                        if cursor_candidate:
                            next_cursor_state = cursor_candidate

                    if self.config.fetch_limit > 0 and len(findings) >= self.config.fetch_limit:
                        reached_limit = True
                        break

                # Pagination
                if reached_limit:
                    break
                if data.get("next"):
                    params["offset"] += page_limit
                else:
                    break

        except RequestException as e:
            logger.error("DefectDojo: failed to fetch findings: %s", e)

        if next_cursor_state and findings:
            self._save_cursor(next_cursor_state)

        logger.info("DefectDojo: total findings fetched: %d", len(findings))
        return findings

    def _cursor_signature(self) -> str:
        """Build a signature so stale cursors are discarded after config changes."""
        signature = {
            "base_url": self.base_url,
            "active": self.config.active,
            "verified": self.config.verified,
            "severity_filter": self.config.severity_filter,
            "product_ids": self.config.product_ids,
            "engagement_ids": self.config.engagement_ids,
            "test_ids": self.config.test_ids,
        }
        return json.dumps(signature, sort_keys=True)

    def _load_cursor(self) -> dict[str, Any] | None:
        """Load the persisted high-watermark for incremental DefectDojo polling."""
        if not self.cursor_path.exists():
            return None

        try:
            data = json.loads(self.cursor_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("DefectDojo: failed to load cursor state: %s", exc)
            return None

        if data.get("signature") != self._cursor_signature():
            logger.info("DefectDojo: cursor filters changed, resetting incremental cursor")
            return None

        last_status_update = data.get("last_status_update")
        last_id = data.get("last_id")
        if not last_status_update or last_id is None:
            return None

        return {
            "last_status_update": str(last_status_update),
            "last_id": int(last_id),
            "signature": data["signature"],
        }

    def _save_cursor(self, state: dict[str, Any]) -> None:
        """Persist the latest processed DefectDojo cursor to disk."""
        payload = {
            "version": 1,
            "signature": self._cursor_signature(),
            "last_status_update": state["last_status_update"],
            "last_id": int(state["last_id"]),
        }
        try:
            self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning("DefectDojo: failed to persist cursor state: %s", exc)

    def _make_cursor_state(self, dd_finding: dict[str, Any]) -> dict[str, Any] | None:
        """Extract a stable high-watermark from a DefectDojo finding."""
        last_status_update = dd_finding.get("last_status_update")
        finding_id = dd_finding.get("id")
        if not last_status_update or finding_id is None:
            return None
        return {
            "last_status_update": str(last_status_update),
            "last_id": int(finding_id),
            "signature": self._cursor_signature(),
        }

    def _is_after_cursor(self, dd_finding: dict[str, Any], cursor_state: dict[str, Any]) -> bool:
        """Return True when a finding sorts strictly after the persisted cursor."""
        finding_cursor = self._make_cursor_state(dd_finding)
        if not finding_cursor:
            return True

        finding_ts = finding_cursor["last_status_update"]
        cursor_ts = cursor_state["last_status_update"]
        if finding_ts > cursor_ts:
            return True
        if finding_ts < cursor_ts:
            return False
        return int(finding_cursor["last_id"]) > int(cursor_state["last_id"])

    def _finding_to_model(self, dd_finding: dict[str, Any]) -> Optional[Finding]:
        """Convert a single DefectDojo finding to a Finding."""
        try:
            severity_str = dd_finding.get("severity", "Info")
            severity_key = str(severity_str).strip().lower()
            severity = DD_SEVERITY_MAP.get(severity_key, Severity.INFO)

            # Extract CVE IDs from vulnerability_ids
            cve_ids = []
            vulnerability_ids = dd_finding.get("vulnerability_ids", [])
            for vuln_id in vulnerability_ids:
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

            cwe = str(dd_finding.get("cwe", "")) if dd_finding.get("cwe") else ""
            param = dd_finding.get("param", "")
            
            # Map robust endpoint_url from DefectDojo endpoint schemas if they exist in full format
            endpoint_url = ""
            if dd_finding.get("endpoints") and isinstance(dd_finding["endpoints"][0], dict):
                # Sometimes expanded payload holds URL
                endpoint_url = dd_finding["endpoints"][0].get("url", "")
            
            # Locate scanner specific signatures
            found_by = dd_finding.get("test_type_name", "")
            plugin_id = self._extract_plugin_id(dd_finding, vulnerability_ids, found_by)
                
            finding = Finding(
                source=FindingSource.DEFECTDOJO,
                source_id=str(dd_finding.get("id", "unknown")),
                title=dd_finding.get("title", "DefectDojo Finding"),
                description="\n".join(desc_parts),
                severity=severity,
                raw_severity=severity_str,
                host=host,
                endpoints=[str(e) for e in endpoints],
                endpoint_url=endpoint_url or host,
                component=dd_finding.get('component_name', ''),
                component_version=dd_finding.get('component_version', ''),
                cwe=cwe,
                param=param,
                found_by=found_by,
                plugin_id=plugin_id,
                cvss=dd_finding.get("cvssv3_score"),
                cve_ids=list(set(cve_ids)),
                tags=tags,
                timestamp=timestamp,
                raw_data=dd_finding,
                enrichment={
                    "defectdojo_url": f"{self.base_url.replace('/api/v2', '')}/finding/{dd_finding.get('id')}"
                }
            )
            return hydrate_identity(finding)

        except Exception as e:
            logger.warning("DefectDojo: failed to parse finding: %s", e)
            return None

    def _extract_plugin_id(
        self,
        dd_finding: dict[str, Any],
        vulnerability_ids: list[dict[str, Any]],
        found_by: str,
    ) -> str:
        """Extract a stable scanner/plugin identifier for Tenable-style findings."""
        found_by_key = found_by.strip().lower()
        preferred_ids: list[str] = []
        fallback_ids: list[str] = []

        for vuln_id in vulnerability_ids:
            vid = str(vuln_id.get("vulnerability_id", "")).strip()
            if not vid or vid.upper().startswith("CVE-"):
                continue

            id_type_parts = [
                str(vuln_id.get("source", "")),
                str(vuln_id.get("type", "")),
                str(vuln_id.get("name", "")),
            ]
            id_type = " ".join(part.strip().lower() for part in id_type_parts if part)

            if any(token in id_type for token in ("plugin", "nessus", "tenable")):
                preferred_ids.append(vid)
            else:
                fallback_ids.append(vid)

        if "tenable" in found_by_key or "nessus" in found_by_key:
            if preferred_ids:
                return preferred_ids[0]
            if fallback_ids:
                return fallback_ids[0]

        plugin_val = str(dd_finding.get("vulnerability_id", "")).strip()
        if plugin_val and not plugin_val.upper().startswith("CVE-"):
            return plugin_val

        if preferred_ids:
            return preferred_ids[0]
        if fallback_ids:
            return fallback_ids[0]
        return ""

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
