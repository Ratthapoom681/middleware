"""
Wazuh client.

Parses Wazuh webhook payloads into middleware findings and uses the
Wazuh Manager API (port 55000) for connection testing.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

from src.config import WazuhConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.identity import hydrate_identity

logger = logging.getLogger(__name__)

# Wazuh alert level → unified severity mapping
WAZUH_LEVEL_MAP: list[tuple[int, Severity]] = [
    (15, Severity.CRITICAL),
    (12, Severity.HIGH),
    (7, Severity.MEDIUM),
    (4, Severity.LOW),
    (0, Severity.INFO),
]


def _map_wazuh_level(level: int) -> Severity:
    """Map Wazuh alert level (0-15) to unified severity."""
    for threshold, severity in WAZUH_LEVEL_MAP:
        if level >= threshold:
            return severity
    return Severity.INFO


class WazuhClient:
    """Client for Wazuh webhook parsing and Manager API connection testing."""

    def __init__(self, config: WazuhConfig):
        self.config = config

        # Manager API (for test_connection)
        self.base_url = config.base_url.rstrip("/")
        if self.base_url.startswith("http://") and ":55000" in self.base_url:
            self.base_url = self.base_url.replace("http://", "https://")
        if not self.base_url.startswith("http"):
            self.base_url = "https://" + self.base_url

        # Session for Manager API (JWT auth)
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

        # Suppress SSL warnings if verify is disabled
        if not config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Manager API (authentication & test) ────────────────────────────

    def _authenticate(self) -> None:
        """Obtain a JWT token from Wazuh Manager API."""
        url = f"{self.base_url}/security/user/authenticate"
        try:
            response = self.session.post(
                url,
                auth=(self.config.username, self.config.password),
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            self._token = data.get("data", {}).get("token", "")
            # Wazuh tokens typically expire in 900s (15 min)
            self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=850)
            self.session.headers["Authorization"] = f"Bearer {self._token}"
            logger.info("Wazuh Manager: authenticated successfully")
        except RequestException as e:
            err_msg = str(e)
            if "RemoteDisconnected" in err_msg or "ConnectionResetError" in err_msg:
                err_msg += " (Hint: Make sure the Wazuh Base URL starts with 'https://', not 'http://')"
            logger.error("Wazuh Manager: authentication failed: %s", err_msg)
            raise RuntimeError(err_msg) from e

    def _ensure_auth(self) -> None:
        """Re-authenticate if token is missing or expired."""
        if not self._token or (self._token_expiry and datetime.now(timezone.utc) >= self._token_expiry):
            self._authenticate()

    def _alert_to_finding(self, alert: dict[str, Any]) -> Optional[Finding]:
        """Convert a single Wazuh alert to a Finding."""
        try:
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})
            data = alert.get("data", {})

            try:
                level = int(rule.get("level", 0) or 0)
            except (TypeError, ValueError):
                level = 0
            if level < self.config.min_level:
                return None

            severity = _map_wazuh_level(level)

            # Extract CVE IDs if present
            cve_ids = []
            if "cve" in data:
                cve_ids = [data["cve"]] if isinstance(data["cve"], str) else data["cve"]
            if rule.get("cve"):
                cve_ids.append(rule["cve"])

            # Build description
            description_parts = [
                rule.get("description", "No description"),
                f"\n**Agent:** {agent.get('name', 'unknown')} ({agent.get('ip', 'unknown')})",
                f"**Rule ID:** {rule.get('id', 'unknown')}",
                f"**Level:** {level}/15",
            ]
            if rule.get("groups"):
                description_parts.append(f"**Groups:** {', '.join(rule['groups'])}")
            if rule.get("mitre"):
                mitre = rule["mitre"]
                if mitre.get("id"):
                    description_parts.append(f"**MITRE ATT&CK:** {', '.join(mitre['id'])}")

            # Parse timestamp; webhooks and indexed alerts commonly use either key.
            timestamp_str = alert.get("@timestamp", alert.get("timestamp", ""))
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("+0000", "+00:00").replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            # Priority: data.devname > data.devid > agent.name > agent.ip
            host_name = data.get("devname") or data.get("devid") or agent.get("name") or agent.get("ip") or "unknown"

            # Extract GeoIP and network fields from Wazuh alert data
            geo_location = alert.get("GeoLocation", {}) or {}

            finding = Finding(
                source=FindingSource.WAZUH,
                source_id=alert.get("id", str(alert.get("_id", "unknown"))),
                title=rule.get("description", "Wazuh Alert"),
                description="\n".join(description_parts),
                severity=severity,
                raw_severity=str(level),
                host=host_name,
                srcip=data.get("srcip", ""),
                dstip=data.get("dstip", ""),
                dstport=str(data.get("dstport", "")),
                protocol=str(data.get("protocol", "")),
                src_country=data.get("srccountry", ""),
                dst_country=data.get("dstcountry", ""),
                geolocation=geo_location,
                cve_ids=list(set(cve_ids)),
                tags=rule.get("groups", []),
                timestamp=timestamp,
                rule_id=str(rule.get("id", "")),
                rule_groups=rule.get("groups", []),
                raw_data=alert,
            )
            
            return hydrate_identity(finding)

        except Exception as e:
            logger.warning("Wazuh: failed to parse alert: %s", e)
            return None

    def test_connection(self) -> bool:
        """Test connectivity to the Wazuh Manager API."""
        try:
            self._authenticate()
            response = self.session.get(
                f"{self.base_url}/manager/info",
                timeout=10,
            )
            response.raise_for_status()
            info = response.json().get("data", {}).get("affected_items", [{}])[0]
            logger.info(
                "Wazuh Manager: connected — version %s, node %s",
                info.get("version", "?"),
                info.get("node_name", "?"),
            )
            return True
        except Exception as e:
            logger.error("Wazuh: connection test failed: %s", e)
            return False
