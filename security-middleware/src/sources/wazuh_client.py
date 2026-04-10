"""
Wazuh API client.

Connects to the Wazuh Manager REST API, authenticates via JWT,
and fetches alerts since the last poll. Each alert is converted
into a unified Finding object.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

from src.config import WazuhConfig
from src.models.finding import Finding, FindingSource, Severity

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
    """Client for the Wazuh Manager REST API."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        
        # Auto-correct http -> https for the default Wazuh API port
        if self.base_url.startswith("http://") and ":55000" in self.base_url:
            self.base_url = self.base_url.replace("http://", "https://")
            
        # Ensure it has a scheme
        if not self.base_url.startswith("http"):
            self.base_url = "https://" + self.base_url

        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._last_poll: Optional[datetime] = None

        # Suppress SSL warnings if verify is disabled
        if not config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _authenticate(self) -> None:
        """Obtain a JWT token from Wazuh API."""
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
            self._token_expiry = datetime.utcnow() + timedelta(seconds=850)
            self.session.headers["Authorization"] = f"Bearer {self._token}"
            logger.info("Wazuh: authenticated successfully")
        except RequestException as e:
            err_msg = str(e)
            if "RemoteDisconnected" in err_msg or "ConnectionResetError" in err_msg:
                err_msg += " (Hint: Make sure the Wazuh Base URL starts with 'https://', not 'http://')"
            logger.error("Wazuh: authentication failed: %s", err_msg)
            raise RuntimeError(err_msg) from e

    def _ensure_auth(self) -> None:
        """Re-authenticate if token is missing or expired."""
        if not self._token or (self._token_expiry and datetime.utcnow() >= self._token_expiry):
            self._authenticate()

    def fetch_alerts(self, since_minutes: int = 5) -> list[Finding]:
        """
        Fetch recent alerts from Wazuh.

        Args:
            since_minutes: Look back this many minutes for alerts.

        Returns:
            List of Finding objects converted from Wazuh alerts.
        """
        self._ensure_auth()

        # Build time filter
        since = self._last_poll or (datetime.utcnow() - timedelta(minutes=since_minutes))
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S+0000")

        url = f"{self.base_url}/alerts"
        params = {
            "limit": 500,
            "sort": "-timestamp",
            "q": f"timestamp>{since_str}",
        }

        # Filter by minimum level
        if self.config.min_level > 0:
            params["q"] += f";rule.level>={self.config.min_level}"

        findings: list[Finding] = []

        try:
            response = self.session.get(url, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()

            alerts = data.get("data", {}).get("affected_items", [])
            logger.info("Wazuh: fetched %d alerts", len(alerts))

            for alert in alerts:
                finding = self._alert_to_finding(alert)
                if finding:
                    findings.append(finding)

            self._last_poll = datetime.utcnow()

        except RequestException as e:
            logger.error("Wazuh: failed to fetch alerts: %s", e)

        return findings

    def _alert_to_finding(self, alert: dict[str, Any]) -> Optional[Finding]:
        """Convert a single Wazuh alert to a Finding."""
        try:
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})
            data = alert.get("data", {})

            level = rule.get("level", 0)
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

            # Parse timestamp
            timestamp_str = alert.get("timestamp", "")
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("+0000", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.utcnow()

            return Finding(
                source=FindingSource.WAZUH,
                source_id=alert.get("id", str(alert.get("_id", "unknown"))),
                title=rule.get("description", "Wazuh Alert"),
                description="\n".join(description_parts),
                severity=severity,
                raw_severity=str(level),
                host=agent.get("name", agent.get("ip", "unknown")),
                cve_ids=list(set(cve_ids)),
                tags=rule.get("groups", []),
                timestamp=timestamp,
                rule_id=str(rule.get("id", "")),
                rule_groups=rule.get("groups", []),
                raw_data=alert,
            )

        except Exception as e:
            logger.warning("Wazuh: failed to parse alert: %s", e)
            return None

    def test_connection(self) -> bool:
        """Test connectivity to the Wazuh API."""
        try:
            self._authenticate()
            response = self.session.get(
                f"{self.base_url}/manager/info",
                timeout=10,
            )
            response.raise_for_status()
            info = response.json().get("data", {}).get("affected_items", [{}])[0]
            logger.info(
                "Wazuh: connected — version %s, node %s",
                info.get("version", "?"),
                info.get("node_name", "?"),
            )
            return True
        except Exception as e:
            logger.error("Wazuh: connection test failed: %s", e)
            return False
