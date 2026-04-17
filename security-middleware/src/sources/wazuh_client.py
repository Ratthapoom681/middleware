"""
Wazuh client.

Fetches alerts from the Wazuh Indexer (OpenSearch, port 9200) and
uses the Wazuh Manager API (port 55000) for connection testing.

Wazuh Architecture:
  - Manager API (55000): Agent management, configuration, rules — no alerts.
  - Indexer API (9200):   OpenSearch-based storage of wazuh-alerts-* indices.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
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
    """Client for the Wazuh Indexer (alerts) and Manager API (connection test)."""

    def __init__(self, config: WazuhConfig):
        self.config = config

        # Manager API (for test_connection)
        self.base_url = config.base_url.rstrip("/")
        if self.base_url.startswith("http://") and ":55000" in self.base_url:
            self.base_url = self.base_url.replace("http://", "https://")
        if not self.base_url.startswith("http"):
            self.base_url = "https://" + self.base_url

        # Indexer API (for fetching alerts)
        self.indexer_url = config.indexer_url.rstrip("/")
        if not self.indexer_url.startswith("http"):
            self.indexer_url = "https://" + self.indexer_url

        # Session for Manager API (JWT auth)
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

        # Session for Indexer API (Basic auth)
        self.indexer_session = requests.Session()
        self.indexer_session.verify = config.verify_ssl
        self.indexer_session.auth = (config.indexer_username, config.indexer_password)
        self.indexer_session.headers["Content-Type"] = "application/json"

        self._last_poll: Optional[datetime] = None

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

    # ── File position tracking for alerts.json ─────────────────────────
    _file_position: int = 0

    # ── Alert fetching (routes to file or indexer) ─────────────────────

    def fetch_alerts(self, since_minutes: int = 5) -> list[Finding]:
        """
        Fetch recent alerts. Routes to file-based or Indexer-based
        depending on whether alerts_json_path is configured.
        """
        if self.config.alerts_json_path:
            return self._fetch_from_file()
        else:
            return self._fetch_from_indexer(since_minutes)

    # ── File-based alert reading ───────────────────────────────────────

    def _fetch_from_file(self) -> list[Finding]:
        """
        Read new alerts from the Wazuh alerts.json log file.
        Tracks file position so each call only reads new lines.
        """
        import json
        import os

        path = self.config.alerts_json_path
        if not os.path.exists(path):
            logger.error("Wazuh alerts file not found: %s", path)
            return []

        findings: list[Finding] = []
        file_size = os.path.getsize(path)

        # If file was rotated (shrunk), reset position
        if file_size < self._file_position:
            logger.info("Wazuh alerts file rotated, resetting position")
            self._file_position = 0

        # On first run, seek to end so we only get new alerts going forward
        # Set _file_position = 0 initially, then on first call jump to end
        if self._last_poll is None:
            self._file_position = file_size
            self._last_poll = datetime.now(timezone.utc)
            logger.info("Wazuh file reader: initialized at position %d (%.1f MB), will read new alerts from now on",
                        self._file_position, file_size / 1024 / 1024)
            return []

        if self._file_position >= file_size:
            logger.info("Wazuh file reader: no new data (position %d)", self._file_position)
            return []

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._file_position)
                lines_read = 0
                parse_errors = 0

                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    lines_read += 1
                    try:
                        alert = json.loads(line)
                    except json.JSONDecodeError:
                        parse_errors += 1
                        continue

                    # Apply min_level filter
                    rule_level = alert.get("rule", {}).get("level", 0)
                    if rule_level < self.config.min_level:
                        continue

                    finding = self._alert_to_finding(alert)
                    if finding:
                        findings.append(finding)

                self._file_position = f.tell()

            logger.info("Wazuh file reader: read %d lines, parsed %d alerts (min_level=%d), %d parse errors",
                        lines_read, len(findings), self.config.min_level, parse_errors)

        except Exception as e:
            logger.error("Wazuh file reader: failed to read alerts: %s", e)

        self._last_poll = datetime.now(timezone.utc)
        return findings

    # ── Indexer-based alert fetching ───────────────────────────────────

    def _fetch_from_indexer(self, since_minutes: int = 5) -> list[Finding]:
        """
        Fetch ALL recent alerts from the Wazuh Indexer (OpenSearch).
        Uses search_after pagination to handle large result sets.
        """
        # On first poll, look back by since_minutes to catch existing alerts
        # On subsequent polls, use the last poll time
        if self._last_poll is None:
            since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        else:
            since = self._last_poll

        since_str = since.strftime("%Y-%m-%dT%H:%M:%S+00:00")

        url = f"{self.indexer_url}/wazuh-alerts-*/_search"
        page_size = 1000

        # Build OpenSearch query — Wazuh uses @timestamp (ELK convention)
        query_body: dict[str, Any] = {
            "size": page_size,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"_id": {"order": "asc"}},
            ],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since_str}}},
                    ]
                }
            }
        }

        # Add minimum rule level filter
        if self.config.min_level > 0:
            query_body["query"]["bool"]["must"].append(
                {"range": {"rule.level": {"gte": self.config.min_level}}}
            )

        logger.info("Wazuh Indexer: querying since=%s, min_level=%d", since_str, self.config.min_level)

        findings: list[Finding] = []
        total_hits = 0
        page = 0

        try:
            while True:
                page += 1
                response = self.indexer_session.post(url, json=query_body, timeout=60)
                response.raise_for_status()
                data = response.json()

                total_info = data.get("hits", {}).get("total", {})
                hits = data.get("hits", {}).get("hits", [])

                if page == 1:
                    total_count = total_info.get("value", 0) if isinstance(total_info, dict) else total_info
                    logger.info("Wazuh Indexer: total matching=%s, fetching all pages...", total_count)

                if not hits:
                    break

                total_hits += len(hits)

                for hit in hits:
                    alert = hit.get("_source", {})
                    alert["_id"] = hit.get("_id", "")
                    finding = self._alert_to_finding(alert)
                    if finding:
                        findings.append(finding)

                # If we got fewer than page_size, we're done
                if len(hits) < page_size:
                    break

                # Use search_after with the sort values from the last hit
                last_hit = hits[-1]
                query_body["search_after"] = last_hit.get("sort")

            logger.info("Wazuh Indexer: fetched %d total hits across %d pages, parsed %d findings",
                        total_hits, page, len(findings))

            self._last_poll = datetime.now(timezone.utc)

        except RequestException as e:
            logger.error("Wazuh Indexer: failed to fetch alerts: %s", e)

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

            # Parse timestamp — Wazuh Indexer uses @timestamp
            timestamp_str = alert.get("@timestamp", alert.get("timestamp", ""))
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("+0000", "+00:00").replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            # Priority: data.devname > data.devid > agent.name > agent.ip
            host_name = data.get("devname") or data.get("devid") or agent.get("name") or agent.get("ip") or "unknown"
            routing_key = data.get("devname", "")

            return Finding(
                source=FindingSource.WAZUH,
                source_id=alert.get("id", str(alert.get("_id", "unknown"))),
                title=rule.get("description", "Wazuh Alert"),
                description="\n".join(description_parts),
                severity=severity,
                raw_severity=str(level),
                host=host_name,
                routing_key=routing_key,
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
        """Test connectivity to the Wazuh Manager API and Indexer."""
        try:
            # Test Manager API
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

            # Test Indexer
            idx_resp = self.indexer_session.get(self.indexer_url, timeout=10)
            idx_resp.raise_for_status()
            idx_info = idx_resp.json()
            logger.info(
                "Wazuh Indexer: connected — cluster %s, version %s",
                idx_info.get("cluster_name", "?"),
                idx_info.get("version", {}).get("number", "?"),
            )

            return True
        except Exception as e:
            logger.error("Wazuh: connection test failed: %s", e)
            return False
