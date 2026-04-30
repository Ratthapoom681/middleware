"""
Unified Finding data model.

All security findings from Wazuh and DefectDojo are normalized into this
common schema before being processed by the middleware pipeline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    """Unified severity levels across all sources."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity string (case-insensitive)."""
        mapping = {
            "info": cls.INFO,
            "informational": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }
        return mapping.get(value.strip().lower(), cls.INFO)

    @property
    def numeric(self) -> int:
        """Return a numeric value for comparison."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __ge__(self, other: "Severity") -> bool:
        return self.numeric >= other.numeric

    def __gt__(self, other: "Severity") -> bool:
        return self.numeric > other.numeric

    def __le__(self, other: "Severity") -> bool:
        return self.numeric <= other.numeric

    def __lt__(self, other: "Severity") -> bool:
        return self.numeric < other.numeric


class FindingSource(Enum):
    """Identifies where the finding originated."""
    WAZUH = "wazuh"
    DEFECTDOJO = "defectdojo"


@dataclass
class Finding:
    """
    Unified finding that flows through the middleware pipeline.

    Both Wazuh alerts and DefectDojo findings are converted into this
    common schema by the respective source clients.
    """

    # --- Identity ---
    source: FindingSource
    source_id: str                          # Original ID from the source system
    title: str
    description: str

    # --- Severity ---
    severity: Severity = Severity.INFO      # Unified severity (set by mapper)
    raw_severity: str = ""                  # Original severity string/level from source

    # --- Context ---
    host: str = ""                          # Affected hostname or IP (UI fallback/routing)
    srcip: str = ""                         # Attacker origin IP
    dstip: str = ""                         # Destination IP
    dstport: str = ""                       # Destination port
    protocol: str = ""                      # Network protocol
    src_country: str = ""                   # Source country (from Wazuh GeoIP)
    dst_country: str = ""                   # Destination country (from Wazuh GeoIP)
    geolocation: dict[str, Any] = field(default_factory=dict)  # Full GeoLocation object
    endpoints: list[str] = field(default_factory=list) # DefectDojo explicit endpoints
    endpoint_url: str = ""                  # Explicit ZAP/Web URL target
    component: str = ""                     # Dependency or system component
    component_version: str = ""
    plugin_id: str = ""                     # Tenable/scanner isolated plugin boundary
    found_by: str = ""                      # Parent scanner tracking string
    cwe: str = ""                           # Contextual enum for ZAP injections
    param: str = ""                         # Targeted injection payload location
    routing_key: str = ""                   # Key for routing rules (e.g. devname)
    cvss: Optional[float] = None            # CVSS score if available
    cve_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # --- Rule info (Wazuh-specific) ---
    rule_id: Optional[str] = None
    rule_groups: list[str] = field(default_factory=list)

    # --- Raw data for debugging ---
    raw_data: dict[str, Any] = field(default_factory=dict, repr=False)

    # --- Enrichment (populated by enricher stage) ---
    enrichment: dict[str, Any] = field(default_factory=dict)

    # --- Pipeline metadata ---
    dedup_key: str = field(default="", init=False)
    dedup_hash: str = field(default="", init=False)
    filtered: bool = field(default=False, init=False)
    occurrence_count: int = field(default=1, init=False)
    dedup_reason: Optional[str] = field(default=None, init=False)
    redmine_issue_id: Optional[int] = field(default=None, init=False)
    issue_state: str = field(default="open", init=False)
    action: Optional[str] = field(default=None, init=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to a dictionary."""
        return {
            "source": self.source.value,
            "source_id": self.source_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "raw_severity": self.raw_severity,
            "host": self.host,
            "srcip": self.srcip,
            "dstip": self.dstip,
            "dstport": self.dstport,
            "protocol": self.protocol,
            "src_country": self.src_country,
            "dst_country": self.dst_country,
            "geolocation": self.geolocation,
            "endpoints": self.endpoints,
            "endpoint_url": self.endpoint_url,
            "component": self.component,
            "component_version": self.component_version,
            "plugin_id": self.plugin_id,
            "found_by": self.found_by,
            "cwe": self.cwe,
            "param": self.param,
            "routing_key": self.routing_key,
            "cvss": self.cvss,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "rule_groups": self.rule_groups,
            "raw_data": self.raw_data,
            "enrichment": self.enrichment,
            "dedup_key": self.dedup_key,
            "dedup_hash": self.dedup_hash,
            "filtered": self.filtered,
            "occurrence_count": self.occurrence_count,
            "dedup_reason": self.dedup_reason,
            "redmine_issue_id": self.redmine_issue_id,
            "issue_state": self.issue_state,
            "action": self.action,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Rehydrate a serialized finding from queue or storage payloads."""
        timestamp_raw = data.get("timestamp")
        if isinstance(timestamp_raw, datetime):
            timestamp = timestamp_raw
        elif timestamp_raw:
            try:
                timestamp = datetime.fromisoformat(str(timestamp_raw).replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        finding = cls(
            source=FindingSource(str(data.get("source", FindingSource.WAZUH.value)).strip().lower()),
            source_id=str(data.get("source_id", "")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            severity=Severity.from_string(str(data.get("severity", Severity.INFO.value))),
            raw_severity=str(data.get("raw_severity", "")),
            host=str(data.get("host", "")),
            srcip=str(data.get("srcip", "")),
            dstip=str(data.get("dstip", "")),
            dstport=str(data.get("dstport", "")),
            protocol=str(data.get("protocol", "")),
            src_country=str(data.get("src_country", "")),
            dst_country=str(data.get("dst_country", "")),
            geolocation=dict(data.get("geolocation", {}) or {}),
            endpoints=[str(item) for item in data.get("endpoints", []) or []],
            endpoint_url=str(data.get("endpoint_url", "")),
            component=str(data.get("component", "")),
            component_version=str(data.get("component_version", "")),
            plugin_id=str(data.get("plugin_id", "")),
            found_by=str(data.get("found_by", "")),
            cwe=str(data.get("cwe", "")),
            param=str(data.get("param", "")),
            routing_key=str(data.get("routing_key", "")),
            cvss=data.get("cvss"),
            cve_ids=[str(item) for item in data.get("cve_ids", []) or []],
            tags=[str(item) for item in data.get("tags", []) or []],
            timestamp=timestamp,
            rule_id=str(data.get("rule_id")) if data.get("rule_id") is not None else None,
            rule_groups=[str(item) for item in data.get("rule_groups", []) or []],
            raw_data=dict(data.get("raw_data", {}) or {}),
            enrichment=dict(data.get("enrichment", {}) or {}),
        )
        finding.dedup_key = str(data.get("dedup_key", "")) or finding.dedup_key
        finding.dedup_hash = str(data.get("dedup_hash", "")) or finding.dedup_hash
        finding.filtered = bool(data.get("filtered", False))
        finding.occurrence_count = int(data.get("occurrence_count", 1) or 1)
        finding.dedup_reason = data.get("dedup_reason")
        finding.redmine_issue_id = data.get("redmine_issue_id")
        finding.issue_state = str(data.get("issue_state", "open") or "open")
        finding.action = data.get("action")
        return finding

    def to_json(self) -> str:
        """Serialize finding to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def __repr__(self) -> str:
        return (
            f"Finding(source={self.source.value}, title='{self.title[:50]}', "
            f"severity={self.severity.value}, host='{self.host}', "
            f"hash={self.dedup_hash[:12]}...)"
        )
