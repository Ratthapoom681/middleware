"""
Unified Finding data model.

All security findings from Wazuh and DefectDojo are normalized into this
common schema before being processed by the middleware pipeline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
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
    host: str = ""                          # Affected hostname or IP
    cvss: Optional[float] = None           # CVSS score if available
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
    dedup_hash: str = field(default="", init=False)
    filtered: bool = field(default=False, init=False)
    occurrence_count: int = field(default=1, init=False)
    dedup_reason: Optional[str] = field(default=None, init=False)
    redmine_issue_id: Optional[int] = field(default=None, init=False)
    action: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        """Compute dedup hash after initialization."""
        self.dedup_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """
        Generate a SHA-256 deduplication hash based on key identity fields.

        The hash is based on: source, title, host, and sorted CVE IDs.
        This means the same vulnerability on the same host from the same
        source will always produce the same hash.
        """
        key_parts = [
            self.source.value,
            self.title.strip().lower(),
            self.host.strip().lower(),
            ",".join(sorted(self.cve_ids)),
        ]
        if self.rule_id:
            key_parts.append(self.rule_id)

        raw = "|".join(key_parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

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
            "cvss": self.cvss,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "rule_groups": self.rule_groups,
            "enrichment": self.enrichment,
            "dedup_hash": self.dedup_hash,
        }

    def to_json(self) -> str:
        """Serialize finding to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def __repr__(self) -> str:
        return (
            f"Finding(source={self.source.value}, title='{self.title[:50]}', "
            f"severity={self.severity.value}, host='{self.host}', "
            f"hash={self.dedup_hash[:12]}...)"
        )
