"""
Filter pipeline stage.

Applies rule-based filtering to drop findings that don't meet
configured criteria (minimum severity, host patterns, exclusions).
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from src.config import FilterConfig
from src.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


class FilterStage:
    """
    Rule-based finding filter.

    Evaluates each finding against configured rules and marks it as
    filtered (dropped) if it doesn't pass all criteria.
    """

    def __init__(self, config: FilterConfig):
        self.config = config
        self.min_severity = Severity.from_string(config.min_severity)

        # Pre-compile regex patterns
        self._host_patterns: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in config.include_hosts
        ]
        self._title_exclude_patterns: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in config.exclude_title_patterns
        ]
        self._exclude_rule_ids: set[str] = set(config.exclude_rule_ids)

    def process(self, findings: list[Finding]) -> list[Finding]:
        """
        Filter a list of findings.

        Returns only findings that pass all filter rules.
        """
        before = len(findings)
        result = [f for f in findings if self._passes(f)]
        dropped = before - len(result)

        if dropped > 0:
            logger.info("Filter: kept %d, dropped %d findings", len(result), dropped)
        else:
            logger.debug("Filter: all %d findings passed", before)

        return result

    def _passes(self, finding: Finding) -> bool:
        """Check if a single finding passes all filter rules."""

        # 1. Minimum severity
        if finding.severity < self.min_severity:
            logger.debug(
                "Filter: dropped (severity %s < %s): %s",
                finding.severity.value,
                self.min_severity.value,
                finding.title[:60],
            )
            finding.dedup_reason = f"Filtered (severity < {self.min_severity.value})"
            return False

        # 2. Excluded rule IDs (Wazuh-specific)
        if finding.rule_id and finding.rule_id in self._exclude_rule_ids:
            logger.debug("Filter: dropped (excluded rule_id %s): %s", finding.rule_id, finding.title[:60])
            finding.dedup_reason = f"Filtered (rule_id {finding.rule_id})"
            return False

        # 3. Host include pattern (if configured, finding must match at least one)
        if self._host_patterns:
            if not any(p.search(finding.host) for p in self._host_patterns):
                logger.debug("Filter: dropped (host '%s' not in include list): %s", finding.host, finding.title[:60])
                finding.dedup_reason = "Filtered (host excluded)"
                return False

        # 4. Title exclude patterns
        if self._title_exclude_patterns:
            if any(p.search(finding.title) for p in self._title_exclude_patterns):
                logger.debug("Filter: dropped (title matches exclude pattern): %s", finding.title[:60])
                finding.dedup_reason = "Filtered (title excluded)"
                return False

        return True
