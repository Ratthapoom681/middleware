"""
Filter pipeline stage.

Applies rule-based filtering to drop findings that don't meet
configured criteria (minimum severity, host patterns, exclusions).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from src.config import FilterConfig, JSONFilterConditionConfig, JSONFilterRuleConfig
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
        self._default_action = config.default_action
        self._json_rules: list[JSONFilterRuleConfig] = [
            rule for rule in config.json_rules if rule.enabled
        ]

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

        # 5. Advanced JSON rules (raw source payload matching)
        matched_rule = self._match_json_rule(finding)
        if matched_rule is not None:
            finding.enrichment["matched_filter_rule"] = matched_rule.name or "(unnamed)"
            if matched_rule.action == "drop":
                logger.debug(
                    "Filter: dropped by JSON rule '%s': %s",
                    matched_rule.name or "(unnamed)",
                    finding.title[:60],
                )
                finding.dedup_reason = f"Filtered (json rule: {matched_rule.name or 'unnamed'})"
                return False
            return True

        if self._json_rules and self._default_action == "drop":
            logger.debug("Filter: dropped (no JSON rule matched): %s", finding.title[:60])
            finding.dedup_reason = "Filtered (no json rule matched)"
            return False

        return True

    def _match_json_rule(self, finding: Finding) -> JSONFilterRuleConfig | None:
        """Return the first advanced JSON rule that matches this finding."""
        for rule in self._json_rules:
            if rule.source not in {"any", finding.source.value}:
                continue
            if self._rule_matches(rule, finding.raw_data):
                return rule
        return None

    def _rule_matches(self, rule: JSONFilterRuleConfig, payload: dict[str, Any]) -> bool:
        """Evaluate one advanced rule against the raw finding payload."""
        if not rule.conditions:
            return False

        results = [self._condition_matches(condition, payload) for condition in rule.conditions]
        return all(results) if rule.match == "all" else any(results)

    def _condition_matches(self, condition: JSONFilterConditionConfig, payload: dict[str, Any]) -> bool:
        """Evaluate one condition against a nested raw payload path."""
        found, actual = self._resolve_path(payload, condition.path)
        operator = condition.op
        expected = condition.value

        if operator == "exists":
            should_exist = True if expected is None else self._coerce_bool(expected)
            return found if should_exist else not found
        if not found:
            return False

        if operator == "equals":
            return self._equals(actual, expected)
        if operator == "not_equals":
            return not self._equals(actual, expected)
        if operator == "contains":
            return self._contains(actual, expected)
        if operator == "regex":
            return self._regex(actual, expected)
        if operator == "in":
            return self._in_operator(actual, expected)
        if operator == "not_in":
            return not self._in_operator(actual, expected)
        if operator == "gt":
            return self._numeric_compare(actual, expected, "gt")
        if operator == "gte":
            return self._numeric_compare(actual, expected, "gte")
        if operator == "lt":
            return self._numeric_compare(actual, expected, "lt")
        if operator == "lte":
            return self._numeric_compare(actual, expected, "lte")

        logger.warning("Filter: unsupported JSON rule operator '%s'", operator)
        return False

    def _resolve_path(self, payload: Any, path: str) -> tuple[bool, Any]:
        """Resolve a dotted path inside a nested dict/list payload."""
        current = payload
        for part in path.split("."):
            token = part.strip()
            if not token:
                return False, None

            if isinstance(current, dict):
                if token not in current:
                    return False, None
                current = current[token]
                continue

            if isinstance(current, list):
                try:
                    index = int(token)
                except (TypeError, ValueError):
                    return False, None
                if index < 0 or index >= len(current):
                    return False, None
                current = current[index]
                continue

            return False, None

        return True, current

    def _equals(self, actual: Any, expected: Any) -> bool:
        """Loose equality that tolerates scanner strings and numeric strings."""
        if isinstance(actual, list):
            return any(self._equals(item, expected) for item in actual)
        if isinstance(expected, list):
            return any(self._equals(actual, item) for item in expected)
        return str(actual).strip().lower() == str(expected).strip().lower()

    def _contains(self, actual: Any, expected: Any) -> bool:
        """Containment for strings and arrays."""
        if isinstance(actual, list):
            return any(self._equals(item, expected) for item in actual)
        return str(expected).strip().lower() in str(actual).strip().lower()

    def _regex(self, actual: Any, expected: Any) -> bool:
        """Regex matching against a scalar or list payload value."""
        pattern = re.compile(str(expected), re.IGNORECASE)
        if isinstance(actual, list):
            return any(pattern.search(str(item)) for item in actual)
        return bool(pattern.search(str(actual)))

    def _in_operator(self, actual: Any, expected: Any) -> bool:
        """Membership check where the expected side is the configured list."""
        candidates = expected if isinstance(expected, list) else [expected]
        if isinstance(actual, list):
            return any(self._equals(item, candidate) for item in actual for candidate in candidates)
        return any(self._equals(actual, candidate) for candidate in candidates)

    def _numeric_compare(self, actual: Any, expected: Any, operator: str) -> bool:
        """Compare numeric strings safely."""
        try:
            actual_value = float(actual)
            expected_value = float(expected)
        except (TypeError, ValueError):
            return False

        if operator == "gt":
            return actual_value > expected_value
        if operator == "gte":
            return actual_value >= expected_value
        if operator == "lt":
            return actual_value < expected_value
        return actual_value <= expected_value

    def _coerce_bool(self, value: Any) -> bool:
        """Interpret permissive boolean-like config values."""
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
