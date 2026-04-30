"""
Detection Rule Engine.

Evaluates security events against configurable detection rules to identify
behavioral patterns such as brute force attacks, port scans, abnormal
network connections, and impossible travel scenarios.

Each rule maintains its own sliding-window state for temporal correlation.
Detection alerts are persisted to a local SQLite database and surfaced
via the REST API and Web UI.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from src.config import DetectionConfig, DetectionRuleConfig
from src.models.finding import Finding, Severity

logger = logging.getLogger("detection")


# ── Data Models ───────────────────────────────────────────────────────────


@dataclass
class DetectionAlert:
    """A detection alert generated when a rule triggers."""
    id: str
    rule_name: str
    rule_type: str
    severity: str
    description: str
    evidence: dict[str, Any]
    source_events: list[dict[str, Any]]
    triggered_at: str
    acknowledged: bool = False
    resolved: bool = False
    create_ticket: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "source_events": self.source_events,
            "triggered_at": self.triggered_at,
            "acknowledged": self.acknowledged,
            "resolved": self.resolved,
            "create_ticket": self.create_ticket,
        }


# ── Sliding Window State ─────────────────────────────────────────────────


class SlidingWindowState:
    """
    Maintains a per-key sliding window of events for temporal rules.

    Events are stored as (timestamp, event_data) tuples and automatically
    expired based on the window duration.
    """

    def __init__(self, window_seconds: int, max_entries: int = 10000):
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        # key -> list of (timestamp_epoch, event_data)
        self._windows: dict[str, list[tuple[float, dict[str, Any]]]] = defaultdict(list)
        self._total_entries = 0

    def add_event(self, key: str, timestamp: float, event_data: dict[str, Any]) -> None:
        """Add an event to the window for the given key."""
        self._expire(key, timestamp)
        self._windows[key].append((timestamp, event_data))
        self._total_entries += 1

        # Evict oldest entries globally if over capacity
        if self._total_entries > self.max_entries:
            self._evict_oldest()

    def get_events(self, key: str, current_time: float | None = None) -> list[tuple[float, dict[str, Any]]]:
        """Get all events in the current window for the given key."""
        now = current_time or time.time()
        self._expire(key, now)
        return list(self._windows.get(key, []))

    def count(self, key: str, current_time: float | None = None) -> int:
        """Count events in the current window for the given key."""
        return len(self.get_events(key, current_time))

    def distinct_values(self, key: str, value_extractor: str, current_time: float | None = None) -> set[str]:
        """Count distinct values of a field across events in the window."""
        events = self.get_events(key, current_time)
        values = set()
        for _, event_data in events:
            val = event_data.get(value_extractor, "")
            if val:
                values.add(str(val))
        return values

    def _expire(self, key: str, current_time: float) -> None:
        """Remove events outside the window."""
        cutoff = current_time - self.window_seconds
        if key in self._windows:
            before = len(self._windows[key])
            self._windows[key] = [(ts, data) for ts, data in self._windows[key] if ts > cutoff]
            self._total_entries -= (before - len(self._windows[key]))
            if not self._windows[key]:
                del self._windows[key]

    def _evict_oldest(self) -> None:
        """Evict the oldest entries globally to stay under max_entries."""
        # Find and remove the oldest single entry across all keys
        oldest_key = None
        oldest_ts = float("inf")
        for key, events in self._windows.items():
            if events and events[0][0] < oldest_ts:
                oldest_ts = events[0][0]
                oldest_key = key
        if oldest_key and self._windows.get(oldest_key):
            self._windows[oldest_key].pop(0)
            self._total_entries -= 1
            if not self._windows[oldest_key]:
                del self._windows[oldest_key]

    def clear(self) -> None:
        """Clear all state."""
        self._windows.clear()
        self._total_entries = 0


# ── Cooldown Tracker ─────────────────────────────────────────────────────


class CooldownTracker:
    """Tracks cooldown periods to suppress duplicate alerts."""

    def __init__(self):
        # (rule_name, cooldown_key) -> last_trigger_epoch
        self._cooldowns: dict[tuple[str, str], float] = {}

    def is_cooled_down(self, rule_name: str, key: str, cooldown_seconds: int) -> bool:
        """Check if this rule+key combination is still in cooldown."""
        cache_key = (rule_name, key)
        last_trigger = self._cooldowns.get(cache_key, 0.0)
        return (time.time() - last_trigger) < cooldown_seconds

    def record_trigger(self, rule_name: str, key: str) -> None:
        """Record that this rule+key was triggered now."""
        self._cooldowns[(rule_name, key)] = time.time()

    def remaining_seconds(self, rule_name: str, key: str, cooldown_seconds: int) -> float:
        """Get remaining cooldown seconds."""
        cache_key = (rule_name, key)
        last_trigger = self._cooldowns.get(cache_key, 0.0)
        remaining = cooldown_seconds - (time.time() - last_trigger)
        return max(0.0, remaining)

    def cleanup(self, max_age_seconds: int = 3600) -> None:
        """Remove expired cooldown entries."""
        cutoff = time.time() - max_age_seconds
        expired = [k for k, v in self._cooldowns.items() if v < cutoff]
        for k in expired:
            del self._cooldowns[k]


# ── Detection Engine ─────────────────────────────────────────────────────


class DetectionEngine:
    """
    Core detection rule engine.

    Evaluates incoming security events against configured detection rules
    and generates alerts when patterns are detected.
    """

    def __init__(self, config: DetectionConfig):
        self.config = config
        self.enabled = config.enabled
        self._rules = [r for r in config.rules if r.enabled] if config.enabled else []
        self._cooldowns = CooldownTracker()
        self._alert_store: Any = None  # Set externally by pipeline

        # Initialize per-rule state
        self._rule_states: dict[str, SlidingWindowState] = {}
        for rule in self._rules:
            window = rule.parameters.get("window_seconds", 60)
            self._rule_states[rule.name] = SlidingWindowState(
                window_seconds=window,
                max_entries=config.max_state_entries,
            )

        if self._rules:
            logger.info(
                "Detection engine initialized with %d active rule(s): %s",
                len(self._rules),
                ", ".join(r.name for r in self._rules),
            )
        elif config.enabled:
            logger.info("Detection engine enabled but no active rules configured")

    def set_alert_store(self, store: Any) -> None:
        """Set the alert persistence store."""
        self._alert_store = store

    def evaluate(self, findings: list[Finding]) -> list[DetectionAlert]:
        """
        Evaluate a batch of findings against all active detection rules.

        Returns a list of detection alerts that were triggered.
        """
        if not self.enabled or not self._rules:
            return []

        all_alerts: list[DetectionAlert] = []

        for finding in findings:
            for rule in self._rules:
                try:
                    alerts = self._evaluate_rule(rule, finding)
                    all_alerts.extend(alerts)
                except Exception as exc:
                    logger.error(
                        "Detection: rule '%s' evaluation failed for finding %s: %s",
                        rule.name, finding.source_id, exc,
                    )

        if all_alerts:
            logger.warning(
                "Detection: %d alert(s) triggered from %d finding(s)",
                len(all_alerts), len(findings),
            )

        # Persist alerts
        if all_alerts and self._alert_store:
            for alert in all_alerts:
                try:
                    self._alert_store.save_alert(alert)
                except Exception as exc:
                    logger.error("Detection: failed to persist alert %s: %s", alert.id, exc)

        # Periodic cooldown cleanup
        self._cooldowns.cleanup()

        return all_alerts

    def _evaluate_rule(self, rule: DetectionRuleConfig, finding: Finding) -> list[DetectionAlert]:
        """Evaluate a single rule against a single finding."""
        if rule.type == "brute_force":
            return self._eval_brute_force(rule, finding)
        elif rule.type == "abnormal_port":
            return self._eval_abnormal_port(rule, finding)
        elif rule.type == "impossible_travel":
            return self._eval_impossible_travel(rule, finding)
        elif rule.type == "port_scan":
            return self._eval_port_scan(rule, finding)
        else:
            logger.debug("Detection: skipping unknown rule type '%s'", rule.type)
            return []

    # ── Brute Force ──────────────────────────────────────────────────

    def _eval_brute_force(self, rule: DetectionRuleConfig, finding: Finding) -> list[DetectionAlert]:
        """
        Detect brute force login attempts.
        Logic: More than N failed login attempts within a time window from same source IP.
        """
        params = rule.parameters
        threshold = params.get("threshold", 5)
        event_type_field = params.get("event_type_field", "data.status")
        event_type_value = params.get("event_type_value", "failed")
        group_by = params.get("group_by", "srcip")

        # Check if this event matches the event type filter
        event_value = self._resolve_field(finding, event_type_field)
        if not event_value or str(event_value).lower() != str(event_type_value).lower():
            logger.debug(
                "Detection: rule '%s' — event type mismatch (got '%s', want '%s')",
                rule.name, event_value, event_type_value,
            )
            return []

        # Get the grouping key
        group_key = self._get_group_key(finding, group_by)
        if not group_key:
            logger.debug("Detection: rule '%s' — missing group_by field '%s'", rule.name, group_by)
            return []

        # Add event to sliding window
        state = self._rule_states[rule.name]
        event_ts = finding.timestamp.timestamp()
        state.add_event(group_key, event_ts, {
            "srcip": finding.srcip,
            "host": finding.host,
            "title": finding.title,
            "timestamp": finding.timestamp.isoformat(),
            "user": self._resolve_field(finding, "data.dstuser") or self._resolve_field(finding, "data.srcuser") or "",
        })

        # Check threshold
        count = state.count(group_key, event_ts)
        logger.debug(
            "Detection: rule '%s' state for key '%s': %d events in window",
            rule.name, group_key, count,
        )

        if count > threshold:
            # Check cooldown
            if self._cooldowns.is_cooled_down(rule.name, group_key, rule.cooldown_seconds):
                remaining = self._cooldowns.remaining_seconds(rule.name, group_key, rule.cooldown_seconds)
                logger.debug(
                    "Detection: rule '%s' suppressed (cooldown active, %.0fs remaining)",
                    rule.name, remaining,
                )
                return []

            self._cooldowns.record_trigger(rule.name, group_key)
            events_in_window = state.get_events(group_key, event_ts)

            alert = DetectionAlert(
                id=str(uuid4()),
                rule_name=rule.name,
                rule_type=rule.type,
                severity=rule.severity,
                description=f"Brute force detected: {count} failed login attempts from {group_key} within {params.get('window_seconds', 60)}s (threshold: {threshold})",
                evidence={
                    "source_ip": group_key,
                    "attempt_count": count,
                    "threshold": threshold,
                    "window_seconds": params.get("window_seconds", 60),
                },
                source_events=[ev for _, ev in events_in_window[-10:]],  # Last 10
                triggered_at=datetime.now(timezone.utc).isoformat(),
                create_ticket=rule.create_ticket,
            )
            logger.warning("Detection: ALERT — rule '%s' triggered: %s", rule.name, alert.description)
            return [alert]

        return []

    # ── Abnormal Port ────────────────────────────────────────────────

    def _eval_abnormal_port(self, rule: DetectionRuleConfig, finding: Finding) -> list[DetectionAlert]:
        """
        Detect connections to unusual/suspicious ports.
        Logic: Stateless — check if dstport is in the suspicious port set.
        """
        params = rule.parameters
        suspicious_ports = set(str(p) for p in params.get("suspicious_ports", [4444, 1337, 31337, 6666, 6667]))
        port_field = params.get("port_field", "dstport")

        # Get port value
        port_value = self._resolve_field(finding, port_field)
        if not port_value:
            return []

        port_str = str(port_value).strip()
        if port_str not in suspicious_ports:
            return []

        # Build key for cooldown
        cooldown_key = f"{finding.srcip}:{port_str}"
        if self._cooldowns.is_cooled_down(rule.name, cooldown_key, rule.cooldown_seconds):
            remaining = self._cooldowns.remaining_seconds(rule.name, cooldown_key, rule.cooldown_seconds)
            logger.debug(
                "Detection: rule '%s' suppressed (cooldown active, %.0fs remaining)",
                rule.name, remaining,
            )
            return []

        self._cooldowns.record_trigger(rule.name, cooldown_key)

        dstip = self._resolve_field(finding, "dstip") or finding.dstip
        protocol = self._resolve_field(finding, "protocol") or finding.protocol

        alert = DetectionAlert(
            id=str(uuid4()),
            rule_name=rule.name,
            rule_type=rule.type,
            severity=rule.severity,
            description=f"Abnormal network connection detected: {finding.srcip} → port {port_str} (suspicious port list match)",
            evidence={
                "srcip": finding.srcip,
                "dstip": str(dstip),
                "dstport": port_str,
                "protocol": str(protocol),
                "src_country": finding.src_country,
                "dst_country": finding.dst_country,
            },
            source_events=[{
                "srcip": finding.srcip,
                "dstip": str(dstip),
                "dstport": port_str,
                "title": finding.title,
                "timestamp": finding.timestamp.isoformat(),
                "host": finding.host,
            }],
            triggered_at=datetime.now(timezone.utc).isoformat(),
            create_ticket=rule.create_ticket,
        )
        logger.warning("Detection: ALERT — rule '%s' triggered: %s", rule.name, alert.description)
        return [alert]

    # ── Impossible Travel ────────────────────────────────────────────

    def _eval_impossible_travel(self, rule: DetectionRuleConfig, finding: Finding) -> list[DetectionAlert]:
        """
        Detect impossible travel scenarios.
        Logic: Same user logs in from different countries within a short time window.
        Uses Wazuh-native srccountry/dstcountry/GeoLocation data.
        """
        params = rule.parameters
        max_travel_seconds = params.get("max_travel_seconds", 3600)
        group_by = params.get("group_by", "user")

        # Get user identifier
        user = self._get_group_key(finding, group_by)
        if not user:
            # Try common user fields in raw_data
            user = (
                self._resolve_field(finding, "data.dstuser")
                or self._resolve_field(finding, "data.srcuser")
                or self._resolve_field(finding, "data.user")
            )
        if not user:
            return []

        # Get country from the finding's geo data
        country = finding.src_country
        if not country:
            country = self._resolve_field(finding, "data.srccountry") or ""
        if not country:
            # Try GeoLocation
            geo = finding.geolocation or {}
            country = geo.get("country_name", "")
        if not country:
            logger.debug(
                "Detection: rule '%s' — no country data for user '%s', srcip '%s'",
                rule.name, user, finding.srcip,
            )
            return []

        # Add to sliding window
        state = self._rule_states[rule.name]
        event_ts = finding.timestamp.timestamp()
        state.add_event(user, event_ts, {
            "country": country,
            "srcip": finding.srcip,
            "timestamp": finding.timestamp.isoformat(),
            "host": finding.host,
        })

        # Check for travel — look at all events in window
        events_in_window = state.get_events(user, event_ts)
        countries_seen: dict[str, tuple[float, str]] = {}  # country -> (timestamp, srcip)

        for ev_ts, ev_data in events_in_window:
            ev_country = ev_data.get("country", "")
            if ev_country:
                if ev_country not in countries_seen or ev_ts > countries_seen[ev_country][0]:
                    countries_seen[ev_country] = (ev_ts, ev_data.get("srcip", ""))

        if len(countries_seen) < 2:
            return []

        # Find the most recent pair with different countries within threshold
        sorted_entries = sorted(countries_seen.items(), key=lambda x: x[1][0], reverse=True)
        for i in range(len(sorted_entries)):
            for j in range(i + 1, len(sorted_entries)):
                c1, (ts1, ip1) = sorted_entries[i]
                c2, (ts2, ip2) = sorted_entries[j]
                time_diff = abs(ts1 - ts2)

                if time_diff < max_travel_seconds and c1 != c2:
                    cooldown_key = f"{user}:{c1}:{c2}"
                    if self._cooldowns.is_cooled_down(rule.name, cooldown_key, rule.cooldown_seconds):
                        continue

                    self._cooldowns.record_trigger(rule.name, cooldown_key)

                    alert = DetectionAlert(
                        id=str(uuid4()),
                        rule_name=rule.name,
                        rule_type=rule.type,
                        severity=rule.severity,
                        description=(
                            f"Impossible travel detected: user '{user}' logged in from "
                            f"'{c1}' ({ip1}) and '{c2}' ({ip2}) within {time_diff:.0f}s "
                            f"(threshold: {max_travel_seconds}s)"
                        ),
                        evidence={
                            "user": user,
                            "country_1": c1,
                            "ip_1": ip1,
                            "country_2": c2,
                            "ip_2": ip2,
                            "time_diff_seconds": round(time_diff),
                            "max_travel_seconds": max_travel_seconds,
                        },
                        source_events=[ev for _, ev in events_in_window[-10:]],
                        triggered_at=datetime.now(timezone.utc).isoformat(),
                        create_ticket=rule.create_ticket,
                    )
                    logger.warning("Detection: ALERT — rule '%s' triggered: %s", rule.name, alert.description)
                    return [alert]

        return []

    # ── Port Scan ────────────────────────────────────────────────────

    def _eval_port_scan(self, rule: DetectionRuleConfig, finding: Finding) -> list[DetectionAlert]:
        """
        Detect port scanning activity.
        Logic: Multiple connections to different ports from the same source IP
        within a short time window.
        """
        params = rule.parameters
        threshold = params.get("threshold", 15)
        group_by = params.get("group_by", "srcip")
        port_field = params.get("port_field", "dstport")

        # Get group key and port value
        group_key = self._get_group_key(finding, group_by)
        if not group_key:
            return []

        port_value = self._resolve_field(finding, port_field)
        if not port_value:
            return []

        # Add event
        state = self._rule_states[rule.name]
        event_ts = finding.timestamp.timestamp()
        state.add_event(group_key, event_ts, {
            "dstport": str(port_value),
            "dstip": finding.dstip or self._resolve_field(finding, "dstip") or "",
            "srcip": finding.srcip,
            "timestamp": finding.timestamp.isoformat(),
            "host": finding.host,
        })

        # Count distinct ports
        distinct_ports = state.distinct_values(group_key, "dstport", event_ts)
        logger.debug(
            "Detection: rule '%s' state for key '%s': %d distinct ports in window",
            rule.name, group_key, len(distinct_ports),
        )

        if len(distinct_ports) > threshold:
            if self._cooldowns.is_cooled_down(rule.name, group_key, rule.cooldown_seconds):
                remaining = self._cooldowns.remaining_seconds(rule.name, group_key, rule.cooldown_seconds)
                logger.debug(
                    "Detection: rule '%s' suppressed (cooldown active, %.0fs remaining)",
                    rule.name, remaining,
                )
                return []

            self._cooldowns.record_trigger(rule.name, group_key)
            events_in_window = state.get_events(group_key, event_ts)

            alert = DetectionAlert(
                id=str(uuid4()),
                rule_name=rule.name,
                rule_type=rule.type,
                severity=rule.severity,
                description=(
                    f"Port scan detected: {group_key} connected to {len(distinct_ports)} "
                    f"distinct ports within {params.get('window_seconds', 60)}s "
                    f"(threshold: {threshold})"
                ),
                evidence={
                    "source_ip": group_key,
                    "distinct_port_count": len(distinct_ports),
                    "ports_sample": sorted(list(distinct_ports))[:20],
                    "threshold": threshold,
                    "window_seconds": params.get("window_seconds", 60),
                },
                source_events=[ev for _, ev in events_in_window[-10:]],
                triggered_at=datetime.now(timezone.utc).isoformat(),
                create_ticket=rule.create_ticket,
            )
            logger.warning("Detection: ALERT — rule '%s' triggered: %s", rule.name, alert.description)
            return [alert]

        return []

    # ── Field Resolution Helpers ─────────────────────────────────────

    def _resolve_field(self, finding: Finding, field_path: str) -> Any:
        """
        Resolve a field path against a Finding object.

        Supports:
        - Direct Finding attributes: "srcip", "host", "dstport"
        - Nested raw_data paths: "data.srcip", "rule.level", "data.dstport"
        """
        # First try direct Finding attributes
        parts = field_path.split(".")
        if len(parts) == 1:
            if hasattr(finding, field_path):
                return getattr(finding, field_path, None)

        # Then try raw_data nested path
        current: Any = finding.raw_data
        for part in parts:
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    def _get_group_key(self, finding: Finding, group_by: str) -> str:
        """Get a grouping key from a finding for sliding window lookups."""
        # Direct Finding fields
        if group_by == "srcip":
            return finding.srcip or ""
        elif group_by == "dstip":
            return finding.dstip or ""
        elif group_by == "host":
            return finding.host or ""
        elif group_by == "user":
            return (
                self._resolve_field(finding, "data.dstuser")
                or self._resolve_field(finding, "data.srcuser")
                or self._resolve_field(finding, "data.user")
                or ""
            )

        # Fallback to resolve_field
        value = self._resolve_field(finding, group_by)
        return str(value) if value else ""

    def reload_rules(self, config: DetectionConfig) -> None:
        """Reload rules from a new config (hot reload support)."""
        self.config = config
        self.enabled = config.enabled
        old_rules = {r.name for r in self._rules}
        self._rules = [r for r in config.rules if r.enabled] if config.enabled else []
        new_rules = {r.name for r in self._rules}

        # Initialize state for new rules
        for rule in self._rules:
            if rule.name not in self._rule_states:
                window = rule.parameters.get("window_seconds", 60)
                self._rule_states[rule.name] = SlidingWindowState(
                    window_seconds=window,
                    max_entries=config.max_state_entries,
                )

        # Clean up state for removed rules
        removed = old_rules - new_rules
        for name in removed:
            self._rule_states.pop(name, None)

        logger.info(
            "Detection engine reloaded: %d active rule(s) (added=%d, removed=%d)",
            len(self._rules),
            len(new_rules - old_rules),
            len(removed),
        )
