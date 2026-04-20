"""
DefectDojo API client.

Connects to DefectDojo's REST API v2, normalizes findings into the shared
Finding model, and maintains a persisted incremental checkpoint for safe
high-volume polling.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException

from src.config import DefectDojoConfig
from src.models.finding import Finding, FindingSource, Severity
from src.pipeline.identity import hydrate_identity

logger = logging.getLogger(__name__)

# DefectDojo severity -> unified severity mapping
DD_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

_PLUGIN_TAG_RE = re.compile(
    r"(?:plugin(?:[_\s-]?id)?|nessus(?:[_\s-]?plugin)?|tenable(?:[_\s-]?plugin)?)[:=\s#-]*([A-Za-z0-9._:-]+)",
    re.IGNORECASE,
)
_UI_API_SUFFIX_RE = re.compile(r"/api(?:/v\d+)?/?$", re.IGNORECASE)


class DefectDojoAPIError(RuntimeError):
    """Raised when DefectDojo returns an unexpected API response."""


def _clean_text(value: Any) -> str:
    """Normalize arbitrary scalar values into stripped strings."""
    if value is None:
        return ""
    return str(value).strip()


def _clean_host(value: Any) -> str:
    """Normalize hostnames/IPs for identity generation and routing."""
    text = _clean_text(value).lower().strip("/")
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def _clean_path(value: Any) -> str:
    """Normalize endpoint paths without manufacturing a trailing slash."""
    text = _clean_text(value)
    if not text or text == "/":
        return ""
    return text if text.startswith("/") else f"/{text}"


def _clean_protocol(value: Any) -> str:
    """Normalize URL schemes into lowercase tokens."""
    return _clean_text(value).lower().rstrip(":/")


def _clean_port(value: Any) -> str:
    """Normalize a numeric TCP port into a string."""
    text = _clean_text(value)
    if not text:
        return ""
    try:
        return str(int(text))
    except (TypeError, ValueError):
        return ""


def _normalize_identifier(value: Any) -> str:
    """Normalize scanner/plugin identifiers without accepting noisy strings."""
    if isinstance(value, (list, tuple, set, dict)):
        return ""
    text = _clean_text(value)
    if not text:
        return ""
    return text


class DefectDojoClient:
    """Client for the DefectDojo REST API v2."""

    def __init__(self, config: DefectDojoConfig, checkpoint_store: Any | None = None):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.cursor_path = Path(config.cursor_path)
        self._checkpoint_store = checkpoint_store
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers.update({
            "Authorization": config.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._pending_checkpoint: dict[str, Any] | None = None

    def fetch_findings(self, limit: int = 100) -> list[Finding]:
        """
        Fetch active findings from DefectDojo.

        The persisted checkpoint is used as the primary incremental boundary.
        `fetch_limit` acts as a processing cap and the checkpoint only advances
        after downstream processing explicitly commits it.
        """
        findings: list[Finding] = []
        url = f"{self.base_url}/findings/"
        self._pending_checkpoint = None

        processing_cap = self.config.fetch_limit if self.config.fetch_limit > 0 else None
        page_limit = min(limit, processing_cap) if processing_cap else limit
        page_limit = max(1, page_limit)
        params, checkpoint_state = self._build_findings_query_params(
            limit=page_limit,
            ordering="last_status_update,id",
        )

        next_checkpoint_state = checkpoint_state
        try:
            while True:
                response = self.session.get(url, params=params, timeout=60)
                data = self._parse_json_response(response, f"findings page offset={params['offset']}")

                results = data.get("results", [])
                logger.info(
                    "DefectDojo: fetched %d findings (offset %d)",
                    len(results),
                    params["offset"],
                )

                reached_processing_cap = False
                for dd_finding in results:
                    if checkpoint_state and not self._is_after_cursor(dd_finding, checkpoint_state):
                        continue

                    finding = self._finding_to_model(dd_finding)
                    if not finding:
                        continue

                    findings.append(finding)
                    checkpoint_candidate = self._make_cursor_state(dd_finding)
                    if checkpoint_candidate:
                        next_checkpoint_state = checkpoint_candidate

                    if processing_cap and len(findings) >= processing_cap:
                        reached_processing_cap = True
                        break

                if reached_processing_cap:
                    break
                if data.get("next"):
                    params["offset"] += page_limit
                else:
                    break

        except (RequestException, DefectDojoAPIError) as exc:
            logger.error("DefectDojo: failed to fetch findings: %s", exc)

        if next_checkpoint_state and findings:
            self._pending_checkpoint = next_checkpoint_state

        logger.info("DefectDojo: total findings fetched: %d", len(findings))
        return findings

    def fetch_scope_data(self) -> dict[str, list[dict[str, Any]]]:
        """Fetch products, engagements, and tests for UI scoping helpers."""
        products = self._fetch_collection("/products/")
        engagements = self._fetch_collection("/engagements/")
        tests = self._fetch_collection("/tests/")

        normalized_products = [
            {
                "id": int(item["id"]),
                "name": item.get("name") or f"Product {item['id']}",
            }
            for item in products
            if item.get("id") is not None
        ]
        normalized_engagements = [
            {
                "id": int(item["id"]),
                "name": item.get("name") or item.get("title") or f"Engagement {item['id']}",
                "product_id": self._extract_related_id(item, "product"),
            }
            for item in engagements
            if item.get("id") is not None
        ]
        normalized_tests = [
            {
                "id": int(item["id"]),
                "name": item.get("title") or item.get("name") or f"Test {item['id']}",
                "engagement_id": self._extract_related_id(item, "engagement"),
                "product_id": self._extract_related_id(item, "product"),
            }
            for item in tests
            if item.get("id") is not None
        ]

        return {
            "products": normalized_products,
            "engagements": normalized_engagements,
            "tests": normalized_tests,
        }

    def get_finding_count_summary(self) -> dict[str, Any]:
        """
        Return a read-only preview of how many findings match the current filters.

        `matching_count` ignores the persisted checkpoint so the UI can show the
        overall size of the current scope. `pending_count` includes the
        checkpoint boundary so operators can see how many findings the next sync
        could actually process.
        """
        matching_count = self._fetch_findings_count(include_checkpoint=False)
        checkpoint_state = self._load_cursor()
        checkpoint_applied = checkpoint_state is not None
        pending_count = (
            self._fetch_findings_count(include_checkpoint=True)
            if checkpoint_applied
            else matching_count
        )
        processing_cap = self.config.fetch_limit if self.config.fetch_limit > 0 else None
        estimated_processed_count = (
            min(pending_count, processing_cap)
            if processing_cap is not None
            else pending_count
        )

        return {
            "matching_count": matching_count,
            "pending_count": pending_count,
            "checkpoint_applied": checkpoint_applied,
            "processing_cap": processing_cap,
            "estimated_processed_count": estimated_processed_count,
        }

    def checkpoint_enabled(self) -> bool:
        """Return True when incremental checkpoint persistence is configured."""
        return bool(self._checkpoint_store or _clean_text(self.config.cursor_path))

    def get_pending_checkpoint(self) -> dict[str, Any] | None:
        """Expose the most recent fetched checkpoint boundary without persisting it."""
        if not self._pending_checkpoint:
            return None
        return dict(self._pending_checkpoint)

    def commit_pending_checkpoint(self) -> None:
        """Persist the fetched checkpoint after downstream processing succeeds."""
        if not self._pending_checkpoint:
            return
        self._save_cursor(self._pending_checkpoint)
        self._pending_checkpoint = None

    def discard_pending_checkpoint(self) -> None:
        """Drop the fetched checkpoint when downstream processing fails."""
        self._pending_checkpoint = None

    def _build_findings_query_params(
        self,
        *,
        limit: int,
        offset: int = 0,
        include_checkpoint: bool = True,
        ordering: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build the canonical findings query params used by fetch and preview flows."""
        checkpoint_state = self._load_cursor() if include_checkpoint else None
        params: dict[str, Any] = {
            "active": "true" if self.config.active else "false",
            "verified": "true" if self.config.verified else "false",
            "duplicate": "false",
            "limit": max(1, limit),
            "offset": max(0, offset),
        }

        if ordering:
            params["ordering"] = ordering

        if self.config.product_ids:
            params["test__engagement__product"] = ",".join(map(str, self.config.product_ids))
        if self.config.engagement_ids:
            params["test__engagement"] = ",".join(map(str, self.config.engagement_ids))
        if self.config.test_ids:
            params["test"] = ",".join(map(str, self.config.test_ids))

        if checkpoint_state:
            params["last_status_update"] = checkpoint_state["last_status_update"]
        elif self.config.updated_since_minutes > 0:
            past_time = datetime.utcnow() - timedelta(minutes=self.config.updated_since_minutes)
            params["last_status_update"] = past_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        if self.config.severity_filter:
            params["severity"] = ",".join(self.config.severity_filter)

        return params, checkpoint_state

    def _fetch_findings_count(self, *, include_checkpoint: bool) -> int:
        """Fetch the DefectDojo `count` for the current filter set."""
        params, _ = self._build_findings_query_params(limit=1, include_checkpoint=include_checkpoint)
        response = self.session.get(f"{self.base_url}/findings/", params=params, timeout=30)
        data = self._parse_json_response(response, "/findings/ count preview")

        try:
            return max(0, int(data.get("count", 0) or 0))
        except (TypeError, ValueError):
            raise DefectDojoAPIError(
                "DefectDojo returned an invalid count value for /findings/ count preview"
            )

    def _fetch_collection(self, path: str) -> list[dict[str, Any]]:
        """Fetch a paginated DefectDojo collection endpoint."""
        items: list[dict[str, Any]] = []
        url = f"{self.base_url}{path}"
        params: dict[str, Any] = {"limit": 200, "offset": 0}

        while True:
            response = self.session.get(url, params=params, timeout=30)
            data = self._parse_json_response(response, path)
            results = data.get("results", [])
            items.extend(result for result in results if isinstance(result, dict))

            if not data.get("next"):
                break
            params["offset"] += params["limit"]

        return items

    def _parse_json_response(self, response: requests.Response, context: str) -> dict[str, Any]:
        """Validate that an upstream response is JSON and return the parsed body."""
        try:
            response.raise_for_status()
        except RequestException as exc:
            raise DefectDojoAPIError(
                f"DefectDojo request failed for {context}: HTTP {response.status_code}"
            ) from exc

        content_type = response.headers.get("Content-Type", "")
        body_preview = response.text[:500].strip()
        if "application/json" not in content_type.lower():
            raise DefectDojoAPIError(
                "DefectDojo returned non-JSON content for "
                f"{context} ({content_type or 'unknown content type'}). "
                "This usually means the Base URL points to the UI/login page, "
                "the API key is invalid, or a proxy/WAF returned an HTML error page. "
                f"Response preview: {body_preview or '<empty>'}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise DefectDojoAPIError(
                "DefectDojo returned malformed JSON for "
                f"{context}. Response preview: {body_preview or '<empty>'}"
            ) from exc

        if not isinstance(data, dict):
            raise DefectDojoAPIError(
                f"DefectDojo returned an unexpected JSON shape for {context}: {type(data).__name__}"
            )
        return data

    def _extract_related_id(self, item: dict[str, Any], field_name: str) -> int | None:
        """Extract a related object ID from either an integer or expanded object."""
        raw_value = item.get(field_name)
        if isinstance(raw_value, dict):
            raw_value = raw_value.get("id")
        if raw_value is None and field_name == "product":
            engagement = item.get("engagement")
            if isinstance(engagement, dict):
                product_value = engagement.get("product")
                if isinstance(product_value, dict):
                    raw_value = product_value.get("id")
                else:
                    raw_value = product_value
        if raw_value in ("", None):
            return None
        try:
            return int(raw_value)
        except (TypeError, ValueError):
            return None

    def _cursor_signature(self) -> str:
        """Build a signature so stale checkpoints are discarded after config changes."""
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
        """Load the persisted checkpoint for incremental DefectDojo polling."""
        if self._checkpoint_store:
            data = self._checkpoint_store.load_checkpoint(
                self._checkpoint_key(),
                self._cursor_signature(),
            )
            if not data:
                return None
            return self._normalize_checkpoint_payload(data)

        if not self.cursor_path.exists():
            return None

        try:
            data = json.loads(self.cursor_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("DefectDojo: failed to load checkpoint state: %s", exc)
            return None

        if data.get("signature") != self._cursor_signature():
            logger.info("DefectDojo: checkpoint filters changed, resetting incremental checkpoint")
            return None

        return self._normalize_checkpoint_payload(data)

    def _normalize_checkpoint_payload(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Validate a checkpoint payload loaded from any storage backend."""
        last_status_update = data.get("last_status_update")
        last_id = data.get("last_id")
        if not last_status_update or last_id is None:
            return None

        return {
            "last_status_update": str(last_status_update),
            "last_id": int(last_id),
        }

    def _save_cursor(self, state: dict[str, Any]) -> None:
        """Persist the latest successfully processed DefectDojo checkpoint."""
        payload = {
            "last_status_update": state["last_status_update"],
            "last_id": int(state["last_id"]),
        }

        if self._checkpoint_store:
            try:
                self._checkpoint_store.save_checkpoint(
                    self._checkpoint_key(),
                    self._cursor_signature(),
                    payload,
                )
            except Exception as exc:
                logger.warning("DefectDojo: failed to persist checkpoint state: %s", exc)
            return

        payload = {
            "version": 1,
            "signature": self._cursor_signature(),
            **payload,
        }
        try:
            self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning("DefectDojo: failed to persist checkpoint state: %s", exc)

    def _checkpoint_key(self) -> str:
        """Build a stable shared-storage key for this incremental cursor."""
        return f"defectdojo:{self.config.cursor_path or 'default'}"

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
        """Return True when a finding sorts strictly after the persisted checkpoint."""
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
            severity_key = _clean_text(severity_str).lower()
            severity = DD_SEVERITY_MAP.get(severity_key, Severity.INFO)

            vulnerability_entries = self._collect_vulnerability_id_entries(dd_finding)
            cve_ids = sorted({
                entry["value"]
                for entry in vulnerability_entries
                if entry["value"].upper().startswith("CVE-")
            })

            normalized_endpoints, normalized_endpoint_objects = self._normalize_endpoints(dd_finding.get("endpoints", []))
            host = self._extract_host(dd_finding, normalized_endpoint_objects)
            endpoint_url = self._extract_endpoint_url(normalized_endpoint_objects, normalized_endpoints, host)

            date_str = dd_finding.get("date", "")
            try:
                timestamp = datetime.strptime(date_str, "%Y-%m-%d")
            except (ValueError, TypeError):
                timestamp = datetime.utcnow()

            desc_parts = [
                dd_finding.get("description", "No description"),
                "",
                f"**Severity:** {severity_str}",
                f"**Component:** {dd_finding.get('component_name', 'N/A')} {dd_finding.get('component_version', '')}".rstrip(),
            ]

            if dd_finding.get("cvssv3"):
                desc_parts.append(f"**CVSS v3:** {dd_finding['cvssv3']}")
            if dd_finding.get("mitigation"):
                desc_parts.append(f"\n**Mitigation:**\n{dd_finding['mitigation']}")
            if dd_finding.get("references"):
                desc_parts.append(f"\n**References:**\n{dd_finding['references']}")

            tags = list(dd_finding.get("tags", []))
            if dd_finding.get("test_type_name"):
                tags.append(f"scan:{dd_finding['test_type_name']}")

            found_by = _clean_text(dd_finding.get("test_type_name"))
            plugin_id = self._extract_plugin_id(dd_finding, vulnerability_entries, found_by)
            defectdojo_url = self._build_finding_ui_url(dd_finding.get("id"))

            finding = Finding(
                source=FindingSource.DEFECTDOJO,
                source_id=str(dd_finding.get("id", "unknown")),
                title=dd_finding.get("title", "DefectDojo Finding"),
                description="\n".join(desc_parts),
                severity=severity,
                raw_severity=severity_str,
                host=host,
                endpoints=normalized_endpoints,
                endpoint_url=endpoint_url,
                component=dd_finding.get("component_name", ""),
                component_version=dd_finding.get("component_version", ""),
                cwe=str(dd_finding.get("cwe", "")) if dd_finding.get("cwe") else "",
                param=_clean_text(dd_finding.get("param")),
                found_by=found_by,
                plugin_id=plugin_id,
                cvss=dd_finding.get("cvssv3_score"),
                cve_ids=cve_ids,
                tags=tags,
                timestamp=timestamp,
                raw_data=dd_finding,
                enrichment={
                    "defectdojo_url": defectdojo_url,
                    "source_url": defectdojo_url,
                    "normalized_endpoints": normalized_endpoint_objects,
                },
            )
            return hydrate_identity(finding)

        except Exception as exc:
            logger.warning("DefectDojo: failed to parse finding: %s", exc)
            return None

    def _build_finding_ui_url(self, finding_id: Any) -> str:
        """Build a browser-facing URL for a DefectDojo finding."""
        clean_id = _clean_text(finding_id)
        if not clean_id:
            return ""
        ui_root = _UI_API_SUFFIX_RE.sub("", self.base_url)
        return f"{ui_root}/finding/{clean_id}"

    def _collect_vulnerability_id_entries(self, dd_finding: dict[str, Any]) -> list[dict[str, str]]:
        """Flatten both legacy and modern vulnerability ID payload shapes."""
        entries: list[dict[str, str]] = []
        for key in ("vulnerability_ids", "vulnerability_id"):
            entries.extend(self._coerce_vulnerability_entries(dd_finding.get(key)))
        return entries

    def _coerce_vulnerability_entries(self, raw_value: Any) -> list[dict[str, str]]:
        """Normalize raw vulnerability ID payloads into a flat list of entries."""
        if raw_value in (None, "", []):
            return []
        if isinstance(raw_value, list):
            entries: list[dict[str, str]] = []
            for item in raw_value:
                entries.extend(self._coerce_vulnerability_entries(item))
            return entries
        if isinstance(raw_value, dict):
            nested = raw_value.get("vulnerability_ids")
            if nested not in (None, "", []):
                return self._coerce_vulnerability_entries(nested)

            value = (
                raw_value.get("vulnerability_id")
                or raw_value.get("value")
                or raw_value.get("id")
                or raw_value.get("name")
            )
            normalized = _normalize_identifier(value)
            if not normalized:
                return []
            return [{
                "value": normalized,
                "source": _clean_text(raw_value.get("source")),
                "type": _clean_text(raw_value.get("type") or raw_value.get("vulnerability_type")),
                "name": _clean_text(raw_value.get("name")),
            }]

        normalized = _normalize_identifier(raw_value)
        return [{"value": normalized, "source": "", "type": "", "name": ""}] if normalized else []

    def _normalize_endpoints(self, endpoints: Any) -> tuple[list[str], list[dict[str, str]]]:
        """Canonicalize expanded endpoint objects into stable host/URL records."""
        normalized_objects: list[dict[str, str]] = []
        normalized_values: list[str] = []
        seen_values: set[str] = set()

        for raw_endpoint in endpoints or []:
            endpoint = self._normalize_endpoint(raw_endpoint)
            canonical = endpoint["url"] or endpoint["canonical"]
            if not canonical:
                continue

            if canonical not in seen_values:
                seen_values.add(canonical)
                normalized_values.append(canonical)
                normalized_objects.append(endpoint)

        return normalized_values, normalized_objects

    def _normalize_endpoint(self, endpoint: Any) -> dict[str, str]:
        """Normalize one endpoint payload into explicit canonical fields."""
        protocol = ""
        host = ""
        port = ""
        path = ""
        url = ""

        if isinstance(endpoint, dict):
            protocol = _clean_protocol(endpoint.get("protocol") or endpoint.get("scheme"))
            host = _clean_host(
                endpoint.get("host")
                or endpoint.get("hostname")
                or endpoint.get("domain")
                or endpoint.get("dns_name")
                or endpoint.get("ip_address")
                or endpoint.get("ip")
            )
            port = _clean_port(endpoint.get("port"))
            path = _clean_path(endpoint.get("path"))
            url = _clean_text(endpoint.get("url"))
        else:
            url = _clean_text(endpoint)

        parsed = None
        url_candidate = url
        if url_candidate and not url_candidate.isdigit():
            try:
                parsed = urlsplit(url_candidate if "://" in url_candidate else f"//{url_candidate}")
            except ValueError:
                parsed = None

        if parsed:
            protocol = protocol or _clean_protocol(parsed.scheme)
            host = host or _clean_host(parsed.hostname)
            port = port or (_clean_port(parsed.port) if parsed.port is not None else "")
            path = path or _clean_path(parsed.path)

        display_port = port
        if (protocol == "https" and port == "443") or (protocol == "http" and port == "80"):
            display_port = ""

        rebuilt_url = ""
        if protocol and host:
            hostport = f"{host}:{display_port}" if display_port else host
            rebuilt_url = urlunsplit((protocol, hostport, path or "", "", ""))
        elif host and path:
            hostport = f"{host}:{display_port}" if display_port else host
            rebuilt_url = f"{hostport}{path}"
        elif host:
            rebuilt_url = f"{host}:{display_port}" if display_port else host

        canonical = rebuilt_url or (url_candidate if url_candidate and not url_candidate.isdigit() else "")

        return {
            "host": host,
            "protocol": protocol,
            "port": port,
            "path": path,
            "url": rebuilt_url,
            "canonical": canonical,
        }

    def _extract_host(self, dd_finding: dict[str, Any], endpoint_objects: list[dict[str, str]]) -> str:
        """Choose a stable asset host from normalized endpoints or top-level fields."""
        for endpoint in endpoint_objects:
            if endpoint["host"]:
                return endpoint["host"]

        for field in ("host", "hostname", "domain", "ip_address", "ip"):
            host = _clean_host(dd_finding.get(field))
            if host:
                return host

        for field in ("url", "endpoint_url", "target_start"):
            candidate = self._normalize_endpoint(dd_finding.get(field))
            if candidate["host"]:
                return candidate["host"]

        return ""

    def _extract_endpoint_url(
        self,
        endpoint_objects: list[dict[str, str]],
        normalized_endpoints: list[str],
        host: str,
    ) -> str:
        """Choose the best URL-like endpoint for web scanner identities."""
        for endpoint in endpoint_objects:
            if endpoint["url"]:
                return endpoint["url"]
        if normalized_endpoints:
            return normalized_endpoints[0]
        return host

    def _extract_plugin_id(
        self,
        dd_finding: dict[str, Any],
        vulnerability_entries: list[dict[str, str]],
        found_by: str,
    ) -> str:
        """Extract a trustworthy scanner/plugin identifier for Tenable-style findings."""
        found_by_key = found_by.strip().lower()
        is_tenable_scan = any(token in found_by_key for token in ("tenable", "nessus"))

        preferred_ids: list[str] = []
        fallback_ids: list[str] = []

        for entry in vulnerability_entries:
            vuln_id = _normalize_identifier(entry.get("value"))
            if not vuln_id or vuln_id.upper().startswith("CVE-"):
                continue

            id_context = " ".join(
                part.strip().lower()
                for part in (entry.get("source"), entry.get("type"), entry.get("name"))
                if part
            )
            if any(token in id_context for token in ("plugin", "nessus", "tenable")):
                preferred_ids.append(vuln_id)
            else:
                fallback_ids.append(vuln_id)

        top_level_candidates = [
            dd_finding.get("plugin_id"),
            dd_finding.get("pluginid"),
            dd_finding.get("nessus_plugin_id"),
            dd_finding.get("tenable_plugin_id"),
            dd_finding.get("vulnerability_id"),
        ]
        for candidate in top_level_candidates:
            normalized = _normalize_identifier(candidate)
            if normalized and not normalized.upper().startswith("CVE-"):
                fallback_ids.append(normalized)

        tag_candidate = self._extract_plugin_id_from_tags(dd_finding.get("tags", []))
        if tag_candidate:
            fallback_ids.append(tag_candidate)

        raw_candidate = self._extract_plugin_id_from_object(dd_finding)
        if raw_candidate:
            fallback_ids.append(raw_candidate)

        if is_tenable_scan:
            if preferred_ids:
                return preferred_ids[0]
            if fallback_ids:
                return fallback_ids[0]

        if preferred_ids:
            return preferred_ids[0]
        if fallback_ids:
            return fallback_ids[0]
        return ""

    def _extract_plugin_id_from_tags(self, tags: Any) -> str:
        """Parse plugin identifiers from tag text when structured IDs are absent."""
        for tag in tags or []:
            text = _clean_text(tag)
            if not text:
                continue
            match = _PLUGIN_TAG_RE.search(text)
            if match:
                return match.group(1)
        return ""

    def _extract_plugin_id_from_object(self, value: Any, depth: int = 0) -> str:
        """Recursively inspect raw payload fragments for plugin-like identifiers."""
        if depth > 4 or value is None:
            return ""

        if isinstance(value, dict):
            for key, raw in value.items():
                normalized_key = _clean_text(key).lower()
                if normalized_key in {"plugin_id", "pluginid", "nessus_plugin_id", "tenable_plugin_id"}:
                    candidate = _normalize_identifier(raw)
                    if candidate:
                        return candidate

                if "plugin" in normalized_key or "nessus" in normalized_key or "tenable" in normalized_key:
                    candidate = _normalize_identifier(raw)
                    if candidate and not candidate.upper().startswith("CVE-"):
                        return candidate

                nested = self._extract_plugin_id_from_object(raw, depth + 1)
                if nested:
                    return nested
            return ""

        if isinstance(value, list):
            for item in value:
                nested = self._extract_plugin_id_from_object(item, depth + 1)
                if nested:
                    return nested
            return ""

        if isinstance(value, str):
            match = _PLUGIN_TAG_RE.search(value)
            if match:
                return match.group(1)

        return ""

    def test_connection(self) -> bool:
        """Test connectivity to the DefectDojo API."""
        try:
            response = self.session.get(
                f"{self.base_url}/user_contact_infos/",
                params={"limit": 1},
                timeout=10,
            )
            self._parse_json_response(response, "/user_contact_infos/")
            logger.info("DefectDojo: connection test successful")
            return True
        except Exception as exc:
            logger.error("DefectDojo: connection test failed: %s", exc)
            return False
