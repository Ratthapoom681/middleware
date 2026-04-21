"""
Redmine API client.

Creates and updates issues in Redmine based on processed findings.
Handles deduplication by checking for existing issues with the same
dedup hash before creating new ones.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

from src.config import RedmineConfig
from src.models.finding import Finding

logger = logging.getLogger(__name__)


class RedmineClient:
    """Client for the Redmine REST API."""

    def __init__(self, config: RedmineConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-Redmine-API-Key": config.api_key,
            "Content-Type": "application/json",
        })

    def create_or_update_issue(self, finding: Finding) -> Optional[int]:
        """
        Wrapper to proxy single-issue creation requests through the canonical batch workflow.
        Returns:
            The Redmine issue ID, or None if the operation failed.
        """
        logger.warning("Redmine: create_or_update_issue() is deprecated; routing through create_issues_batch.")
        stats, successful = self.create_issues_batch([finding])
        if successful:
            return successful[0].redmine_issue_id
        return None

    def _source_link(self, finding: Finding) -> str:
        """Return the browser-facing source URL for traceability when available."""
        return str(
            finding.enrichment.get("source_url")
            or finding.enrichment.get("defectdojo_url")
            or ""
        ).strip()

    def _source_link_section(self, finding: Finding) -> str:
        """Build a Textile-safe source-link section for new Redmine issues."""
        source_link = self._source_link(finding)
        if not source_link:
            return ""
        return f'h3. Source Finding\n\n"View DefectDojo finding":{source_link}\n'

    def _create_issue(self, finding: Finding) -> Optional[int]:
        """Create a new Redmine issue."""
        url = f"{self.base_url}/issues.json"

        # Routing engine determines tracker and parent linking
        tracker_id, use_parent, active_parent_tracker_id = self._evaluate_routing(finding)
        parent_id = None
        if use_parent:
            parent_id = self._get_or_create_parent_issue(finding, active_parent_tracker_id)

        # Build subject line with severity prefix
        severity_prefix = finding.severity.value.upper()
        subject = f"[{severity_prefix}] [{finding.source.value.upper()}] {finding.title}"
        # Redmine subject max length is typically 255
        subject = subject[:255]

        # Get formatted description from enrichment, or use raw description
        description = finding.enrichment.get("redmine_description", finding.description)

        # Ensure the dedup hash is explicitly in the description for fallback subject-matching
        if finding.dedup_hash not in description:
            description += f"\n\n---\n_Dedup Hash: {finding.dedup_hash}_\n"

        source_link_section = self._source_link_section(finding)
        if source_link_section:
            description += f"\n---\n\n{source_link_section}"

        # Append raw alert JSON for full data visibility
        if finding.raw_data:
            import json
            raw_json = json.dumps(finding.raw_data, indent=2, default=str, ensure_ascii=False)
            description += f"\n\n---\n\nh3. Raw Alert Data\n\n<pre>\n{raw_json}\n</pre>\n"

        # Build issue payload
        issue_data: dict[str, Any] = {
            "issue": {
                "project_id": self.config.project_id,
                "tracker_id": tracker_id,
                "subject": subject,
                "description": description,
                "priority_id": finding.enrichment.get(
                    "redmine_priority_id",
                    self.config.priority_map.get(finding.severity.value, 1),
                ),
            }
        }

        if parent_id:
            issue_data["issue"]["parent_issue_id"] = parent_id

        # Add dedup hash as custom field if configured
        if self.config.dedup_custom_field_id:
            issue_data["issue"]["custom_fields"] = [
                {
                    "id": self.config.dedup_custom_field_id,
                    "value": finding.dedup_hash,
                }
            ]

        try:
            response = self.session.post(f"{self.base_url}/issues.json", json=issue_data, timeout=30)
            response.raise_for_status()
            result = response.json()
            issue_id = result.get("issue", {}).get("id")
            logger.info("Redmine: created issue #%s", issue_id)
            return issue_id
        except RequestException as e:
            logger.error("Redmine: failed to create issue: %s", e)
            return None

    def _update_issue(self, issue_id: int, finding: Finding, reopen: bool = False) -> Optional[int]:
        """Update an existing Redmine issue with new finding data."""
        url = f"{self.base_url}/issues/{issue_id}.json"

        # Add a note (journal entry) with the new occurrence
        count = getattr(finding, 'occurrence_count', 1)
        note_parts = [
            "h3. Repeat finding detected",
            "",
            f"|_. Source|{finding.source.value.upper()}|",
            f"|_. Source ID|{finding.source_id}|",
            f"|_. Timestamp|{finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}|",
            f"|_. Severity|{finding.severity.value.upper()}|",
            f"|_. New Occurrences|{count}|",
            "",
            f"This finding has been seen *{count}* more time(s) since the last update.",
        ]
        source_link = self._source_link(finding)
        if source_link:
            note_parts.extend([
                "",
                f'"View DefectDojo finding":{source_link}',
            ])

        update_data: dict[str, Any] = {
            "issue": {
                "notes": "\n".join(note_parts),
                # Optionally escalate priority if new finding is more severe
                "priority_id": finding.enrichment.get(
                    "redmine_priority_id",
                    self.config.priority_map.get(finding.severity.value, 1),
                ),
            }
        }
        
        if reopen:
            update_data["issue"]["status_id"] = 1

        try:
            response = self.session.put(url, json=update_data, timeout=30)
            response.raise_for_status()
            logger.info("Redmine: updated issue #%s with new occurrence", issue_id)
            return issue_id
        except RequestException as e:
            logger.error("Redmine: failed to update issue #%s: %s", issue_id, e)
            return None

    def _get_issue(self, issue_id: int) -> Optional[dict[str, Any]]:
        """
        Fetch issue explicitly by ID to verify state.
        Returns None ONLY on explicit 404. Raises RequestException otherwise.
        """
        url = f"{self.base_url}/issues/{issue_id}.json"
        response = self.session.get(url, timeout=10)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json().get("issue")

    def _evaluate_routing(self, finding: Finding) -> tuple[int, bool, Optional[int]]:
        """Evaluate routing rules to determine tracker and parent configuration."""
        for rule in self.config.routing_rules:
            if not rule.enabled:
                continue
            
            # Check source constraint
            if rule.source != "any" and rule.source != finding.source.value:
                continue
                
            # Check match against finding's routing_key
            val = finding.routing_key
            matched = False
            
            if rule.match_type == "exact":
                matched = (val == rule.match_value)
            elif rule.match_type == "prefix":
                matched = val.startswith(rule.match_value)
            elif rule.match_type == "regex":
                import re
                try:
                    if re.match(rule.match_value, val):
                        matched = True
                except re.error:
                    pass
            
            if matched:
                t_id = rule.tracker_id if rule.tracker_id else self.config.tracker_id
                logger.debug("Redmine: finding matched routing rule '%s'", rule.match_value)
                finding.enrichment["matched_rule"] = f"{rule.match_type}: {rule.match_value or '(empty)'}"
                finding.enrichment["selected_tracker"] = t_id
                return t_id, rule.use_parent, rule.parent_tracker_id

        # Fallback to default
        finding.enrichment["matched_rule"] = "default fallback"
        finding.enrichment["selected_tracker"] = self.config.tracker_id
        return self.config.tracker_id, self.config.enable_parent_issues, self.config.parent_tracker_id

    def _get_or_create_parent_issue(self, finding: Finding, active_parent_tracker_id: Optional[int] = None) -> Optional[int]:
        """
        Find or create a parent issue (e.g. for the affected device).
        """
        parent_tracker = active_parent_tracker_id if active_parent_tracker_id else self.config.parent_tracker_id
        if not parent_tracker:
            logger.debug("Redmine: no parent_tracker_id configured, skipping parent link")
            return None

        # Format parent subject, ensuring it respects the routing_key (or host fallback)
        subject_target = finding.routing_key if finding.routing_key else finding.host
        subject = f"Security Incidents: {subject_target}"
        url = f"{self.base_url}/issues.json"
        
        # 1. Search for existing open parent
        params = {
            "project_id": self.config.project_id,
            "tracker_id": parent_tracker,
            "status_id": "open",
            "subject": subject,
            "limit": 1,
        }
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            issues = response.json().get("issues", [])
            if issues:
                return issues[0]["id"]
        except RequestException as e:
            logger.warning("Redmine: failed to search for parent issue: %s", e)

        # 2. Doesn't exist, create it
        
        # Build description with asset context if available
        description = f"Security tracking Epic for device: *{finding.host}*"
        asset_info = finding.enrichment.get("asset")
        if asset_info:
            description += "\n\nh3. Asset Information\n\n"
            for key, value in asset_info.items():
                if key != "aliases":
                    description += f"|_. {key.replace('_', ' ').title()}|{value}|\n"

        issue_data = {
            "issue": {
                "project_id": self.config.project_id,
                "tracker_id": parent_tracker,
                "subject": subject,
                "description": description,
            }
        }

        try:
            response = self.session.post(url, json=issue_data, timeout=30)
            response.raise_for_status()
            parent_id = response.json().get("issue", {}).get("id")
            logger.info("Redmine: created new Parent Device Issue #%s for %s", parent_id, finding.host)
            return parent_id
        except RequestException as e:
            logger.error("Redmine: failed to create parent issue for %s: %s", finding.host, e)
            return None

    def create_issues_batch(self, findings: list[Finding]) -> tuple[dict[str, int], list[Finding]]:
        """
        Process a batch of findings, creating or updating Redmine issues.

        Returns:
            Tuple of (stats dict, list of successfully processed findings).
            Stats dict has counts: {"created": N, "updated": M, "failed": K, "reopened": X, "recreated": Y}
        """
        stats = {"created": 0, "updated": 0, "failed": 0, "reopened": 0, "recreated": 0}
        successful_findings: list[Finding] = []

        for finding in findings:
            if finding.redmine_issue_id:
                try:
                    issue = self._get_issue(finding.redmine_issue_id)
                except RequestException as e:
                    logger.warning("Redmine: transient error fetching issue #%s: %s", finding.redmine_issue_id, e)
                    finding.action = "failed"
                    stats["failed"] += 1
                    continue

                if not issue:
                    # Missing in Redmine -> Recreate
                    finding.action = "recreated"
                    new_id = self._create_issue(finding)
                    if new_id:
                        finding.redmine_issue_id = new_id
                        finding.issue_state = "open"
                        stats["recreated"] += 1
                        successful_findings.append(finding)
                    else:
                        finding.action = "failed"
                        stats["failed"] += 1
                else:
                    status = issue.get("status", {})
                    is_closed = status.get("is_closed", False)

                    if is_closed:
                        finding.action = "reopened"
                        result = self._update_issue(finding.redmine_issue_id, finding, reopen=True)
                        if result:
                            finding.issue_state = "open"
                            stats["reopened"] += 1
                            successful_findings.append(finding)
                        else:
                            finding.action = "failed"
                            stats["failed"] += 1
                    else:
                        finding.action = "updated"
                        result = self._update_issue(finding.redmine_issue_id, finding)
                        if result:
                            finding.issue_state = "open"
                            stats["updated"] += 1
                            successful_findings.append(finding)
                        else:
                            finding.action = "failed"
                            stats["failed"] += 1
            else:
                finding.action = "created"
                new_id = self._create_issue(finding)
                if new_id:
                    finding.redmine_issue_id = new_id
                    finding.issue_state = "open"
                    stats["created"] += 1
                    successful_findings.append(finding)
                else:
                    finding.action = "failed"
                    stats["failed"] += 1

        logger.info(
            "Redmine: batch complete — %d created, %d updated, %d reopened, %d recreated, %d failed",
            stats["created"],
            stats["updated"],
            stats["reopened"],
            stats["recreated"],
            stats["failed"],
        )
        return stats, successful_findings

    def test_connection(self) -> bool:
        """Test connectivity to the Redmine API."""
        try:
            response = self.session.get(
                f"{self.base_url}/projects/{self.config.project_id}.json",
                timeout=10,
            )
            response.raise_for_status()
            project = response.json().get("project", {})
            logger.info(
                "Redmine: connected — project '%s' (ID: %s)",
                project.get("name", "?"),
                project.get("id", "?"),
            )
            return True
        except Exception as e:
            logger.error("Redmine: connection test failed: %s", e)
            return False

    def get_trackers(self) -> list[dict[str, Any]]:
        """Fetch all available trackers from Redmine."""
        url = f"{self.base_url}/trackers.json"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json().get("trackers", [])
        except Exception as e:
            logger.error("Redmine: failed to fetch trackers: %s", e)
            return []
