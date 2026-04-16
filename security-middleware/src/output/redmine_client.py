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
        Create a new Redmine issue for the finding, or update an existing
        one if a duplicate is found.

        Returns:
            The Redmine issue ID, or None if the operation failed.
        """
        # Check for existing issue
        existing_id = self._find_existing_issue(finding)

        if existing_id:
            return self._update_issue(existing_id, finding)
        else:
            return self._create_issue(finding)

    def _create_issue(self, finding: Finding) -> Optional[int]:
        """Create a new Redmine issue."""
        url = f"{self.base_url}/issues.json"

        # Build subject line with severity prefix
        severity_prefix = finding.severity.value.upper()
        subject = f"[{severity_prefix}] [{finding.source.value.upper()}] {finding.title}"
        # Redmine subject max length is typically 255
        subject = subject[:255]

        # Get formatted description from enrichment, or use raw description
        description = finding.enrichment.get("redmine_description", finding.description)

        # Append raw alert JSON for full data visibility
        if finding.raw_data:
            import json
            raw_json = json.dumps(finding.raw_data, indent=2, default=str, ensure_ascii=False)
            description += f"\n\n---\n\nh3. Raw Alert Data\n\n<pre>\n{raw_json}\n</pre>\n"

        # Build issue payload
        issue_data: dict[str, Any] = {
            "issue": {
                "project_id": self.config.project_id,
                "tracker_id": self.config.tracker_id,
                "subject": subject,
                "description": description,
                "priority_id": finding.enrichment.get(
                    "redmine_priority_id",
                    self.config.priority_map.get(finding.severity.value, 1),
                ),
            }
        }

        # Add dedup hash as custom field if configured
        if self.config.dedup_custom_field_id:
            issue_data["issue"]["custom_fields"] = [
                {
                    "id": self.config.dedup_custom_field_id,
                    "value": finding.dedup_hash,
                }
            ]

        try:
            response = self.session.post(url, json=issue_data, timeout=30)
            response.raise_for_status()
            result = response.json()
            issue_id = result.get("issue", {}).get("id")
            logger.info(
                "Redmine: created issue #%s — %s",
                issue_id,
                subject[:80],
            )
            return issue_id
        except RequestException as e:
            logger.error("Redmine: failed to create issue: %s", e)
            if hasattr(e, "response") and e.response is not None:
                logger.error("Redmine: response: %s", e.response.text[:500])
            return None

    def _update_issue(self, issue_id: int, finding: Finding) -> Optional[int]:
        """Update an existing Redmine issue with new finding data."""
        url = f"{self.base_url}/issues/{issue_id}.json"

        # Add a note (journal entry) with the new occurrence
        note_parts = [
            f"h3. Duplicate finding detected",
            "",
            f"|_. Source|{finding.source.value.upper()}|",
            f"|_. Source ID|{finding.source_id}|",
            f"|_. Timestamp|{finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}|",
            f"|_. Severity|{finding.severity.value.upper()}|",
            "",
            "This finding has been seen again. The existing issue has been updated.",
        ]

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

        try:
            response = self.session.put(url, json=update_data, timeout=30)
            response.raise_for_status()
            logger.info("Redmine: updated issue #%s with new occurrence", issue_id)
            return issue_id
        except RequestException as e:
            logger.error("Redmine: failed to update issue #%s: %s", issue_id, e)
            return None

    def _find_existing_issue(self, finding: Finding) -> Optional[int]:
        """
        Search for an existing open issue that matches this finding.

        Uses custom field search if dedup_custom_field_id is configured,
        otherwise falls back to subject-line matching.
        """
        try:
            if self.config.dedup_custom_field_id:
                return self._search_by_custom_field(finding.dedup_hash)
            else:
                return self._search_by_subject(finding)
        except Exception as e:
            logger.warning("Redmine: issue search failed: %s", e)
            return None

    def _search_by_custom_field(self, dedup_hash: str) -> Optional[int]:
        """Search for issue by dedup hash in custom field."""
        url = f"{self.base_url}/issues.json"
        params = {
            "project_id": self.config.project_id,
            "status_id": "open",
            f"cf_{self.config.dedup_custom_field_id}": dedup_hash,
            "limit": 1,
        }

        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        issues = response.json().get("issues", [])

        if issues:
            issue_id = issues[0]["id"]
            logger.debug("Redmine: found existing issue #%s by custom field", issue_id)
            return issue_id
        return None

    def _search_by_subject(self, finding: Finding) -> Optional[int]:
        """Search for issue by matching subject line."""
        url = f"{self.base_url}/issues.json"

        # Build the expected subject prefix
        severity_prefix = finding.severity.value.upper()
        search_term = f"[{severity_prefix}] [{finding.source.value.upper()}] {finding.title}"

        params = {
            "project_id": self.config.project_id,
            "status_id": "open",
            "subject": f"~{finding.title[:100]}",  # Partial match
            "limit": 5,
        }

        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        issues = response.json().get("issues", [])

        for issue in issues:
            # Check if the dedup hash appears in the description
            desc = issue.get("description", "")
            if finding.dedup_hash in desc:
                logger.debug("Redmine: found existing issue #%s by subject match", issue["id"])
                return issue["id"]

        return None

    def create_issues_batch(self, findings: list[Finding]) -> dict[str, int]:
        """
        Process a batch of findings, creating or updating Redmine issues.

        Returns:
            Dictionary with counts: {"created": N, "updated": M, "failed": K}
        """
        stats = {"created": 0, "updated": 0, "failed": 0}

        for finding in findings:
            existing_id = self._find_existing_issue(finding)

            if existing_id:
                result = self._update_issue(existing_id, finding)
                if result:
                    stats["updated"] += 1
                else:
                    stats["failed"] += 1
            else:
                result = self._create_issue(finding)
                if result:
                    stats["created"] += 1
                else:
                    stats["failed"] += 1

        logger.info(
            "Redmine: batch complete — %d created, %d updated, %d failed",
            stats["created"],
            stats["updated"],
            stats["failed"],
        )
        return stats

    def test_connection(self) -> bool:
        """Test connectivity to the Redmine API."""
        try:
            url = f"{self.base_url}/projects/{self.config.project_id}.json"
            response = self.session.get(url, timeout=10)
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
