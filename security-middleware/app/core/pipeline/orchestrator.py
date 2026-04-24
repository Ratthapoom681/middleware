"""
Pipeline Orchestrator – central engine that runs the end-to-end pipeline.

Fetches findings from Wazuh and DefectDojo, runs them through
Filter → SeverityMapper → Enricher → Deduplicator, delivers results
to Redmine, and persists all processed findings to the database.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.settings.models import settings_manager
from app.config import build_typed_configs
from app.core.database import database, findings as findings_table
from app.core.websocket import ws_manager
from app.pipeline import monitor
from app.pipeline.dead_letter import add_dead_letter
from app.audit.models import log_action

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Central pipeline execution engine.

    Reads configuration from SettingsManager, instantiates source clients
    and pipeline stages, and orchestrates a single poll cycle.
    """

    def __init__(self):
        self._configs = None
        self._wazuh_client = None
        self._defectdojo_client = None
        self._redmine_client = None
        self._filter_stage = None
        self._severity_mapper = None
        self._enricher_stage = None
        self._dedup_stage = None
        self._initialized = False

    def rebuild(self) -> None:
        """
        (Re-)construct all clients and pipeline stages from the current
        SettingsManager state. Called on first run and after config changes.
        """
        # Close previous dedup if it exists
        if self._dedup_stage:
            try:
                self._dedup_stage.close()
            except Exception:
                pass

        self._configs = build_typed_configs(settings_manager)

        wazuh_cfg = self._configs["wazuh"]
        dd_cfg = self._configs["defectdojo"]
        redmine_cfg = self._configs["redmine"]
        filter_cfg = self._configs["filter"]
        dedup_cfg = self._configs["dedup"]
        enrichment_cfg = self._configs["enrichment"]

        # Source clients
        from app.wazuh.client import WazuhClient
        self._wazuh_client = WazuhClient(wazuh_cfg) if wazuh_cfg.base_url or wazuh_cfg.alerts_json_path else None

        from app.defectdojo.client import DefectDojoClient
        self._defectdojo_client = DefectDojoClient(dd_cfg) if dd_cfg.enabled and dd_cfg.base_url else None

        from app.redmine.client import RedmineClient
        self._redmine_client = RedmineClient(redmine_cfg) if redmine_cfg.base_url and redmine_cfg.api_key else None

        # Pipeline stages
        from app.core.pipeline.filter import FilterStage
        self._filter_stage = FilterStage(filter_cfg)

        from app.core.pipeline.severity_mapper import SeverityMapperStage
        self._severity_mapper = SeverityMapperStage(redmine_cfg.priority_map)

        from app.core.pipeline.enricher import EnricherStage
        self._enricher_stage = EnricherStage(enrichment_cfg)

        from app.core.pipeline.deduplicator import DeduplicatorStage
        self._dedup_stage = DeduplicatorStage(dedup_cfg)

        self._initialized = True
        logger.info(
            "PipelineOrchestrator: rebuilt (wazuh=%s, defectdojo=%s, redmine=%s)",
            "enabled" if self._wazuh_client else "disabled",
            "enabled" if self._defectdojo_client else "disabled",
            "enabled" if self._redmine_client else "disabled",
        )

    async def run_once(self) -> dict[str, Any]:
        """
        Execute one full pipeline cycle.

        Returns:
            A stats dict with counts of ingested, filtered, deduplicated, etc.
        """
        if not self._initialized:
            self.rebuild()

        stats = {
            "ingested": 0,
            "filtered": 0,
            "deduplicated": 0,
            "new": 0,
            "repeat": 0,
            "created": 0,
            "updated": 0,
            "reopened": 0,
            "recreated": 0,
            "failed": 0,
            "delivered": 0,
        }

        pipeline_cfg = settings_manager.get("pipeline")
        lookback_minutes = int(pipeline_cfg.get("initial_lookback_minutes", 1440))

        # ── 1. Ingest ─────────────────────────────────────────────────
        all_findings = []

        # Wazuh findings are now pushed via webhook (see app/webhook/routes.py)
        # Only poll sources that don't support push yet.

        if self._defectdojo_client:
            try:
                dd_findings = await asyncio.to_thread(
                    self._defectdojo_client.fetch_findings
                )
                all_findings.extend(dd_findings)
                logger.info("Pipeline: fetched %d DefectDojo findings", len(dd_findings))
            except Exception as exc:
                logger.error("Pipeline: DefectDojo fetch failed: %s", exc)

        stats["ingested"] = len(all_findings)
        return await self.process_batch(all_findings, stats)

    async def process_batch(self, findings: list[Any], stats: dict[str, Any] = None) -> dict[str, Any]:
        """
        Run the pipeline stages for a specific batch of findings.
        Returns the stats of the run.
        """
        if not stats:
            stats = {
                "ingested": len(findings),
                "filtered": 0,
                "deduplicated": 0,
                "new": 0,
                "repeat": 0,
                "created": 0,
                "updated": 0,
                "reopened": 0,
                "recreated": 0,
                "delivered": 0,
                "failed": 0,
            }
        
        if not self._initialized:
            self.rebuild()

        if not findings:
            logger.info("Pipeline: no findings to process")
            monitor.record_run(stats)
            return stats

        # ── 2. Filter ────────────────────────────────────────────────
        filtered = self._filter_stage.process(findings)
        stats["filtered"] += (len(findings) - len(filtered))

        if not filtered:
            logger.info("Pipeline: all findings were filtered out")
            monitor.record_run(stats)
            return stats

        # ── 3. Severity Mapping ──────────────────────────────────────
        mapped = self._severity_mapper.process(filtered)

        # ── 4. Enrichment ────────────────────────────────────────────
        enriched = self._enricher_stage.process(mapped)

        # ── 5. Deduplication ─────────────────────────────────────────
        new_findings, repeat_findings = await asyncio.to_thread(
            self._dedup_stage.process, enriched
        )
        stats["new"] = len(new_findings)
        stats["repeat"] = len(repeat_findings)
        stats["deduplicated"] = stats["repeat"]

        # ── 6. Output to Redmine ─────────────────────────────────────
        if self._redmine_client:
            # Process new findings
            if new_findings:
                try:
                    redmine_stats, successful = await asyncio.to_thread(
                        self._redmine_client.create_issues_batch, new_findings
                    )
                    stats["created"] += redmine_stats.get("created", 0)
                    stats["failed"] += redmine_stats.get("failed", 0)

                    # Commit dedup hashes only for successfully delivered findings
                    if successful:
                        await asyncio.to_thread(self._dedup_stage.commit_new, successful)
                except Exception as exc:
                    logger.error("Pipeline: Redmine create batch failed: %s", exc)
                    stats["failed"] += len(new_findings)

            # Process repeat findings (update existing tickets)
            if repeat_findings:
                try:
                    update_stats, update_successful = await asyncio.to_thread(
                        self._redmine_client.create_issues_batch, repeat_findings
                    )
                    stats["updated"] += update_stats.get("updated", 0)
                    stats["reopened"] += update_stats.get("reopened", 0)
                    stats["recreated"] += update_stats.get("recreated", 0)
                    stats["failed"] += update_stats.get("failed", 0)

                    if update_successful:
                        await asyncio.to_thread(self._dedup_stage.commit_updates, update_successful)
                except Exception as exc:
                    logger.error("Pipeline: Redmine update batch failed: %s", exc)
                    stats["failed"] += len(repeat_findings)

            # Commit DefectDojo checkpoint on success
            if self._defectdojo_client and stats["failed"] == 0:
                try:
                    await asyncio.to_thread(self._defectdojo_client.commit_pending_checkpoint)
                except Exception:
                    pass
            elif self._defectdojo_client:
                self._defectdojo_client.discard_pending_checkpoint()
        else:
            # No Redmine configured — still commit dedup and mark as delivered
            if new_findings:
                await asyncio.to_thread(self._dedup_stage.commit_new, new_findings)
            if repeat_findings:
                await asyncio.to_thread(self._dedup_stage.commit_updates, repeat_findings)

        stats["delivered"] = stats["created"] + stats["updated"] + stats["reopened"] + stats["recreated"]

        # ── 7. Persist findings to DB ────────────────────────────────
        all_processed = new_findings + repeat_findings
        for finding in all_processed:
            try:
                await database.execute(
                    findings_table.insert().values(
                        source=finding.source.value,
                        source_id=finding.source_id,
                        dedup_hash=finding.dedup_hash,
                        severity=finding.severity.value,
                        title=finding.title[:500],
                        description=finding.description[:5000],
                        raw_data=json.dumps(finding.raw_data, default=str)[:10000],
                        redmine_ticket_id=finding.redmine_issue_id,
                        status="delivered" if finding.redmine_issue_id else "processed",
                    )
                )
            except Exception as exc:
                logger.warning("Pipeline: failed to persist finding %s: %s", finding.source_id, exc)

        # Write failed findings to dead-letter queue
        for finding in all_processed:
            if finding.action == "failed":
                try:
                    await add_dead_letter(
                        finding_id=0,
                        error=f"Redmine delivery failed for {finding.source.value}:{finding.source_id}"
                    )
                except Exception:
                    pass

        # ── 8. Record metrics & broadcast ────────────────────────────
        monitor.record_run(stats)

        try:
            await ws_manager.broadcast({
                "type": "pipeline_run",
                "stats": stats,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass

        # Audit log
        try:
            await log_action(
                module="pipeline",
                action="run",
                detail=(
                    f"Ingested {stats['ingested']}, filtered {stats['filtered']}, "
                    f"deduped {stats['deduplicated']}, delivered {stats['delivered']}, "
                    f"failed {stats['failed']}"
                ),
            )
        except Exception:
            pass

        logger.info(
            "Pipeline run complete: ingested=%d, filtered=%d, deduped=%d, "
            "delivered=%d, failed=%d",
            stats["ingested"],
            stats["filtered"],
            stats["deduplicated"],
            stats["delivered"],
            stats["failed"],
        )

        return stats

    def close(self) -> None:
        """Clean up resources."""
        if self._dedup_stage:
            try:
                self._dedup_stage.close()
            except Exception:
                pass


# Module-level singleton
pipeline_orchestrator = PipelineOrchestrator()
