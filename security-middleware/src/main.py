"""
Security Middleware Pipeline — Main Entry Point.

Orchestrates the full pipeline:
  1. Fetch findings from Wazuh and DefectDojo
  2. Run through pipeline stages (filter → severity map → dedup → enrich)
  3. Create/update tickets in Redmine
  4. Repeat on the configured polling interval
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

# Ensure the project root is on sys.path so 'web' module is found reliably
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import load_config, AppConfig
from src.models.finding import Finding
from src.sources.wazuh_client import WazuhClient
from src.sources.defectdojo_client import DefectDojoClient
from src.pipeline.filter import FilterStage
from src.pipeline.severity_mapper import SeverityMapperStage
from src.pipeline.deduplicator import DeduplicatorStage
from src.pipeline.enricher import EnricherStage
from src.output.redmine_client import RedmineClient
from src.dashboard_history import create_dashboard_history_store
from src.state_store import create_state_store

logger = logging.getLogger("middleware")

# Graceful shutdown flag
_shutdown = False


def _signal_handler(signum, frame):
    global _shutdown
    logger.info("Shutdown signal received, finishing current cycle...")
    _shutdown = True


class MiddlewarePipeline:
    """
    Orchestrates the full ingestion → processing → output pipeline.
    """

    def __init__(self, config: AppConfig, config_path: str = None):
        self.config = config
        self.config_path = config_path or config._loaded_path or "config/config.yaml"
        self._last_config_mtime = self._get_config_mtime()
        self.state_store = create_state_store(config.storage)
        self.dashboard_history = create_dashboard_history_store(config.storage, self.state_store)

        # Source clients
        self.wazuh = WazuhClient(config.wazuh)
        self.defectdojo = DefectDojoClient(config.defectdojo, checkpoint_store=self.state_store)

        # Pipeline stages
        self.filter_stage = FilterStage(config.pipeline.filter)
        self.severity_mapper = SeverityMapperStage(config.redmine.priority_map)
        self.dedup_stage = DeduplicatorStage(config.pipeline.dedup, state_store=self.state_store)
        self.enricher = EnricherStage(config.pipeline.enrichment)

        # Output
        self.redmine = RedmineClient(config.redmine)

    def _get_config_mtime(self) -> float:
        import os
        try:
            return os.path.getmtime(self.config_path)
        except OSError:
            return 0.0

    def check_config_reload(self) -> None:
        """Check if the config file has been modified on disk and reload if necessary."""
        current_mtime = self._get_config_mtime()
        if current_mtime > self._last_config_mtime:
            logger.info("Config file modification detected! Reloading pipeline components...")
            self._last_config_mtime = current_mtime
            try:
                from src.config import load_config
                new_config = load_config(self.config_path)
                new_state_store = create_state_store(new_config.storage)
                new_dashboard_history = create_dashboard_history_store(new_config.storage, new_state_store)

                self.close()

                self.config = new_config
                self.state_store = new_state_store
                self.dashboard_history = new_dashboard_history

                # Re-initialize all clients with new config
                self.wazuh = WazuhClient(self.config.wazuh)
                self.defectdojo = DefectDojoClient(
                    self.config.defectdojo,
                    checkpoint_store=self.state_store,
                )
                self.filter_stage = FilterStage(self.config.pipeline.filter)
                self.severity_mapper = SeverityMapperStage(self.config.redmine.priority_map)
                self.dedup_stage = DeduplicatorStage(
                    self.config.pipeline.dedup,
                    state_store=self.state_store,
                )
                self.enricher = EnricherStage(self.config.pipeline.enrichment)
                self.redmine = RedmineClient(self.config.redmine)
                logger.info("Pipeline components reloaded successfully.")
                self.test_connections()
            except Exception as e:
                logger.error("Failed to reload configuration: %s", e)

    def test_connections(self) -> bool:
        """Test connectivity to all external services."""
        results = {}

        logger.info("=" * 60)
        logger.info("Testing connections...")
        logger.info("=" * 60)

        results["wazuh"] = self.wazuh.test_connection()
        results["defectdojo"] = self.defectdojo.test_connection()
        results["redmine"] = self.redmine.test_connection()

        for name, ok in results.items():
            status = "✅ OK" if ok else "❌ FAILED"
            logger.info("  %s: %s", name.upper(), status)

        all_ok = all(results.values())
        if not all_ok:
            logger.warning("Some connections failed — pipeline may not work correctly")
        return all_ok

    def run_cycle(self) -> dict[str, int]:
        """
        Execute a single pipeline cycle:
          fetch → filter → map → dedup → enrich → output
        """
        cycle_start = datetime.now(timezone.utc)
        logger.info("=" * 60)
        logger.info("Pipeline cycle started at %s", cycle_start.isoformat())
        logger.info("=" * 60)

        # --- 1. Ingest ---
        findings: list[Finding] = []

        logger.info("--- Ingesting from Wazuh ---")
        try:
            wazuh_findings = self.wazuh.fetch_alerts(
                since_minutes=self.config.pipeline.initial_lookback_minutes
            )
            findings.extend(wazuh_findings)
            logger.info("Wazuh: %d alerts ingested", len(wazuh_findings))
        except Exception as e:
            logger.error("Wazuh ingestion failed: %s", e)

        dd_findings: list[Finding] = []
        if self.config.defectdojo.enabled:
            logger.info("--- Ingesting from DefectDojo ---")
            try:
                dd_findings = self.defectdojo.fetch_findings()
                findings.extend(dd_findings)
                logger.info("DefectDojo: %d findings ingested", len(dd_findings))
            except Exception as e:
                self.defectdojo.discard_pending_checkpoint()
                logger.error("DefectDojo ingestion failed: %s", e)
        else:
            logger.debug("DefectDojo: disabled, skipping")

        if not findings:
            logger.info("No findings to process this cycle")
            return {"ingested": 0, "filtered": 0, "deduplicated": 0, "output": 0}

        try:
            outcome = self.process_batch(
                findings,
                cycle_start,
                event_context={
                    "origin": "poll",
                    "alert_count": len(findings),
                    "source_counts": {
                        "wazuh": len(wazuh_findings),
                        "defectdojo": len(dd_findings),
                    },
                },
            )
        except Exception:
            self.defectdojo.discard_pending_checkpoint()
            raise

        if dd_findings:
            dd_failures = [finding for finding in dd_findings if getattr(finding, "action", None) == "failed"]
            if dd_failures:
                logger.warning(
                    "DefectDojo: %d finding(s) failed downstream processing; checkpoint will not advance",
                    len(dd_failures),
                )
                self.defectdojo.discard_pending_checkpoint()
            else:
                self.defectdojo.commit_pending_checkpoint()

        return outcome["stats"]

    def process_batch(
        self,
        findings: list[Finding],
        cycle_start: datetime = None,
        event_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Process a batch of pre-ingested findings through the pipeline:
          filter → map → dedup → enrich → output
        """
        if not cycle_start:
            cycle_start = datetime.now(timezone.utc)
            
        original_findings = list(findings)
        total_ingested = len(findings)
        logger.info("Processing batch: %d findings", total_ingested)

        # --- 2. Filter ---
        logger.info("--- Filtering ---")
        findings = self.filter_stage.process(findings)
        after_filter = len(findings)

        # --- 3. Map severity ---
        logger.info("--- Mapping severity ---")
        findings = self.severity_mapper.process(findings)

        # --- 4. Deduplicate ---
        logger.info("--- Deduplicating ---")
        new_findings, repeat_findings = self.dedup_stage.process(findings)
        after_dedup = len(new_findings)

        # --- 5. Enrich ---
        logger.info("--- Enriching ---")
        new_findings = self.enricher.process(new_findings)
        if repeat_findings:
            repeat_findings = self.enricher.process(repeat_findings)

        async_delivery_enabled = self._async_delivery_enabled()
        successful_new: list[Finding] = []
        successful_repeat: list[Finding] = []
        queue_stats = {"queued": 0, "failed": 0}
        sync_stats = {"created": 0, "updated": 0, "failed": 0, "reopened": 0, "recreated": 0}

        if async_delivery_enabled:
            logger.info("--- Queueing Wazuh findings for async Redmine delivery ---")
            async_new = [finding for finding in new_findings if finding.source.value == "wazuh"]
            async_repeat = [finding for finding in repeat_findings if finding.source.value == "wazuh"]
            sync_new = [finding for finding in new_findings if finding.source.value != "wazuh"]
            sync_repeat = [finding for finding in repeat_findings if finding.source.value != "wazuh"]

            queue_stats = self._enqueue_redmine_jobs(async_new, async_repeat)
            sync_stats, successful_new, successful_repeat = self._deliver_findings(sync_new, sync_repeat)
        else:
            sync_stats, successful_new, successful_repeat = self._deliver_findings(new_findings, repeat_findings)

        stats = {
            "created": sync_stats.get("created", 0),
            "updated": sync_stats.get("updated", 0),
            "reopened": sync_stats.get("reopened", 0),
            "recreated": sync_stats.get("recreated", 0),
            "failed": sync_stats.get("failed", 0) + queue_stats.get("failed", 0),
            "queued": queue_stats.get("queued", 0),
        }

        # --- 7. Commit successful findings to dedup registry ---
        if successful_new:
            self.dedup_stage.commit_new(successful_new)
        if successful_repeat:
            self.dedup_stage.commit_updates(successful_repeat)

        total_failed = stats.get("failed", 0)
        if total_failed > 0:
            logger.warning(
                "Deduplicator: %d findings were NOT committed (Redmine API failed). "
                "They will be retried next cycle.",
                total_failed,
            )

        # Ensure database cleanup happens strictly after operational dependencies conclude
        self.dedup_stage.cleanup()

        # --- Summary ---
        elapsed = (datetime.now(timezone.utc) - cycle_start).total_seconds()
        logger.info("=" * 60)
        logger.info("Pipeline processing complete in %.1fs", elapsed)
        logger.info(
            "  Ingested: %d | After filter: %d | New: %d | Repeat: %d | "
            "Created: %d | Updated: %d | Failed: %d",
            total_ingested,
            after_filter,
            after_dedup,
            len(repeat_findings),
            stats.get("created", 0),
            stats.get("updated", 0),
            stats.get("failed", 0),
        )
        logger.info("=" * 60)

        results = []
        for f in original_findings:
            # Force evaluation of tracing metadata even if finding was filtered
            self.redmine._evaluate_routing(f)
            
            results.append({
                "title": f.title,
                "severity": f.severity.value,
                "source": f.source.value,
                "source_id": f.source_id,
                "action": getattr(f, "action", None) or "Filtered",
                "reason": getattr(f, "dedup_reason", None) or "Unknown",
                "dedup_reason": getattr(f, "dedup_reason", None) or "",
                "occurrences": getattr(f, "occurrence_count", 1),
                "host": f.host,
                "routing_key": f.routing_key,
                "matched_rule": f.enrichment.get("matched_rule", "unknown"),
                "selected_tracker": f.enrichment.get("selected_tracker", "unknown"),
                "source_link": f.enrichment.get("source_url") or f.enrichment.get("defectdojo_url", ""),
                "dedup_key": f.dedup_key,
                "dedup_hash": f.dedup_hash,
            })

        outcome = {
            "stats": {
                "ingested": total_ingested,
                "filtered": total_ingested - after_filter,
                "deduplicated": len(repeat_findings),
                "created": stats.get("created", 0),
                "updated": stats.get("updated", 0),
                "reopened": stats.get("reopened", 0),
                "recreated": stats.get("recreated", 0),
                "queued": stats.get("queued", 0),
                "failed": stats.get("failed", 0),
            },
            "results": results
        }
        self._record_dashboard_event(outcome, event_context)
        return outcome

    def _async_delivery_enabled(self) -> bool:
        """Return whether async Redmine delivery can be used safely."""
        if not self.config.pipeline.delivery.async_enabled:
            return False
        if not self.state_store or not hasattr(self.state_store, "enqueue_outbound_job"):
            logger.warning("Async Redmine delivery is enabled but shared Postgres state is unavailable; using synchronous delivery")
            return False
        return True

    def _deliver_findings(
        self,
        new_findings: list[Finding],
        repeat_findings: list[Finding],
    ) -> tuple[dict[str, int], list[Finding], list[Finding]]:
        """Deliver findings to Redmine synchronously using the current client."""
        logger.info("--- Creating Redmine issues (%d new) ---", len(new_findings))
        create_stats, successful_new = self.redmine.create_issues_batch(new_findings)

        new_ids = {f.dedup_hash: f.redmine_issue_id for f in successful_new if f.redmine_issue_id}
        for rf in repeat_findings:
            if not rf.redmine_issue_id and rf.dedup_hash in new_ids:
                rf.redmine_issue_id = new_ids[rf.dedup_hash]

        update_stats = {"created": 0, "updated": 0, "failed": 0, "reopened": 0, "recreated": 0}
        successful_repeat: list[Finding] = []
        if repeat_findings:
            logger.info(
                "--- Updating Redmine issues (%d repeat, %d total occurrences) ---",
                len(repeat_findings),
                sum(f.occurrence_count for f in repeat_findings),
            )
            update_stats, successful_repeat = self.redmine.create_issues_batch(repeat_findings)

        stats = {
            "created": create_stats.get("created", 0) + update_stats.get("created", 0),
            "updated": create_stats.get("updated", 0) + update_stats.get("updated", 0),
            "reopened": create_stats.get("reopened", 0) + update_stats.get("reopened", 0),
            "recreated": create_stats.get("recreated", 0) + update_stats.get("recreated", 0),
            "failed": create_stats.get("failed", 0) + update_stats.get("failed", 0),
        }
        return stats, successful_new, successful_repeat

    def _enqueue_redmine_jobs(self, new_findings: list[Finding], repeat_findings: list[Finding]) -> dict[str, int]:
        """Queue Wazuh findings for async Redmine delivery in shared Postgres state."""
        assert self.state_store is not None

        queued = 0
        failed = 0
        for action, bucket in (("create_ticket", new_findings), ("update_ticket", repeat_findings)):
            for finding in bucket:
                try:
                    if action == "update_ticket" and not finding.redmine_issue_id:
                        logger.debug(
                            "Skipping queued update for %s because no Redmine issue ID is known yet",
                            finding.dedup_hash,
                        )
                        continue
                    self.redmine._evaluate_routing(finding)
                    finding.action = "queued"
                    job_id = f"{action}:{finding.dedup_hash}"
                    self.state_store.enqueue_outbound_job(
                        job_id=job_id,
                        dedup_hash=finding.dedup_hash,
                        action=action,
                        payload={"finding": finding.to_dict()},
                    )
                    self.state_store.save_ticket_state(
                        finding.dedup_hash,
                        redmine_issue_id=finding.redmine_issue_id,
                        issue_state=finding.issue_state,
                        tracker_id=finding.enrichment.get("selected_tracker"),
                        subject=finding.title,
                        last_delivery_status="queued",
                        payload={"source": finding.source.value, "action": action},
                    )
                    queued += 1
                except Exception as exc:
                    finding.action = "failed"
                    failed += 1
                    logger.error("Failed to enqueue Redmine job for %s: %s", finding.dedup_hash, exc)
        return {"queued": queued, "failed": failed}

    def process_delivery_queue_once(self) -> dict[str, int]:
        """Claim one batch of queued Redmine jobs and process them."""
        if not self.state_store or not hasattr(self.state_store, "claim_outbound_jobs"):
            logger.warning("Delivery queue requested without shared Postgres state")
            return {"claimed": 0, "succeeded": 0, "failed": 0}

        worker_id = f"delivery-{uuid4()}"
        batch_size = self.config.pipeline.delivery.worker_batch_size
        retry_delay = self.config.pipeline.delivery.retry_delay_seconds
        jobs = self.state_store.claim_outbound_jobs(worker_id, limit=batch_size)
        if not jobs:
            return {"claimed": 0, "succeeded": 0, "failed": 0}

        succeeded = 0
        failed = 0
        for job in jobs:
            job_id = job["job_id"]
            try:
                finding_payload = dict(job.get("payload", {}).get("finding", {}) or {})
                finding = Finding.from_dict(finding_payload)
                _, successful = self.redmine.create_issues_batch([finding])
                if not successful:
                    raise RuntimeError("Redmine delivery returned no successful findings")

                delivered = successful[0]
                if job["action"] == "create_ticket":
                    self.dedup_stage.commit_new([delivered])
                else:
                    self.dedup_stage.commit_updates([delivered])

                self.state_store.save_ticket_state(
                    delivered.dedup_hash,
                    redmine_issue_id=delivered.redmine_issue_id,
                    issue_state=delivered.issue_state,
                    tracker_id=delivered.enrichment.get("selected_tracker"),
                    subject=delivered.title,
                    last_ticket_check_at=datetime.now(timezone.utc).isoformat(),
                    last_ticket_seen_at=datetime.now(timezone.utc).isoformat(),
                    last_delivery_status=delivered.action or "succeeded",
                    payload={"source": delivered.source.value, "action": job["action"]},
                )
                self.state_store.mark_outbound_job_succeeded(job_id)
                succeeded += 1
            except Exception as exc:
                failed += 1
                next_attempt_at = (datetime.now(timezone.utc) + timedelta(seconds=retry_delay)).isoformat()
                self.state_store.mark_outbound_job_retry(job_id, str(exc), next_attempt_at=next_attempt_at)
                logger.error("Delivery queue job %s failed: %s", job_id, exc)

        self.dedup_stage.cleanup()
        return {"claimed": len(jobs), "succeeded": succeeded, "failed": failed}

    def run_delivery_worker(self) -> None:
        """Run the outbound Redmine delivery queue in a polling loop."""
        interval = self.config.pipeline.delivery.worker_poll_interval
        logger.info("Starting Redmine delivery worker (poll interval: %ds)", interval)
        self.test_connections()

        while not _shutdown:
            try:
                self.check_config_reload()
                stats = self.process_delivery_queue_once()
                if stats["claimed"] > 0:
                    logger.info(
                        "Delivery worker processed %d queued job(s): %d succeeded, %d failed",
                        stats["claimed"],
                        stats["succeeded"],
                        stats["failed"],
                    )
            except Exception as exc:
                logger.exception("Delivery worker loop failed: %s", exc)

            if _shutdown:
                break

            for _ in range(interval):
                if _shutdown:
                    break
                time.sleep(1)

        logger.info("Delivery worker shutdown complete")
        self.close()

    def run(self) -> None:
        """Run the pipeline in a continuous polling loop."""
        logger.info("Starting middleware pipeline (poll interval: %ds)", self.config.pipeline.poll_interval)
        self.test_connections()

        while not _shutdown:
            try:
                self.check_config_reload()
                self.run_cycle()
            except Exception as e:
                logger.exception("Pipeline cycle failed: %s", e)

            if _shutdown:
                break

            # Re-read interval each cycle so config changes take effect
            interval = self.config.pipeline.poll_interval
            logger.info("Sleeping %d seconds until next cycle...", interval)
            # Sleep in small increments to allow graceful shutdown
            for _ in range(interval):
                if _shutdown:
                    break
                time.sleep(1)

        logger.info("Pipeline shutdown complete")
        self.close()

    def run_once(self) -> dict[str, int]:
        """Run a single pipeline cycle and exit."""
        logger.info("Running single pipeline cycle...")
        self.test_connections()
        result = self.run_cycle()
        self.close()
        return result

    def _record_dashboard_event(self, outcome: dict[str, Any], event_context: dict[str, Any] | None = None) -> None:
        """Persist one dashboard event so polling and webhook paths share history."""
        if not getattr(self, "dashboard_history", None):
            return

        event_context = event_context or {}
        record = {
            "id": str(uuid4()),
            "receive_time": datetime.now(timezone.utc).isoformat(),
            "origin": event_context.get("origin", "pipeline"),
            "alert_count": int(event_context.get("alert_count", outcome["stats"].get("ingested", 0)) or 0),
            "source_counts": event_context.get("source_counts", {}),
            "findings": outcome.get("results", []),
            "stats": outcome.get("stats", {}),
        }
        try:
            self.dashboard_history.append_dashboard_event(record)
        except Exception as exc:
            logger.warning("Failed to persist dashboard event: %s", exc)

    def close(self) -> None:
        """Close open pipeline resources."""
        if getattr(self, "dashboard_history", None) is not None and self.dashboard_history is not self.state_store:
            try:
                self.dashboard_history.close()
            except Exception:
                logger.debug("Dashboard history close failed", exc_info=True)
            self.dashboard_history = None

        if hasattr(self, "dedup_stage") and self.dedup_stage:
            self.dedup_stage.close()
            self.dedup_stage = None

        if getattr(self, "state_store", None) is not None:
            try:
                self.state_store.close()
            except Exception:
                logger.debug("State store close failed", exc_info=True)
            self.state_store = None


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security Middleware Pipeline — Wazuh/DefectDojo → Redmine"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to config file (default: config/config.yaml)",
        default=None,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single cycle and exit (don't loop)",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test connections only, then exit",
    )
    parser.add_argument(
        "--delivery-worker",
        action="store_true",
        help="Run the Redmine outbound delivery worker only",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run pipeline but don't create Redmine issues (log only)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Web UI host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Web UI port to listen on")
    parser.add_argument("--no-web", action="store_true", help="Disable the Web UI and run pipeline only")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Set debug level if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    config = load_config(args.config)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Create pipeline
    pipeline = MiddlewarePipeline(config, config_path=args.config)

    if args.test:
        success = pipeline.test_connections()
        pipeline.close()
        sys.exit(0 if success else 1)

    if args.delivery_worker:
        logger.info("Running Redmine delivery worker only")
        pipeline.run_delivery_worker()
    elif args.once:
        result = pipeline.run_once()
        logger.info("Result: %s", result)
    elif args.no_web:
        logger.info("Running pipeline only (Web UI disabled)")
        pipeline.run()
    else:
        import threading
        from web.server import app as web_app
        
        logger.info("Starting pipeline in background thread...")
        t = threading.Thread(target=pipeline.run, daemon=True)
        t.start()
        
        logger.info(f"Starting Web UI + Webhook Receiver on http://{args.host}:{args.port}")
        # Disable use_reloader to avoid double-starting the background thread
        web_app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)

if __name__ == "__main__":
    main()
