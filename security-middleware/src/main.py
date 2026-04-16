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
from datetime import datetime
from pathlib import Path

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
        self.config_path = config_path or "config/config.yaml"
        self._last_config_mtime = self._get_config_mtime()

        # Source clients
        self.wazuh = WazuhClient(config.wazuh)
        self.defectdojo = DefectDojoClient(config.defectdojo)

        # Pipeline stages
        self.filter_stage = FilterStage(config.pipeline.filter)
        self.severity_mapper = SeverityMapperStage(config.redmine.priority_map)
        self.dedup_stage = DeduplicatorStage(config.pipeline.dedup)
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
                self.config = load_config(self.config_path)
                
                # Re-initialize all clients with new config
                self.wazuh = WazuhClient(self.config.wazuh)
                self.defectdojo = DefectDojoClient(self.config.defectdojo)
                self.filter_stage = FilterStage(self.config.pipeline.filter)
                self.severity_mapper = SeverityMapperStage(self.config.redmine.priority_map)
                
                # Gracefully close old dedup DB connection
                if hasattr(self, 'dedup_stage'):
                    self.dedup_stage.close()
                self.dedup_stage = DeduplicatorStage(self.config.pipeline.dedup)
                
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
        cycle_start = datetime.utcnow()
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

        if self.config.defectdojo.enabled:
            logger.info("--- Ingesting from DefectDojo ---")
            try:
                dd_findings = self.defectdojo.fetch_findings()
                findings.extend(dd_findings)
                logger.info("DefectDojo: %d findings ingested", len(dd_findings))
            except Exception as e:
                logger.error("DefectDojo ingestion failed: %s", e)
        else:
            logger.debug("DefectDojo: disabled, skipping")

        if not findings:
            logger.info("No findings to process this cycle")
            return {"ingested": 0, "filtered": 0, "deduplicated": 0, "output": 0}

        return self.process_batch(findings, cycle_start)

    def process_batch(self, findings: list[Finding], cycle_start: datetime = None) -> dict[str, int]:
        """
        Process a batch of pre-ingested findings through the pipeline:
          filter → map → dedup → enrich → output
        """
        if not cycle_start:
            cycle_start = datetime.utcnow()
            
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
        findings = self.dedup_stage.process(findings)
        after_dedup = len(findings)

        # --- 5. Enrich ---
        logger.info("--- Enriching ---")
        findings = self.enricher.process(findings)

        # --- 6. Output to Redmine ---
        logger.info("--- Creating Redmine issues ---")
        stats = self.redmine.create_issues_batch(findings)

        # --- Summary ---
        elapsed = (datetime.utcnow() - cycle_start).total_seconds()
        logger.info("=" * 60)
        logger.info("Pipeline processing complete in %.1fs", elapsed)
        logger.info(
            "  Ingested: %d | After filter: %d | After dedup: %d | "
            "Created: %d | Updated: %d | Failed: %d",
            total_ingested,
            after_filter,
            after_dedup,
            stats.get("created", 0),
            stats.get("updated", 0),
            stats.get("failed", 0),
        )
        logger.info("=" * 60)

        return {
            "ingested": total_ingested,
            "filtered": total_ingested - after_filter,
            "deduplicated": after_filter - after_dedup,
            "created": stats.get("created", 0),
            "updated": stats.get("updated", 0),
            "failed": stats.get("failed", 0),
        }

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
        self.dedup_stage.close()

    def run_once(self) -> dict[str, int]:
        """Run a single pipeline cycle and exit."""
        logger.info("Running single pipeline cycle...")
        self.test_connections()
        result = self.run_cycle()
        self.dedup_stage.close()
        return result


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
        sys.exit(0 if success else 1)

    if args.once:
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
