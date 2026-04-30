"""
Configuration Web UI Server.

A lightweight Flask app that serves a web-based configuration editor
for the Security Middleware Pipeline.

Run:  python -m web.server
      python -m web.server --port 8888
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import threading

import yaml
from flask import Flask, jsonify, request, send_from_directory

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.main import MiddlewarePipeline
from src.state_store import create_state_store
from src.sources.wazuh_client import WazuhClient
from src.pipeline.detection_store import DetectionAlertStore
from src.output.redmine_client import RedmineClient

from src.config import (
    AppConfig,
    load_config,
    _build_config,
)

logger = logging.getLogger(__name__)

CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"
BACKUP_DIR = PROJECT_ROOT / "config" / "backups"
STATIC_DIR = PROJECT_ROOT / "web" / "static"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")


# ── API Endpoints ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/config", methods=["GET"])
def get_config():
    """Return the current config as JSON."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        else:
            raw = {}

        # Build typed config to fill in defaults, then convert to dict
        config = _build_config(raw)
        config_dict = _config_to_dict(config)
        return jsonify({"status": "ok", "config": config_dict, "path": str(CONFIG_PATH)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config", methods=["POST"])
def save_config():
    """Save config from JSON body to config.yaml."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No JSON body"}), 400

        # Create backup
        if CONFIG_PATH.exists():
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            import shutil
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"config_{ts}.yaml"
            shutil.copy2(CONFIG_PATH, backup_path)
            logger.info("Config backup saved to %s", backup_path)

        # Validate by building typed config
        config = _build_config(data)

        # Write YAML
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        yaml_content = _build_yaml(data)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        return jsonify({"status": "ok", "message": "Configuration saved successfully", "path": str(CONFIG_PATH)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config/raw", methods=["GET"])
def get_config_raw():
    """Return the raw config.yaml text."""
    try:
        content = ""
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                content = f.read()
        return jsonify({"status": "ok", "content": content})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config/raw", methods=["POST"])
def save_config_raw():
    """Save raw YAML text directly to config.yaml."""
    try:
        yaml_content = request.get_data(as_text=True)
        # Validate that it's parseable YAML
        data = yaml.safe_load(yaml_content)
        # Validate schema
        _build_config(data or {})

        # Create backup
        if CONFIG_PATH.exists():
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            import shutil
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_raw")
            shutil.copy2(CONFIG_PATH, BACKUP_DIR / f"config_{ts}.yaml")

        # Write YAML directly
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        return jsonify({"status": "ok", "message": "Raw YAML saved successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/config/backups", methods=["GET"])
def get_backups():
    """Return a list of available configuration backups."""
    try:
        backups = []
        if BACKUP_DIR.exists() and BACKUP_DIR.is_dir():
            for f in BACKUP_DIR.glob("*.yaml"):
                stat = f.stat()
                backups.append({
                    "filename": f.name,
                    "timestamp": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    "size": stat.st_size
                })
        # Sort newest first
        backups.sort(key=lambda x: x["timestamp"], reverse=True)
        return jsonify({"status": "ok", "backups": backups})
    except Exception as e:
        logger.exception("Error listing backups")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config/backups/restore/<filename>", methods=["POST"])
def restore_backup(filename: str):
    """Restore a specific backup over the active config."""
    try:
        # Basic sanitization
        if "/" in filename or "\\" in filename or ".." in filename:
            return jsonify({"status": "error", "message": "Invalid filename"}), 400
            
        backup_path = BACKUP_DIR / filename
        if not backup_path.exists() or not backup_path.is_file():
            return jsonify({"status": "error", "message": "Backup not found"}), 404

        import shutil
        # Create a pre-restore safety backup of current config if it exists
        if CONFIG_PATH.exists():
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_prerestore")
            shutil.copy2(CONFIG_PATH, BACKUP_DIR / f"config_{ts}.yaml")

        # Perform the actual restore
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, CONFIG_PATH)
        
        logger.info("Restored configuration from %s", backup_path)
        return jsonify({"status": "ok", "message": f"Successfully restored {filename}"})
    except Exception as e:
        logger.exception("Failed to restore backup")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config/validate", methods=["POST"])
def validate_config():
    """Validate config without saving."""
    try:
        data = request.get_json()
        config = _build_config(data or {})
        issues = _validate_config(data or {})
        return jsonify({
            "status": "ok" if not issues else "warning",
            "valid": True,
            "issues": issues,
        })
    except Exception as e:
        return jsonify({"status": "error", "valid": False, "message": str(e)}), 400


@app.route("/api/config/test/<service>", methods=["POST"])
def test_connection(service: str):
    """Test connection to a specific service."""
    try:
        data = request.get_json() or {}
        config = _build_config(data)

        if service == "wazuh":
            from src.sources.wazuh_client import WazuhClient
            client = WazuhClient(config.wazuh)
            ok = client.test_connection()
        elif service == "defectdojo":
            from src.sources.defectdojo_client import DefectDojoClient
            state_store = create_state_store(config.storage)
            try:
                client = DefectDojoClient(config.defectdojo, checkpoint_store=state_store)
                ok = client.test_connection()
            finally:
                if state_store:
                    state_store.close()
        elif service == "redmine":
            from src.output.redmine_client import RedmineClient
            client = RedmineClient(config.redmine)
            ok = client.test_connection()
        else:
            return jsonify({"status": "error", "message": f"Unknown service: {service}"}), 400

        return jsonify({
            "status": "ok" if ok else "error",
            "service": service,
            "connected": ok,
            "message": f"{service} connection {'successful' if ok else 'failed'}",
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "service": service,
            "connected": False,
            "message": str(e),
        }), 500


@app.route("/api/redmine/trackers", methods=["POST"])
def fetch_redmine_trackers():
    """Fetch available tracking scopes directly from Redmine."""
    try:
        data = request.get_json() or {}
        config = _build_config(data)

        from src.output.redmine_client import RedmineClient
        client = RedmineClient(config.redmine)
        trackers = client.get_trackers()

        if not trackers:
             return jsonify({
                 "status": "error", 
                 "message": "Failed to authenticate or zero trackers found. Ensure token and URL are valid."
             }), 400

        return jsonify({"status": "ok", "trackers": trackers})
    except Exception as e:
        logger.exception("Redmine tracker synchronization failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/defectdojo/scope-data", methods=["POST"])
def fetch_defectdojo_scope_data():
    """Fetch products, engagements, and tests for the DefectDojo UI selectors."""
    try:
        data = request.get_json() or {}
        config = _build_config(data)

        from src.sources.defectdojo_client import DefectDojoAPIError, DefectDojoClient

        state_store = create_state_store(config.storage)
        try:
            client = DefectDojoClient(config.defectdojo, checkpoint_store=state_store)
            scope_data = client.fetch_scope_data()
        finally:
            if state_store:
                state_store.close()
        return jsonify({"status": "ok", **scope_data})
    except DefectDojoAPIError as e:
        logger.warning("DefectDojo scope synchronization failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        logger.exception("DefectDojo scope synchronization failed")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/defectdojo/finding-count", methods=["POST"])
def preview_defectdojo_finding_count():
    """Return a lightweight count preview for the current DefectDojo filters."""
    try:
        data = request.get_json() or {}
        config = _build_config(data)

        from src.sources.defectdojo_client import DefectDojoAPIError, DefectDojoClient

        state_store = create_state_store(config.storage)
        try:
            client = DefectDojoClient(config.defectdojo, checkpoint_store=state_store)
            summary = client.get_finding_count_summary()
        finally:
            if state_store:
                state_store.close()
        return jsonify({"status": "ok", **summary})
    except DefectDojoAPIError as e:
        logger.warning("DefectDojo finding count preview failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        logger.exception("DefectDojo finding count preview failed")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/webhook/wazuh", methods=["POST"])
def wazuh_webhook():
    """
    Receive alerts directly from Wazuh Integrations (Push Model).
    Wazuh sends a JSON array (or single object) of rules/alerts.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No JSON payload"}), 400

        # Wazuh integrations can send a dict or list
        if not isinstance(data, list):
            data = [data]

        # Load current config
        config = load_config(str(CONFIG_PATH) if CONFIG_PATH.exists() else None)
        
        # We need the WazuhClient just to reuse the parser logic
        wazuh_client = WazuhClient(config.wazuh)
        
        findings = []
        for alert in data:
            finding = wazuh_client._alert_to_finding(alert)
            if finding:
                findings.append(finding)

        if not findings:
            return jsonify({"status": "ok", "message": "No meaningful alerts found in payload"}), 200

        # Process the batch ad-hoc
        pipeline = MiddlewarePipeline(config)
        try:
            if pipeline._store_first_ingest_enabled():
                event_ids = pipeline.persist_ingested_findings(findings)
                remaining_event_ids = list(event_ids)
                aggregated_stats = {
                    "ingested": 0,
                    "filtered": 0,
                    "deduplicated": 0,
                    "created": 0,
                    "updated": 0,
                    "reopened": 0,
                    "recreated": 0,
                    "queued": 0,
                    "failed": 0,
                }

                while remaining_event_ids:
                    outcome = pipeline.process_ingest_queue_once(
                        event_context={
                            "origin": "webhook",
                            "alert_count": len(data),
                            "source_counts": {"wazuh": len(findings)},
                        },
                        event_ids=remaining_event_ids,
                    )
                    if not outcome:
                        break
                    for key, value in outcome.get("stats", {}).items():
                        aggregated_stats[key] = aggregated_stats.get(key, 0) + int(value or 0)
                    processed_event_ids = set(outcome.get("event_ids", []))
                    remaining_event_ids = [
                        event_id for event_id in remaining_event_ids if event_id not in processed_event_ids
                    ]
                    if not outcome.get("successful", False):
                        break

                outcome = {"stats": aggregated_stats}
                outcome["stats"]["persisted"] = len(event_ids)
            else:
                outcome = pipeline.process_batch(
                    findings,
                    event_context={
                        "origin": "webhook",
                        "alert_count": len(data),
                        "source_counts": {"wazuh": len(findings)},
                    },
                )
        finally:
            pipeline.close()

        return jsonify({"status": "ok", "stats": outcome["stats"]}), 200

    except Exception as e:
        logger.exception("Webhook processing failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500




# ── Detection API Endpoints ──────────────────────────────────────────

def _get_detection_store() -> DetectionAlertStore:
    """Create a DetectionAlertStore from current config."""
    config = load_config(str(CONFIG_PATH) if CONFIG_PATH.exists() else None)
    return DetectionAlertStore(db_path=config.pipeline.detection.db_path)


def _check_alerts_against_redmine(
    alerts: list[dict],
    store: DetectionAlertStore,
    config: AppConfig,
) -> list[dict]:
    """Refresh Redmine linkage for returned detection alerts."""
    redmine = RedmineClient(config.redmine)
    refreshed: list[dict] = []
    for alert in alerts:
        issue_id = alert.get("redmine_issue_id")
        if not issue_id:
            refreshed.append(alert)
            continue

        try:
            redmine_status = redmine.check_issue(int(issue_id))
            exists = bool(redmine_status.get("exists"))
            is_closed = bool(redmine_status.get("is_closed")) if redmine_status.get("is_closed") is not None else False
            local_resolved = (not exists) or is_closed
            store.update_redmine_issue(
                str(alert["id"]),
                issue_id=int(issue_id),
                exists=exists,
                status=str(redmine_status.get("status") or ("open" if exists else "deleted")),
                resolved=local_resolved,
            )
            refreshed_alert = store.get_alert_by_id(str(alert["id"]))
            refreshed.append(refreshed_alert or alert)
        except Exception as exc:
            logger.warning(
                "Failed to refresh Redmine issue #%s for detection alert %s: %s",
                issue_id,
                alert.get("id"),
                exc,
            )
            refreshed.append(alert)

    return refreshed


@app.route("/api/detection/alerts", methods=["GET"])
def get_detection_alerts():
    """List detection alerts with optional filters."""
    try:
        config = load_config(str(CONFIG_PATH) if CONFIG_PATH.exists() else None)
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)
        rule_type = request.args.get("rule_type")
        severity = request.args.get("severity")
        acknowledged = request.args.get("acknowledged")
        resolved = request.args.get("resolved")
        check_redmine = request.args.get("check_redmine", "0") in {"1", "true", "yes"}

        store = DetectionAlertStore(db_path=config.pipeline.detection.db_path)
        try:
            alerts = store.get_alerts(
                limit=limit,
                offset=offset,
                rule_type=rule_type or None,
                severity=severity or None,
                acknowledged=bool(int(acknowledged)) if acknowledged is not None else None,
                resolved=bool(int(resolved)) if resolved is not None else None,
            )
            if check_redmine:
                alerts = _check_alerts_against_redmine(alerts, store, config)
        finally:
            store.close()

        return jsonify({"status": "ok", "alerts": alerts, "count": len(alerts)})
    except Exception as e:
        logger.exception("Failed to fetch detection alerts")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/detection/alerts/stats", methods=["GET"])
def get_detection_stats():
    """Get aggregate detection alert statistics."""
    try:
        store = _get_detection_store()
        try:
            stats = store.get_stats()
        finally:
            store.close()
        return jsonify({"status": "ok", "stats": stats})
    except Exception as e:
        logger.exception("Failed to fetch detection stats")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/detection/alerts/<alert_id>/acknowledge", methods=["POST"])
def acknowledge_detection_alert(alert_id: str):
    """Mark a detection alert as acknowledged."""
    try:
        store = _get_detection_store()
        try:
            ok = store.acknowledge_alert(alert_id)
        finally:
            store.close()

        if ok:
            return jsonify({"status": "ok", "message": f"Alert {alert_id} acknowledged"})
        else:
            return jsonify({"status": "error", "message": "Alert not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/detection/alerts/<alert_id>/resolve", methods=["POST"])
def resolve_detection_alert(alert_id: str):
    """Mark a detection alert as resolved."""
    try:
        store = _get_detection_store()
        try:
            ok = store.resolve_alert(alert_id)
        finally:
            store.close()

        if ok:
            return jsonify({"status": "ok", "message": f"Alert {alert_id} resolved"})
        else:
            return jsonify({"status": "error", "message": "Alert not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/detection/alerts/<alert_id>/check-redmine", methods=["POST"])
def check_detection_alert_redmine(alert_id: str):
    """Check whether the Redmine issue linked to a detection alert still exists."""
    try:
        config = load_config(str(CONFIG_PATH) if CONFIG_PATH.exists() else None)
        store = DetectionAlertStore(db_path=config.pipeline.detection.db_path)
        try:
            alert = store.get_alert_by_id(alert_id)
            if not alert:
                return jsonify({"status": "error", "message": "Alert not found"}), 404

            issue_id = alert.get("redmine_issue_id")
            if not issue_id:
                return jsonify({
                    "status": "ok",
                    "message": "No Redmine issue is linked to this detection alert",
                    "redmine": {"exists": None, "issue_id": None, "status": "not_linked"},
                    "alert": alert,
                })

            redmine_status = RedmineClient(config.redmine).check_issue(int(issue_id))
            exists = bool(redmine_status.get("exists"))
            is_closed = bool(redmine_status.get("is_closed")) if redmine_status.get("is_closed") is not None else False
            local_resolved = (not exists) or is_closed
            store.update_redmine_issue(
                alert_id,
                issue_id=int(issue_id),
                exists=exists,
                status=str(redmine_status.get("status") or ("open" if exists else "deleted")),
                resolved=local_resolved,
            )
            updated_alert = store.get_alert_by_id(alert_id)
        finally:
            store.close()

        message = "Redmine issue exists"
        if not exists:
            message = "Redmine issue is missing; detection alert marked resolved"
        elif is_closed:
            message = "Redmine issue is closed; detection alert marked resolved"

        return jsonify({
            "status": "ok",
            "message": message,
            "redmine": redmine_status,
            "alert": updated_alert,
        })
    except Exception as e:
        logger.exception("Failed to check Redmine issue for detection alert")
        return jsonify({"status": "error", "message": str(e)}), 500


# ── API Routes (Config Manager) ──────────────────────────────────────────

def _config_to_dict(config: AppConfig) -> dict:
    """Convert AppConfig to a plain dict."""
    detection_dict = {
        "enabled": config.pipeline.detection.enabled,
        "alert_ttl_hours": config.pipeline.detection.alert_ttl_hours,
        "max_state_entries": config.pipeline.detection.max_state_entries,
        "db_path": config.pipeline.detection.db_path,
        "rules": [
            {
                "name": r.name,
                "type": r.type,
                "enabled": r.enabled,
                "severity": r.severity,
                "parameters": r.parameters,
                "cooldown_seconds": r.cooldown_seconds,
                "create_ticket": r.create_ticket,
            }
            for r in config.pipeline.detection.rules
        ],
    }
    return {
        "wazuh": asdict(config.wazuh),
        "defectdojo": asdict(config.defectdojo),
        "redmine": asdict(config.redmine),
        "pipeline": {
            "poll_interval": config.pipeline.poll_interval,
            "initial_lookback_minutes": config.pipeline.initial_lookback_minutes,
            "filter": asdict(config.pipeline.filter),
            "dedup": asdict(config.pipeline.dedup),
            "delivery": asdict(config.pipeline.delivery),
            "enrichment": asdict(config.pipeline.enrichment),
            "detection": detection_dict,
        },
        "storage": asdict(config.storage),
        "logging": asdict(config.logging),
    }


def _validate_config(data: dict) -> list[str]:
    """Return a list of config issues/warnings."""
    issues = []
    w = data.get("wazuh", {})
    d = data.get("defectdojo", {})
    r = data.get("redmine", {})
    p = data.get("pipeline", {})

    if w.get("password") in ("changeme", "", None):
        issues.append("Wazuh password is set to default")
    if d.get("api_key") in ("Token changeme", "", None):
        issues.append("DefectDojo API key is set to default")
    if r.get("api_key") in ("changeme", "", None):
        issues.append("Redmine API key is set to default")
    if not w.get("base_url"):
        issues.append("Wazuh base URL is empty")
    if not d.get("base_url"):
        issues.append("DefectDojo base URL is empty")
    if not r.get("base_url"):
        issues.append("Redmine base URL is empty")
    if (
        not d.get("product_ids")
        and not d.get("engagement_ids")
        and not d.get("test_ids")
        and int(d.get("updated_since_minutes", 0) or 0) == 0
    ):
        issues.append("DefectDojo scope is very broad: no Product/Engagement/Test filters and Updated Since is 0")
    if int(d.get("fetch_limit", 0) or 0) > 0 and not d.get("cursor_path"):
        issues.append("DefectDojo fetch_limit is set without checkpoint-backed incremental sync")

    poll = p.get("poll_interval", 300)
    if isinstance(poll, int) and poll < 30:
        issues.append(f"Poll interval ({poll}s) is very low, may cause rate limiting")

    dedup = p.get("dedup", {})
    ttl = dedup.get("ttl_hours", 168)
    if isinstance(ttl, int) and ttl < 1:
        issues.append("Dedup TTL is less than 1 hour")

    filter_cfg = p.get("filter", {})
    if filter_cfg.get("default_action") == "drop" and not filter_cfg.get("json_rules"):
        issues.append("Advanced filter default action is 'drop' but no JSON rules are configured")

    storage = data.get("storage", {})
    if storage.get("backend") == "postgres" and not storage.get("postgres_dsn"):
        issues.append("Storage backend is set to postgres but postgres_dsn is empty")

    return issues


def _build_yaml(data: dict) -> str:
    """Build a human-readable YAML string with comments."""
    lines = [
        "# ============================================================",
        "# Security Middleware Pipeline - Configuration",
        "# ============================================================",
        "",
    ]

    def _dump_section(title, key, data_section):
        lines.append(f"# --- {title} ---")
        lines.append(yaml.dump({key: data_section}, default_flow_style=False, sort_keys=False).rstrip())
        lines.append("")

    _dump_section("Wazuh SIEM", "wazuh", data.get("wazuh", {}))
    _dump_section("DefectDojo Vulnerability Management", "defectdojo", data.get("defectdojo", {}))
    _dump_section("Redmine Issue Tracker", "redmine", data.get("redmine", {}))
    _dump_section("Pipeline Settings", "pipeline", data.get("pipeline", {}))
    _dump_section("Shared State Storage", "storage", data.get("storage", {}))
    _dump_section("Logging", "logging", data.get("logging", {}))

    return "\n".join(lines) + "\n"


# ── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Security Middleware Config Web UI")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--background-polling", action="store_true", help="Run background pipeline poller")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    
    if args.background_polling:
        logger.info("Starting background pipeline poller thread...")
        config = load_config(str(CONFIG_PATH) if CONFIG_PATH.exists() else None)
        pipeline = MiddlewarePipeline(config)
        # Daemon thread will die when flask dies
        t = threading.Thread(target=pipeline.run, daemon=True)
        t.start()

    print(f"\n  Security Middleware Config UI & Webhook Receiver")
    print(f"  Open http://{args.host}:{args.port} in your browser")
    print(f"  Webhook URL: http://{args.host}:{args.port}/api/webhook/wazuh\n")
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False if args.background_polling else True)


if __name__ == "__main__":
    main()
