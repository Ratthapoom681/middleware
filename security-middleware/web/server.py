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
import os
import sys
from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import threading
import uuid

import yaml
from flask import Flask, jsonify, request, send_from_directory

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.main import MiddlewarePipeline
from src.sources.wazuh_client import WazuhClient

from src.config import (
    AppConfig,
    WazuhConfig,
    DefectDojoConfig,
    RedmineConfig,
    PipelineConfig,
    FilterConfig,
    DedupConfig,
    EnrichmentConfig,
    LoggingConfig,
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
            client = DefectDojoClient(config.defectdojo)
            ok = client.test_connection()
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

        from src.sources.defectdojo_client import DefectDojoClient

        client = DefectDojoClient(config.defectdojo)
        scope_data = client.fetch_scope_data()
        return jsonify({"status": "ok", **scope_data})
    except Exception as e:
        logger.exception("DefectDojo scope synchronization failed")
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
        outcome = pipeline.process_batch(findings)
        pipeline.dedup_stage.close()

        # Log it to our Dashboard Queue
        record = {
            "id": str(uuid.uuid4()),
            "receive_time": datetime.now(timezone.utc).isoformat(),
            "alert_count": len(data),
            "findings": outcome["results"],
            "stats": outcome["stats"]
        }

        WEBHOOK_HISTORY.appendleft(record)

        return jsonify({"status": "ok", "stats": outcome["stats"]}), 200

    except Exception as e:
        logger.exception("Webhook processing failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/webhook/history", methods=["GET"])
def get_webhook_history():
    """
    Returns the last 200 webhook events for the Live Events Dashboard.
    """
    return jsonify({"status": "ok", "history": list(WEBHOOK_HISTORY)}), 200


# ── Webhook Dashboard State ───────────────────────────────────────────

# In-memory rolling log of the last 200 webhook events
WEBHOOK_HISTORY = deque(maxlen=200)

# ── API Routes (Config Manager) ──────────────────────────────────────────

def _config_to_dict(config: AppConfig) -> dict:
    """Convert AppConfig to a plain dict."""
    return {
        "wazuh": asdict(config.wazuh),
        "defectdojo": asdict(config.defectdojo),
        "redmine": asdict(config.redmine),
        "pipeline": {
            "poll_interval": config.pipeline.poll_interval,
            "initial_lookback_minutes": config.pipeline.initial_lookback_minutes,
            "filter": asdict(config.pipeline.filter),
            "dedup": asdict(config.pipeline.dedup),
            "enrichment": asdict(config.pipeline.enrichment),
        },
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
