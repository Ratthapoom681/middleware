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
from dataclasses import asdict
from pathlib import Path

import yaml
from flask import Flask, jsonify, request, send_from_directory

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

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


@app.route("/api/config/backups", methods=["GET"])
def list_backups():
    """List available config backups."""
    backups = []
    if BACKUP_DIR.exists():
        for f in sorted(BACKUP_DIR.glob("config_*.yaml"), reverse=True):
            backups.append({
                "name": f.name,
                "size": f.stat().st_size,
                "modified": f.stat().st_mtime,
            })
    return jsonify({"status": "ok", "backups": backups[:20]})


@app.route("/api/config/restore/<filename>", methods=["POST"])
def restore_backup(filename: str):
    """Restore a config backup."""
    try:
        backup_path = BACKUP_DIR / filename
        if not backup_path.exists():
            return jsonify({"status": "error", "message": "Backup not found"}), 404

        import shutil
        shutil.copy2(backup_path, CONFIG_PATH)
        return jsonify({"status": "ok", "message": f"Restored from {filename}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Helpers ───────────────────────────────────────────────────────────

def _config_to_dict(config: AppConfig) -> dict:
    """Convert AppConfig to a plain dict."""
    return {
        "wazuh": asdict(config.wazuh),
        "defectdojo": asdict(config.defectdojo),
        "redmine": asdict(config.redmine),
        "pipeline": {
            "poll_interval": config.pipeline.poll_interval,
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
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    print(f"\n  Security Middleware Config UI")
    print(f"  Open http://{args.host}:{args.port} in your browser\n")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
