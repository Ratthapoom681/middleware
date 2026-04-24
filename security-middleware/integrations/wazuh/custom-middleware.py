#!/usr/bin/env python3
"""
Wazuh Custom Integration: Forward alerts to Security Middleware.

Wazuh Manager calls this script for each matching alert.
Arguments (provided by the integration engine):
  sys.argv[1]  Path to a temporary file containing the alert JSON
  sys.argv[2]  API key (from <api_key> in ossec.conf)
  sys.argv[3]  Webhook URL (from <hook_url> in ossec.conf)
"""

import json
import sys
import os
import logging
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_SECONDS = 10
VERIFY_SSL = False  # Set True if middleware uses a trusted certificate


def log(level: str, msg: str) -> None:
    """Append a log line to the integrations log file and stderr."""
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    entry = f"{timestamp} custom-middleware: {level}: {msg}"
    
    # Print to stderr so it appears in Wazuh's ossec.log
    sys.stderr.write(entry + "\n")
    sys.stderr.flush()

    # Log to file
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except Exception:
        pass


def send_with_requests(url: str, headers: dict, payload: dict) -> None:
    """Send alert using the 'requests' library."""
    response = requests.post(
        url,
        json=payload,
        headers=headers,
        timeout=TIMEOUT_SECONDS,
        verify=VERIFY_SSL,
    )
    if response.status_code < 200 or response.status_code >= 300:
        raise Exception(
            f"HTTP {response.status_code}: {response.text[:200]}"
        )
    log("INFO", f"Alert forwarded successfully (HTTP {response.status_code})")


def send_with_urllib(url: str, headers: dict, payload: dict) -> None:
    """Fallback: send alert using Python's built-in urllib."""
    import urllib.request
    import ssl

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    ctx = None
    if not VERIFY_SSL:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=ctx) as resp:
        status = resp.getcode()
        if status < 200 or status >= 300:
            body = resp.read().decode("utf-8", errors="replace")[:200]
            raise Exception(f"HTTP {status}: {body}")
    log("INFO", f"Alert forwarded successfully (urllib, HTTP {status})")


def main():
    # --- Debug: log all arguments ---
    # log("DEBUG", f"Received arguments: {sys.argv}")

    # --- Parse arguments ---
    if len(sys.argv) < 4:
        log("ERROR", f"Expected at least 3 arguments, got {len(sys.argv) - 1}. Full argv: {sys.argv}")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    api_key = sys.argv[2]
    webhook_url = sys.argv[3]

    # --- Read alert JSON ---
    try:
        with open(alert_file_path, "r") as f:
            alert = json.load(f)
    except Exception as e:
        log("ERROR", f"Failed to read alert file {alert_file_path}: {e}")
        sys.exit(1)

    # --- Build request ---
    headers = {"Content-Type": "application/json"}
    if api_key and api_key.lower() != "none" and api_key.strip() != "":
        headers["X-API-Key"] = api_key

    # --- Send ---
    try:
        if HAS_REQUESTS:
            send_with_requests(webhook_url, headers, alert)
        else:
            send_with_urllib(webhook_url, headers, alert)
    except Exception as e:
        log("ERROR", f"Failed to forward alert to {webhook_url}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
