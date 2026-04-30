#!/usr/bin/env python3
"""
Simulate Wazuh calling the custom integration script with Fortigate alerts.

This writes Wazuh indexer-hit JSON files based on the Fortigate sample, then
invokes:
  integrations/custom-security-middleware <alert_file> <api_key> <hook_url>
"""

from __future__ import annotations

import argparse
import copy
import errno
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCRIPT = PROJECT_ROOT / "integrations" / "custom-security-middleware"
DEFAULT_SAMPLE = PROJECT_ROOT / "samples" / "wazuh_fortigate_failed_login_indexer_hit.json"
DEFAULT_URL = "http://127.0.0.1:5000/api/webhook/wazuh"
USE_CASES = ("brute-force", "abnormal-port", "impossible-travel", "port-scan")


def load_sample(sample_path: Path) -> dict:
    with sample_path.open("r", encoding="utf-8") as sample_file:
        sample = json.load(sample_file)
    if not isinstance(sample.get("_source"), dict):
        raise ValueError(f"sample must be a Wazuh indexer hit with _source: {sample_path}")
    return sample


def default_count_for_use_case(use_case: str) -> int:
    if use_case == "brute-force":
        return 5
    if use_case == "abnormal-port":
        return 1
    if use_case == "impossible-travel":
        return 2
    if use_case == "port-scan":
        return 16
    return 1


def expand_use_cases(use_case: str) -> list[str]:
    return list(USE_CASES) if use_case == "all" else [use_case]


def build_alert(
    sample: dict,
    *,
    global_index: int,
    scenario: str,
    scenario_index: int,
    srcip: str,
    agent_name: str,
    payload_format: str,
) -> dict:
    hit = copy.deepcopy(sample)
    alert = hit["_source"]
    now = datetime.now(timezone.utc) + timedelta(seconds=scenario_index)
    epoch_ms = int(now.timestamp() * 1000)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

    data = alert.setdefault("data", {})
    rule = alert.setdefault("rule", {})
    geo = alert.setdefault("GeoLocation", {})

    alert["timestamp"] = timestamp
    alert["id"] = f"simulate-{scenario}-{int(time.time())}-{scenario_index}"
    alert["agent"] = {"id": "000", "name": agent_name}
    rule["firedtimes"] = scenario_index
    rule["level"] = 4
    rule["description"] = "Fortigate: Login failed."
    rule["groups"] = ["fortigate", "syslog", "authentication_failed", "invalid_login"]
    rule["id"] = "81606"

    data["srcip"] = srcip
    data["ip"] = srcip
    data["dstip"] = data.get("dstip") or "223.27.209.82"
    data["dstuser"] = data.get("dstuser") or "admin"
    data["action"] = "login"
    data["status"] = "failed"
    data["method"] = "https"
    data["protocol"] = data.get("protocol") or "\"https\""
    data["time"] = now.strftime("%H:%M:%S")
    data["msg"] = f"Administrator {data['dstuser']} login failed from https({srcip}) because of blocked IP"

    if scenario == "abnormal-port":
        data["dstport"] = "4444"
        data["service"] = "tcp/4444"
        data["msg"] = f"Fortigate suspicious connection from {srcip} to {data['dstip']}:4444"
        rule["description"] = "Fortigate: Suspicious port connection."
        rule["groups"] = ["fortigate", "syslog", "network", "connection"]
    elif scenario == "impossible-travel":
        countries = [
            ("Bulgaria", "85.11.187.20", "Sofia"),
            ("Thailand", "49.229.120.10", "Bangkok"),
        ]
        country, country_srcip, city = countries[(scenario_index - 1) % len(countries)]
        data["srcip"] = country_srcip
        data["ip"] = country_srcip
        data["dstuser"] = "admin"
        data["msg"] = f"Administrator admin login failed from https({country_srcip}) because of blocked IP"
        geo["country_name"] = country
        geo["city_name"] = city
    elif scenario == "port-scan":
        data["dstport"] = str(20000 + scenario_index)
        data["service"] = f"tcp/{data['dstport']}"
        data["msg"] = f"Fortigate connection attempt from {srcip} to {data['dstip']}:{data['dstport']}"
        rule["description"] = "Fortigate: Multiple destination ports."
        rule["groups"] = ["fortigate", "syslog", "network", "connection"]

    alert["full_log"] = (
        f"devname=\"{data.get('devname', 'BCH-FG80F_NS2')}\" "
        f"srcip={data['srcip']} dstip={data.get('dstip', '')} "
        f"dstport={data.get('dstport', '')} action=\"{data.get('action', '')}\" "
        f"status=\"{data.get('status', '')}\" msg=\"{data.get('msg', '')}\""
    )

    if payload_format == "raw":
        return alert

    date_suffix = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    hit["_index"] = f"wazuh-alerts-4.x-{date_suffix}"
    hit["_id"] = f"simulate-{scenario}-{epoch_ms}-{global_index}"
    hit["_score"] = None
    hit["fields"] = {"timestamp": [now.isoformat().replace("+00:00", "Z")]}
    hit["sort"] = [epoch_ms]
    return hit


def invoke_integration(script: Path, alert_path: Path, api_key: str, url: str) -> subprocess.CompletedProcess:
    if sys.platform.startswith("win"):
        command = [sys.executable, str(script), str(alert_path), api_key, url]
    else:
        command = [str(script), str(alert_path), api_key, url]
    try:
        return subprocess.run(command, text=True, capture_output=True, check=False)
    except PermissionError as exc:
        if exc.errno != errno.EACCES:
            raise
        fallback = [sys.executable, str(script), str(alert_path), api_key, url]
        return subprocess.run(fallback, text=True, capture_output=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate Wazuh custom integration webhook delivery")
    parser.add_argument("--url", default=DEFAULT_URL, help="Middleware Wazuh webhook URL")
    parser.add_argument("--script", default=str(DEFAULT_SCRIPT), help="Path to custom-security-middleware script")
    parser.add_argument("--sample", default=str(DEFAULT_SAMPLE), help="Fortigate Wazuh indexer-hit sample JSON")
    parser.add_argument(
        "--usecase",
        choices=[*USE_CASES, "all"],
        default="brute-force",
        help="Detection use case to simulate",
    )
    parser.add_argument("--count", type=int, default=0, help="Override number of alerts to send per use case")
    parser.add_argument("--srcip", default="85.11.187.20", help="Source IP for grouped use cases")
    parser.add_argument("--agent", default="wazuh-server", help="Wazuh agent name")
    parser.add_argument("--api-key", default="", help="Optional API key argument passed by Wazuh")
    parser.add_argument("--interval", type=float, default=0.1, help="Seconds between alerts")
    parser.add_argument("--format", choices=["indexer", "raw"], default="indexer", help="Payload shape to send")
    args = parser.parse_args()

    script = Path(args.script).resolve()
    if not script.exists():
        print(f"Integration script not found: {script}", file=sys.stderr)
        return 2

    sample = load_sample(Path(args.sample).resolve())
    scenarios = expand_use_cases(args.usecase)
    total = sum(args.count or default_count_for_use_case(scenario) for scenario in scenarios)

    failures = 0
    sent = 0
    with tempfile.TemporaryDirectory(prefix="wazuh-integration-") as temp_dir:
        temp_path = Path(temp_dir)
        for scenario in scenarios:
            scenario_count = args.count or default_count_for_use_case(scenario)
            print(f"Simulating {scenario}: {scenario_count} Fortigate alert(s)")
            for index in range(1, scenario_count + 1):
                sent += 1
                alert = build_alert(
                    sample,
                    global_index=sent,
                    scenario=scenario,
                    scenario_index=index,
                    srcip=args.srcip,
                    agent_name=args.agent,
                    payload_format=args.format,
                )
                alert_path = temp_path / f"{scenario}-{index}.json"
                alert_path.write_text(json.dumps(alert, indent=2), encoding="utf-8")

                result = invoke_integration(script, alert_path, args.api_key, args.url)
                alert_id = alert.get("_source", alert).get("id", alert.get("_id", "unknown"))
                if result.returncode == 0:
                    print(f"[{sent}/{total}] delivered {scenario} alert {alert_id} to {args.url}")
                else:
                    failures += 1
                    print(
                        f"[{sent}/{total}] FAILED {scenario} alert {alert_id} exit={result.returncode}",
                        file=sys.stderr,
                    )
                    if result.stdout:
                        print(result.stdout.rstrip(), file=sys.stderr)
                    if result.stderr:
                        print(result.stderr.rstrip(), file=sys.stderr)

                if sent < total:
                    time.sleep(args.interval)

    if failures:
        print(f"{failures} alert(s) failed", file=sys.stderr)
        return 1

    print("Simulation complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
