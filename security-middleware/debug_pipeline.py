"""
Debug Pipeline Runner -- Terminal Debug Messages for All Main Features.

Run with:  python debug_pipeline.py
           python debug_pipeline.py --stage filter
           python debug_pipeline.py --stage dedup
           python debug_pipeline.py --verbose

Exercises each pipeline stage with mock data and prints rich,
color-coded diagnostic output to the terminal.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# Enable ANSI escape codes and UTF-8 on Windows
if sys.platform == "win32":
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# --- ANSI color helpers -------------------------------------------------------
class C:
    """ANSI color/style codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"


def banner(text: str, color: str = C.CYAN) -> None:
    w = 70
    print()
    print(f"{color}{C.BOLD}{'=' * w}{C.RESET}")
    print(f"{color}{C.BOLD}  {text}{C.RESET}")
    print(f"{color}{C.BOLD}{'=' * w}{C.RESET}")


def section(text: str, color: str = C.YELLOW) -> None:
    print(f"\n{color}{C.BOLD}-- {text} --{C.RESET}")


def info(label: str, value: str, color: str = C.WHITE) -> None:
    print(f"  {C.GRAY}|{C.RESET} {C.BOLD}{label}:{C.RESET} {color}{value}{C.RESET}")


def ok(msg: str) -> None:
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {C.RED}[x]{C.RESET} {msg}")


def dbg(msg: str) -> None:
    print(f"  {C.GRAY}    -> {msg}{C.RESET}")


def finding_card(f, index: int = 0) -> None:
    """Pretty-print a single Finding."""
    sev_colors = {
        "critical": C.RED,
        "high":     C.YELLOW,
        "medium":   C.MAGENTA,
        "low":      C.BLUE,
        "info":     C.GRAY,
    }
    sc = sev_colors.get(f.severity.value, C.WHITE)
    print(f"  {C.GRAY}|{C.RESET}")
    print(
        f"  {C.GRAY}|{C.RESET}  "
        f"{C.BOLD}[{index + 1}]{C.RESET} "
        f"{sc}{C.BOLD}{f.severity.value.upper():8s}{C.RESET} "
        f"{f.title[:55]}"
    )
    print(
        f"  {C.GRAY}|{C.RESET}     "
        f"source={C.CYAN}{f.source.value}{C.RESET}  "
        f"host={C.CYAN}{f.host or 'N/A'}{C.RESET}  "
        f"hash={C.DIM}{f.dedup_hash[:12]}...{C.RESET}"
    )


# --- Mock finding factory -----------------------------------------------------
from app.models.finding import Finding, FindingSource, Severity  # noqa: E402


def make_findings() -> list[Finding]:
    """Create a realistic set of mock findings for debug purposes."""
    return [
        # 1 - Wazuh: high-level SSH brute force
        Finding(
            source=FindingSource.WAZUH,
            source_id="wazuh-5001",
            title="SSH brute force attempt",
            description="Multiple failed SSH logins from 203.0.113.42",
            severity=Severity.HIGH,
            raw_severity="13",
            host="web-server-01",
            rule_id="5710",
            rule_groups=["sshd", "authentication"],
            tags=["sshd", "authentication"],
            timestamp=datetime.now(timezone.utc),
        ),
        # 2 - Wazuh: low-level syslog noise
        Finding(
            source=FindingSource.WAZUH,
            source_id="wazuh-5002",
            title="Syslog rotation completed",
            description="Log rotation ran on schedule",
            severity=Severity.INFO,
            raw_severity="2",
            host="web-server-01",
            rule_id="100",
            rule_groups=["syslog"],
            tags=["syslog"],
            timestamp=datetime.now(timezone.utc),
        ),
        # 3 - DefectDojo: critical CVE
        Finding(
            source=FindingSource.DEFECTDOJO,
            source_id="dd-42",
            title="CVE-2024-1234 - Remote Code Execution in OpenSSL",
            description="A critical RCE vulnerability in OpenSSL 1.1.1",
            severity=Severity.CRITICAL,
            raw_severity="Critical",
            host="db-master",
            cvss=9.8,
            cve_ids=["CVE-2024-1234"],
            tags=["webapp", "scan:SAST"],
            timestamp=datetime.now(timezone.utc),
        ),
        # 4 - DefectDojo: medium, lowercase severity (the bug we fixed)
        Finding(
            source=FindingSource.DEFECTDOJO,
            source_id="dd-99",
            title="Information disclosure via HTTP headers",
            description="Server banner reveals version info",
            severity=Severity.MEDIUM,
            raw_severity="medium",
            host="api-gateway",
            tags=["headers", "scan:DAST"],
            timestamp=datetime.now(timezone.utc),
        ),
        # 5 - Duplicate of #1 (same title + host -> same hash)
        Finding(
            source=FindingSource.WAZUH,
            source_id="wazuh-5003",
            title="SSH brute force attempt",
            description="Duplicate alert - same attack on same host",
            severity=Severity.HIGH,
            raw_severity="13",
            host="web-server-01",
            rule_id="5710",
            rule_groups=["sshd", "authentication"],
            tags=["sshd", "authentication"],
            timestamp=datetime.now(timezone.utc),
        ),
        # 6 - Same title as #1 but different host (should NOT be deduped)
        Finding(
            source=FindingSource.WAZUH,
            source_id="wazuh-5004",
            title="SSH brute force attempt",
            description="Same attack, different machine",
            severity=Severity.HIGH,
            raw_severity="13",
            host="web-server-02",
            rule_id="5710",
            rule_groups=["sshd", "authentication"],
            tags=["sshd", "authentication"],
            timestamp=datetime.now(timezone.utc),
        ),
    ]


# --- Stage runners ------------------------------------------------------------

def debug_ingestion(findings: list[Finding], verbose: bool) -> list[Finding]:
    """Debug: Simulated ingestion from Wazuh + DefectDojo."""
    banner("STAGE 1 - INGESTION", C.CYAN)

    wazuh = [f for f in findings if f.source == FindingSource.WAZUH]
    dojo  = [f for f in findings if f.source == FindingSource.DEFECTDOJO]

    section("Wazuh Alerts")
    info("Count", str(len(wazuh)), C.GREEN)
    for i, f in enumerate(wazuh):
        finding_card(f, i)
        if verbose:
            dbg(f"raw_severity={f.raw_severity}  rule_id={f.rule_id}  groups={f.rule_groups}")

    section("DefectDojo Findings")
    info("Count", str(len(dojo)), C.GREEN)
    for i, f in enumerate(dojo):
        finding_card(f, i)
        if verbose:
            dbg(f"raw_severity={f.raw_severity}  cvss={f.cvss}  cve_ids={f.cve_ids}")

    section("Ingestion Summary")
    info("Total findings ingested", str(len(findings)), C.GREEN)
    info("Wazuh", str(len(wazuh)), C.CYAN)
    info("DefectDojo", str(len(dojo)), C.CYAN)

    return findings


def debug_filter(findings: list[Finding], verbose: bool) -> list[Finding]:
    """Debug: FilterStage with min_severity=low."""
    banner("STAGE 2 - FILTERING", C.YELLOW)

    from app.config import FilterConfig
    from app.core.pipeline.filter import FilterStage

    config = FilterConfig(min_severity="low", exclude_title_patterns=["^Syslog.*"])
    stage = FilterStage(config)

    section("Filter Configuration")
    info("min_severity", config.min_severity, C.YELLOW)
    info("exclude_rule_ids", str(config.exclude_rule_ids) or "[]")
    info("include_hosts", str(config.include_hosts) or "[]")
    info("exclude_title_patterns", str(config.exclude_title_patterns))

    section("Processing")
    before = len(findings)
    result = stage.process(findings)
    after = len(result)
    dropped = before - after

    for f in findings:
        passed = f in result
        status = f"{C.GREEN}PASS{C.RESET}" if passed else f"{C.RED}DROP{C.RESET}"
        reason = ""
        if not passed:
            if f.severity.numeric < Severity.from_string(config.min_severity).numeric:
                reason = f" {C.DIM}(severity {f.severity.value} < {config.min_severity}){C.RESET}"
            else:
                reason = f" {C.DIM}(title pattern match){C.RESET}"
        print(
            f"  {C.GRAY}|{C.RESET}  [{status}] "
            f"{f.severity.value.upper():8s}  {f.title[:45]}  {reason}"
        )

    section("Filter Summary")
    info("Input", str(before))
    info("Passed", str(after), C.GREEN)
    info("Dropped", str(dropped), C.RED if dropped else C.GREEN)

    return result


def debug_severity_mapper(findings: list[Finding], verbose: bool) -> list[Finding]:
    """Debug: SeverityMapperStage."""
    banner("STAGE 3 - SEVERITY MAPPING", C.MAGENTA)

    from app.core.pipeline.severity_mapper import SeverityMapperStage

    priority_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    stage = SeverityMapperStage(priority_map)

    section("Priority Map (Severity -> Redmine Priority ID)")
    for sev, pid in priority_map.items():
        print(f"  {C.GRAY}|{C.RESET}  {sev:10s} -> priority_id={pid}")

    section("Processing")
    before_severities = [(f.title[:40], f.severity.value, f.raw_severity) for f in findings]
    result = stage.process(findings)

    for i, f in enumerate(result):
        old_title, old_sev, raw = before_severities[i]
        new_sev = f.severity.value
        pid = f.enrichment.get("redmine_priority_id", "?")
        changed = f" {C.YELLOW}<- remapped{C.RESET}" if old_sev != new_sev else ""

        sev_colors = {"critical": C.RED, "high": C.YELLOW, "medium": C.MAGENTA, "low": C.BLUE, "info": C.GRAY}
        sc = sev_colors.get(new_sev, C.WHITE)

        print(
            f"  {C.GRAY}|{C.RESET}  {f.title[:40]:42s}  "
            f"raw={C.DIM}{raw:10s}{C.RESET} -> "
            f"{sc}{C.BOLD}{new_sev.upper():8s}{C.RESET}  "
            f"priority_id={C.CYAN}{pid}{C.RESET}{changed}"
        )

    section("Severity Distribution")
    counts: dict[str, int] = {}
    for f in result:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    for sev, count in sorted(counts.items()):
        bar = "#" * (count * 4)
        print(f"  {C.GRAY}|{C.RESET}  {sev:10s} {bar} {count}")

    return result


def debug_dedup(findings: list[Finding], verbose: bool) -> list[Finding]:
    """Debug: DeduplicatorStage with a temp database."""
    banner("STAGE 4 - DEDUPLICATION", C.BLUE)

    from app.config import DedupConfig
    from app.core.pipeline.deduplicator import DeduplicatorStage

    with tempfile.TemporaryDirectory() as tmpdir:
        config = DedupConfig(enabled=True, db_path=str(Path(tmpdir) / "debug_dedup.db"), ttl_hours=1)
        stage = DeduplicatorStage(config)

        section("Dedup Configuration")
        info("Enabled", str(config.enabled), C.GREEN)
        info("DB path", config.db_path, C.DIM)
        info("TTL", f"{config.ttl_hours} hours")

        section("Dedup Hash Analysis")
        hash_groups: dict[str, list[Finding]] = {}
        for f in findings:
            hash_groups.setdefault(f.dedup_hash, []).append(f)

        for h, group in hash_groups.items():
            if len(group) > 1:
                warn(f"Hash {C.BOLD}{h[:16]}...{C.RESET}{C.YELLOW} has {len(group)} findings (duplicates!)")
                for f in group:
                    dbg(f"{f.source.value}:{f.source_id}  {f.title[:40]}  host={f.host}")
            else:
                f = group[0]
                ok(f"Hash {C.DIM}{h[:16]}...{C.RESET} is unique -- {f.title[:40]}")

        section("Processing")
        before = len(findings)
        result = stage.process(findings)
        after = len(result)

        for f in findings:
            passed = f in result
            status = f"{C.GREEN}KEEP{C.RESET}" if passed else f"{C.RED}DUPE{C.RESET}"
            print(
                f"  {C.GRAY}|{C.RESET}  [{status}] "
                f"{f.source.value}:{f.source_id:12s}  {f.title[:40]}  "
                f"host={C.CYAN}{f.host}{C.RESET}"
            )

        section("Dedup Summary")
        info("Input", str(before))
        info("Unique (kept)", str(after), C.GREEN)
        info("Duplicates dropped", str(before - after), C.RED if before > after else C.GREEN)

        section("Database Stats")
        stats = stage.get_stats()
        for k, v in stats.items():
            info(k, str(v))

        stage.close()

    return result


def debug_enrichment(findings: list[Finding], verbose: bool) -> list[Finding]:
    """Debug: EnricherStage."""
    banner("STAGE 5 - ENRICHMENT", C.GREEN)

    from app.config import EnrichmentConfig
    from app.core.pipeline.enricher import EnricherStage

    config = EnrichmentConfig(asset_inventory_enabled=False, add_remediation_links=True)
    stage = EnricherStage(config)

    section("Enrichment Configuration")
    info("Asset inventory", "disabled" if not config.asset_inventory_enabled else "enabled")
    info("Remediation links", "enabled" if config.add_remediation_links else "disabled", C.GREEN)

    section("Processing")
    result = stage.process(findings)

    for i, f in enumerate(result):
        finding_card(f, i)
        enrich_keys = list(f.enrichment.keys())
        dbg(f"enrichment keys: {C.GREEN}{enrich_keys}{C.RESET}")

        if f.enrichment.get("remediation_links"):
            for link in f.enrichment["remediation_links"]:
                dbg(f"  link: {C.CYAN}{link}{C.RESET}")

        label = f.enrichment.get("severity_label", "")
        if label:
            dbg(f"severity_label: {label}")

    section("Enrichment Summary")
    with_links = sum(1 for f in result if f.enrichment.get("remediation_links"))
    info("Findings enriched", str(len(result)), C.GREEN)
    info("With remediation links", str(with_links), C.CYAN)

    return result


def debug_output(findings: list[Finding], verbose: bool) -> None:
    """Debug: Simulated Redmine output (no real API call)."""
    banner("STAGE 6 - OUTPUT (Redmine - Simulated)", C.RED)

    section("Issues That Would Be Created")

    for i, f in enumerate(findings):
        severity_prefix = f.severity.value.upper()
        subject = f"[{severity_prefix}] [{f.source.value.upper()}] {f.title}"
        priority_id = f.enrichment.get("redmine_priority_id", "?")

        print(f"  {C.GRAY}|{C.RESET}")
        print(f"  {C.GRAY}|{C.RESET}  {C.BOLD}Ticket #{i + 1}{C.RESET}")
        print(f"  {C.GRAY}|{C.RESET}    Subject:     {C.WHITE}{subject[:65]}{C.RESET}")
        print(f"  {C.GRAY}|{C.RESET}    Project:     {C.CYAN}security-incidents{C.RESET}")
        print(f"  {C.GRAY}|{C.RESET}    Tracker:     {C.CYAN}Bug (ID: 1){C.RESET}")
        print(f"  {C.GRAY}|{C.RESET}    Priority:    {C.YELLOW}{priority_id}{C.RESET}")
        print(f"  {C.GRAY}|{C.RESET}    Dedup hash:  {C.DIM}{f.dedup_hash[:24]}...{C.RESET}")

        if verbose and f.enrichment.get("redmine_description"):
            desc_preview = f.enrichment["redmine_description"][:120].replace("\n", " ")
            print(f"  {C.GRAY}|{C.RESET}    Description: {C.DIM}{desc_preview}...{C.RESET}")

    section("Output Summary")
    info("Total issues to create", str(len(findings)), C.GREEN)


# --- Full pipeline run --------------------------------------------------------

def run_full_pipeline(verbose: bool) -> None:
    """Run all stages in sequence with debug output."""
    start = time.perf_counter()

    banner("SECURITY MIDDLEWARE -- DEBUG PIPELINE RUN", C.CYAN)
    print(f"  {C.GRAY}Timestamp:{C.RESET}  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {C.GRAY}Verbose:{C.RESET}    {verbose}")
    print(f"  {C.GRAY}Python:{C.RESET}     {sys.version.split()[0]}")

    # Create mock findings
    findings = make_findings()

    # Run stages
    findings = debug_ingestion(findings, verbose)
    findings = debug_filter(findings, verbose)
    findings = debug_severity_mapper(findings, verbose)
    findings = debug_dedup(findings, verbose)
    findings = debug_enrichment(findings, verbose)
    debug_output(findings, verbose)

    elapsed = time.perf_counter() - start

    # Final summary
    banner("PIPELINE COMPLETE", C.GREEN)
    info("Total time", f"{elapsed:.3f}s", C.GREEN)
    info("Final output findings", str(len(findings)), C.GREEN)
    print()


def run_single_stage(stage_name: str, verbose: bool) -> None:
    """Run a single named stage for focused debugging."""
    findings = make_findings()

    stages = {
        "ingest":   debug_ingestion,
        "filter":   debug_filter,
        "severity": debug_severity_mapper,
        "dedup":    debug_dedup,
        "enrich":   debug_enrichment,
    }

    if stage_name == "output":
        # Output needs enrichment first
        from app.config import EnrichmentConfig
        from app.core.pipeline.enricher import EnricherStage
        from app.core.pipeline.severity_mapper import SeverityMapperStage
        SeverityMapperStage({"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}).process(findings)
        EnricherStage(EnrichmentConfig(add_remediation_links=True)).process(findings)
        debug_output(findings, verbose)
        return

    if stage_name not in stages:
        print(f"{C.RED}Unknown stage: {stage_name}{C.RESET}")
        print(f"Available: {', '.join(list(stages.keys()) + ['output'])}")
        sys.exit(1)

    stages[stage_name](findings, verbose)
    print()


# --- CLI ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Debug runner for the Security Middleware pipeline stages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python debug_pipeline.py                  Run full pipeline debug
  python debug_pipeline.py --verbose        Full pipeline with extra detail
  python debug_pipeline.py --stage filter   Debug only the filter stage
  python debug_pipeline.py --stage dedup    Debug only the deduplicator
        """,
    )
    parser.add_argument(
        "--stage",
        choices=["ingest", "filter", "severity", "dedup", "enrich", "output"],
        help="Run only a specific stage",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show extra detail (raw data, descriptions, etc.)",
    )

    args = parser.parse_args()

    if args.stage:
        run_single_stage(args.stage, args.verbose)
    else:
        run_full_pipeline(args.verbose)


if __name__ == "__main__":
    main()
