"""Pipeline monitoring – collects runtime metrics."""

from datetime import datetime, timezone

_metrics = {
    "total_processed": 0,
    "total_deduplicated": 0,
    "total_filtered": 0,
    "total_delivered": 0,
    "total_failed": 0,
    "last_run": None,
}


def record_run(stats: dict):
    """Record metrics from a pipeline run."""
    _metrics["total_processed"] += stats.get("ingested", 0)
    _metrics["total_deduplicated"] += stats.get("deduplicated", 0)
    _metrics["total_filtered"] += stats.get("filtered", 0)
    _metrics["total_delivered"] += stats.get("created", 0) + stats.get("updated", 0)
    _metrics["total_failed"] += stats.get("failed", 0)
    _metrics["last_run"] = datetime.now(timezone.utc).isoformat()


def get_metrics() -> dict:
    """Return current pipeline metrics."""
    return dict(_metrics)
