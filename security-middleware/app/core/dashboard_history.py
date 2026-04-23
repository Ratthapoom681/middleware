"""
Persistent dashboard history helpers.

Local mode stores recent event payloads in a JSONL file under the project data
directory. Postgres mode reuses the shared state store for durable history so
the dashboard can survive restarts and show both webhook and polling activity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config import PROJECT_ROOT, StorageConfig

DEFAULT_LOCAL_HISTORY_PATH = PROJECT_ROOT / "data" / "dashboard_events.jsonl"


def create_dashboard_history_store(
    config: StorageConfig,
    shared_state_store: Any | None = None,
) -> Any:
    """Create a dashboard history store for the configured backend."""
    if config.backend == "postgres" and shared_state_store is not None:
        return shared_state_store
    return LocalDashboardHistoryStore(DEFAULT_LOCAL_HISTORY_PATH)


class LocalDashboardHistoryStore:
    """Append-only JSONL dashboard history for local deployments."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def append_dashboard_event(self, record: dict[str, Any]) -> None:
        """Persist one dashboard event."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")

    def get_dashboard_history(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return the most recent persisted dashboard events, newest first."""
        safe_limit = max(1, int(limit))
        if not self.path.exists():
            return []

        lines = self.path.read_text(encoding="utf-8").splitlines()
        events: list[dict[str, Any]] = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
            if len(events) >= safe_limit:
                break
        return events

    def close(self) -> None:
        """No-op for API compatibility with shared stores."""
        return None
