# Settings Management in Security Middleware

This document explains how configuration settings are managed, accessed, and updated within the Security Middleware application.

## Overview

The middleware uses a hybrid settings architecture:
1. **Persistent Storage (PostgreSQL)**: Settings are stored as JSON in the `settings_table` inside the database to persist across restarts.
2. **In-Memory Singleton (`settings_manager`)**: A singleton instance caches settings in memory for fast, synchronous reads across all modules without querying the database every time.
3. **Hot Reloading**: Updates to the database trigger an immediate reload of the `settings_manager`, ensuring all system components (like pipelines or schedulers) see the new configuration instantly. WebSocket events are also broadcast to the frontend.

---

## 1. Reading Settings in Python Code

To read configuration values anywhere in the application, import the `settings_manager` from `app.settings.models`. 

**Example: Reading Redmine settings inside a function**

```python
from app.settings.models import settings_manager

async def create_ticket(title: str, description: str):
    # 1. Get the 'redmine' configuration section
    redmine_config = settings_manager.get("redmine")
    
    # 2. Extract values (with fallback defaults if needed)
    base_url = redmine_config.get("base_url")
    api_key = redmine_config.get("api_key")
    project_id = redmine_config.get("project_id", "security")
    
    if not base_url or not api_key:
        raise ValueError("Redmine is not fully configured!")
        
    print(f"Connecting to Redmine at {base_url} for project {project_id}")
    # ... proceed to create ticket
```

> **Tip:** You can use `settings_manager.get_all()` to get a dictionary of all configuration sections and their current values.

---

## 2. Updating Settings Programmatically

To update settings from within the backend code (e.g., after an automated check or setup wizard), use the asynchronous `upsert_section` function. This will write to the database and automatically trigger a hot reload.

**Example: Updating pipeline configuration**

```python
from app.settings.models import upsert_section

async def adjust_polling_rate(new_interval_seconds: int):
    # 1. Define the updated configuration payload
    new_pipeline_config = {
        "poll_interval": new_interval_seconds,
        "initial_lookback_minutes": 1440
    }
    
    # 2. Upsert the section. This saves to DB and calls settings_manager.reload()
    await upsert_section("pipeline", new_pipeline_config)
    
    print(f"Pipeline polling interval updated to {new_interval_seconds}s!")
```

---

## 3. Managing Settings via REST API

The middleware exposes API endpoints for the frontend (or external scripts) to manage configuration. When updated via the API, the backend updates the DB, hot-reloads memory, and pushes a WebSocket event to all clients.

### Get a Section
**GET** `/api/settings/{section}`

```bash
curl -X GET "http://localhost:8000/api/settings/wazuh"
```
**Response:**
```json
{
  "section": "wazuh",
  "config": {
    "base_url": "https://wazuh.local",
    "username": "admin",
    "min_level": 7,
    "...": "..."
  }
}
```

### Update a Section
**PUT** `/api/settings/{section}`

```bash
curl -X PUT "http://localhost:8000/api/settings/redmine" \
     -H "Content-Type: application/json" \
     -d '{
           "config": {
             "base_url": "https://redmine.local",
             "api_key": "mysecretkey123",
             "project_id": "infosec"
           }
         }'
```

---

## Available Configuration Sections

The `settings_manager` maintains default structures for the following sections:

- `wazuh`: Credentials, API URL, Indexer URL, and minimum alert levels.
- `defectdojo`: API keys, product/engagement IDs, severity filters, fetch limits.
- `redmine`: Tracker IDs, project IDs, base URLs, and priority mapping.
- `pipeline`: Polling intervals and lookback windows.
- `filter`: Global severity minimums, exclusion rules, and whitelists.
- `dedup`: SQLite deduplication DB path and TTL rules.
- `enrichment`: Asset inventory integration settings.
- `severity_map`: Maps native source severities to the unified pipeline scale.
- `storage`: Database table mappings and connection strings.
- `logging`: Log levels and formatting rules.

---

## Configuration Formats & Examples

When updating settings that expect JSON objects or maps (especially via the UI or API), use the following formats.

### Severity Mapping (`severity_map`)

The pipeline normalizes severities into a unified scale (`info`, `low`, `medium`, `high`, `critical`).

**Wazuh Level Map**
Maps Wazuh alert levels (numeric 0-15) to unified severities. Keys must be strings representing the *minimum* Wazuh level for that severity.
```json
{
  "15": "critical",
  "12": "high",
  "7": "medium",
  "4": "low",
  "0": "info"
}
```

**DefectDojo Severity Map**
Maps DefectDojo's string severities to unified severities.
```json
{
  "critical": "critical",
  "high": "high",
  "medium": "medium",
  "low": "low",
  "info": "info",
  "informational": "info"
}
```

### Redmine Priority Map (`redmine.priority_map`)

Maps the unified pipeline severity to your Redmine instance's specific Priority IDs (integers). You can find these IDs in Redmine under Administration > Enumerations.
```json
{
  "critical": 5,
  "high": 4,
  "medium": 3,
  "low": 2,
  "info": 1
}
```

### Routing Rules (`redmine.routing_rules`)

An array of rules that route specific findings to different Redmine Tracker IDs or Project IDs based on conditions.
```json
[
  {
    "condition": "source == 'wazuh' and rule_id == '5716'",
    "project_id": "authentication",
    "tracker_id": 2
  },
  {
    "condition": "severity == 'critical'",
    "priority_id": 6
  }
]
```

---

## Startup Seeding

When the application first starts (in `main.py`), it reads from `config/config.yaml` to seed any missing database settings. After that, the database becomes the source of truth, and `config.yaml` is ignored.
