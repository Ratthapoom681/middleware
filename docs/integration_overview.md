# Integration Overview

## How Frontend and Backend Work Together

---

## 1. Communication Architecture

The frontend (SPA) and backend (Flask) communicate exclusively via **JSON REST API** over HTTP. Flask serves both the static frontend files and the API endpoints from a single process on port 5000.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          BROWSER                                    │
│                                                                     │
│   index.html + app.js + styles.css                                  │
│        │                                                            │
│        │  fetch() calls (JSON over HTTP)                             │
│        ▼                                                            │
├─────────────────────────────────────────────────────────────────────┤
│                     FLASK SERVER (:5000)                             │
│                                                                     │
│   Static Files          REST API              Webhook Receiver       │
│   GET /               GET/POST /api/config    POST /api/webhook/wazuh│
│   GET /static/*       POST /api/config/test/* GET /api/webhook/history│
│                       POST /api/redmine/*                            │
│                       POST /api/defectdojo/*                         │
│        │                     │                       │               │
│        ▼                     ▼                       ▼               │
│   ┌──────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│   │ Disk     │    │ External APIs    │    │ Pipeline Engine  │      │
│   │config.yaml│   │ Wazuh/DD/Redmine│    │ MiddlewarePipeline│     │
│   └──────────┘    └──────────────────┘    └──────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Integration Points

| Frontend Action | API Endpoint | Backend Operation |
|----------------|--------------|-------------------|
| Load config | `GET /api/config` | Read YAML → build typed config → serialize to JSON |
| Save config | `POST /api/config` | Validate → backup → write YAML |
| Test connection | `POST /api/config/test/:service` | Build config → instantiate client → call test API |
| Fetch trackers | `POST /api/redmine/trackers` | Build config → RedmineClient → GET /trackers.json |
| View live events | `GET /api/webhook/history` | Read dashboard history store (JSONL or Postgres) |
| Preview findings | `POST /api/defectdojo/finding-count` | Build config → DefectDojoClient → count query |

---

## 2. Request/Response Flow Examples

### 2.1 Configuration Load Flow

```
Browser                        Flask                         Disk
  │                              │                             │
  │  GET /api/config             │                             │
  │─────────────────────────────►│                             │
  │                              │  Read config.yaml           │
  │                              │────────────────────────────►│
  │                              │◄────────────────────────────│
  │                              │                             │
  │                              │  yaml.safe_load()           │
  │                              │  _build_config(raw)         │
  │                              │  _config_to_dict(config)    │
  │                              │                             │
  │  200 OK                      │                             │
  │  { status: "ok",             │                             │
  │    config: { wazuh: {...},   │                             │
  │              redmine: {...}, │                             │
  │              ... },          │                             │
  │    path: "config/config.yaml"│                             │
  │  }                           │                             │
  │◄─────────────────────────────│                             │
  │                              │                             │
  │  Populate form fields        │                             │
  │  from config object          │                             │
```

### 2.2 Configuration Save Flow

```
Browser                        Flask                         Disk
  │                              │                             │
  │  POST /api/config            │                             │
  │  Body: { wazuh: {...},       │                             │
  │          redmine: {...}, ... }│                             │
  │─────────────────────────────►│                             │
  │                              │  _build_config(data)        │
  │                              │  ← validates or throws →    │
  │                              │                             │
  │                              │  Copy config.yaml →         │
  │                              │  config_20260430_031800.yaml │
  │                              │────────────────────────────►│
  │                              │                             │
  │                              │  _build_yaml(data)          │
  │                              │  Write new config.yaml      │
  │                              │────────────────────────────►│
  │                              │                             │
  │  200 OK                      │                             │
  │  { status: "ok",             │                             │
  │    message: "Configuration   │                             │
  │             saved" }         │                             │
  │◄─────────────────────────────│                             │
  │                              │                             │
  │  Show success toast          │                             │
```

### 2.3 Connection Test Flow

```
Browser                     Flask                    External Service
  │                           │                             │
  │  POST /api/config/test/   │                             │
  │       wazuh               │                             │
  │  Body: { full config }    │                             │
  │──────────────────────────►│                             │
  │                           │  _build_config(data)        │
  │                           │  WazuhClient(config.wazuh)  │
  │                           │  client.test_connection()   │
  │                           │                             │
  │                           │  POST /security/user/       │
  │                           │       authenticate          │
  │                           │────────────────────────────►│
  │                           │  ← JWT token ──────────────│
  │                           │                             │
  │                           │  GET /manager/info          │
  │                           │────────────────────────────►│
  │                           │  ← version, node info ─────│
  │                           │                             │
  │                           │  GET indexer_url/            │
  │                           │────────────────────────────►│
  │                           │  ← cluster info ───────────│
  │                           │                             │
  │  200 OK                   │                             │
  │  { status: "ok",          │                             │
  │    connected: true,       │                             │
  │    service: "wazuh" }     │                             │
  │◄──────────────────────────│                             │
  │                           │                             │
  │  Show ✅ indicator        │                             │
```

### 2.4 Webhook Processing Flow

```
Wazuh Integration            Flask                    Pipeline            Redmine
  │                            │                         │                   │
  │  POST /api/webhook/wazuh   │                         │                   │
  │  Body: [{ alert data }]    │                         │                   │
  │───────────────────────────►│                         │                   │
  │                            │  Parse alerts           │                   │
  │                            │  WazuhClient._alert_    │                   │
  │                            │    to_finding()         │                   │
  │                            │                         │                   │
  │                            │  MiddlewarePipeline     │                   │
  │                            │  .process_batch()       │                   │
  │                            │────────────────────────►│                   │
  │                            │                         │  Filter           │
  │                            │                         │  SeverityMap      │
  │                            │                         │  Dedup            │
  │                            │                         │  Enrich           │
  │                            │                         │                   │
  │                            │                         │  POST /issues.json│
  │                            │                         │──────────────────►│
  │                            │                         │  ← issue #1234 ──│
  │                            │                         │                   │
  │                            │  ← outcome stats ──────│                   │
  │  200 OK                    │                         │                   │
  │  { status: "ok",           │                         │                   │
  │    stats: { created: 1 }}  │                         │                   │
  │◄───────────────────────────│                         │                   │
```

---

## 3. Authentication Flows

### 3.1 Wazuh — JWT Authentication

```
Pipeline                         Wazuh Manager (:55000)
  │                                     │
  │  POST /security/user/authenticate   │
  │  Basic Auth: (username, password)   │
  │────────────────────────────────────►│
  │                                     │
  │  200 OK                             │
  │  { data: { token: "eyJ..." } }     │
  │◄────────────────────────────────────│
  │                                     │
  │  [All subsequent requests]          │
  │  Authorization: Bearer eyJ...       │
  │────────────────────────────────────►│
  │                                     │
  │  Token expires after 900s (15 min)  │
  │  → Auto re-authenticate at 850s    │
```

### 3.2 DefectDojo — API Token

```
Pipeline                         DefectDojo (:8080)
  │                                     │
  │  GET /api/v2/findings/              │
  │  Authorization: Token <api-key>     │
  │  Content-Type: application/json     │
  │────────────────────────────────────►│
  │                                     │
  │  200 OK { results: [...] }         │
  │◄────────────────────────────────────│
```

### 3.3 Redmine — API Key Header

```
Pipeline                         Redmine (:3000)
  │                                     │
  │  POST /issues.json                  │
  │  X-Redmine-API-Key: <api-key>      │
  │  Content-Type: application/json     │
  │────────────────────────────────────►│
  │                                     │
  │  201 Created { issue: { id: 1234 }}│
  │◄────────────────────────────────────│
```

### 3.4 Frontend → Backend (No Auth)

The frontend-to-Flask communication currently has **no authentication**. The Flask server is intended to run on a trusted internal network.

> [!WARNING]
> If the Web UI is exposed to untrusted networks, add authentication middleware (e.g., Flask-Login, reverse proxy with HTTP Basic Auth, or OAuth2 proxy).

---

## 4. Data Flow Diagrams

### 4.1 End-to-End Pipeline Data Flow

```
                    ┌──────────────┐
                    │  config.yaml │
                    └──────┬───────┘
                           │ load_config()
                           ▼
    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
    │  Wazuh   │───►│              │    │              │
    │ Indexer/ │    │   INGEST     │    │  IDENTITY    │
    │ File/    │    │              │───►│  RESOLUTION  │
    │ Webhook  │    │ alert →      │    │              │
    └──────────┘    │   Finding    │    │ dedup_key    │
    ┌──────────┐    │              │    │ dedup_hash   │
    │DefectDojo│───►│              │    │ routing_key  │
    │ REST API │    └──────────────┘    └──────┬───────┘
    └──────────┘                               │
                                               ▼
                                    ┌──────────────────┐
                                    │     FILTER        │
                                    │                   │
                                    │ severity check    │
                                    │ rule_id exclusion │
                                    │ host patterns     │
                                    │ title patterns    │
                                    │ JSON rules        │
                                    └────────┬─────────┘
                                             │ passed findings
                                             ▼
                                    ┌──────────────────┐
                                    │  SEVERITY MAPPER  │
                                    │                   │
                                    │ raw → unified     │
                                    │ unified → Redmine │
                                    │   priority_id     │
                                    └────────┬─────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │   DEDUPLICATOR    │
                                    │                   │
                                    │ hash lookup       │──► SQLite/Postgres
                                    │ new vs repeat     │
                                    │ batch collapse    │
                                    └────────┬─────────┘
                                             │
                                    ┌────────┴────────┐
                                    │                 │
                               new_findings    repeat_findings
                                    │                 │
                                    ▼                 ▼
                                    ┌──────────────────┐
                                    │     ENRICHER      │
                                    │                   │
                                    │ asset metadata    │
                                    │ remediation links │
                                    │ Redmine desc      │
                                    └────────┬─────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │  REDMINE OUTPUT   │    ┌──────────┐
                                    │                   │───►│ Redmine  │
                                    │ create / update / │    │ REST API │
                                    │ reopen / recreate │    └──────────┘
                                    └────────┬─────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │  COMMIT TO DEDUP  │
                                    │  (only on success)│──► SQLite/Postgres
                                    └────────┬─────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │ DASHBOARD EVENT   │──► JSONL/Postgres
                                    │ (persist history) │
                                    └──────────────────┘
```

### 4.2 Frontend Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                    BROWSER (app.js)                      │
│                                                         │
│  Page Load                                              │
│    │                                                    │
│    ├── GET /api/config ──► populate config forms         │
│    └── GET /api/webhook/history ──► render dashboard    │
│                                                         │
│  Config Save                                            │
│    │                                                    │
│    ├── Collect form values into JSON                    │
│    ├── POST /api/config ──► validate + save + backup    │
│    └── Toast success/error                              │
│                                                         │
│  Connection Test                                        │
│    │                                                    │
│    ├── POST /api/config/test/:service                   │
│    │   (sends current unsaved config as body)           │
│    └── Update ✅/❌ indicator per service                │
│                                                         │
│  Live Events (5s polling)                               │
│    │                                                    │
│    ├── GET /api/webhook/history                         │
│    └── Re-render event cards + update stats             │
│                                                         │
│  DefectDojo Scope (on-demand)                           │
│    │                                                    │
│    ├── POST /api/defectdojo/scope-data                  │
│    │   ──► populate product/engagement/test dropdowns   │
│    └── POST /api/defectdojo/finding-count               │
│       ──► show matching/pending count preview           │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Error Handling Across Systems

### Error Propagation Chain

```
External API Error
       │
       ▼
Source Client (catches RequestException)
       │
       ├── Logs error with context
       ├── Returns empty list / None
       │
       ▼
Pipeline Orchestrator
       │
       ├── Counts failures in stats
       ├── DefectDojo: discards pending checkpoint on failure
       ├── Dedup: does NOT commit failed findings (retry next cycle)
       │
       ▼
Flask API / Dashboard
       │
       ├── Returns { status: "ok", stats: { failed: N } }
       ├── Dashboard event records failure counts
       │
       ▼
Frontend
       │
       ├── Displays failed count in event cards
       └── Shows error toast for connection test failures
```

### Error Handling by Layer

| Layer | Strategy | Example |
|-------|----------|---------|
| **Wazuh Client** | Catch `RequestException`, log, return `[]` | Indexer timeout → empty findings list |
| **DefectDojo Client** | Raise `DefectDojoAPIError` for non-JSON responses | HTML login page → clear error message |
| **Deduplicator** | Assert state store availability | No DB → skip dedup |
| **Redmine Client** | Per-finding try/catch, count failures | API 422 → finding.action = "failed" |
| **Pipeline** | Aggregate stats, checkpoint rollback | Any failure → discard DD checkpoint |
| **Flask API** | Try/except → JSON error response | Exception → `{ status: "error", message: "..." }` |
| **Frontend** | Catch in fetch → toast notification | Network error → user-visible message |

### Retry Behavior

| Scenario | Retry Strategy |
|----------|---------------|
| Redmine create fails | Finding NOT committed to dedup → retried next cycle |
| DefectDojo fetch fails | Checkpoint NOT advanced → same findings re-fetched |
| Wazuh indexer timeout | Findings from that cycle are skipped; next poll retries |
| Async delivery failure | Job rescheduled with `retry_delay_seconds` backoff |
| Webhook processing fails | HTTP 500 returned to Wazuh → Wazuh's own retry logic |

---

## 6. Bottlenecks & Mitigations

| Bottleneck | Impact | Mitigation |
|------------|--------|-----------|
| **Redmine API latency** | Slow issue creation blocks pipeline cycle | Enable async delivery (`delivery.async_enabled: true`) to decouple pipeline from Redmine |
| **Large Wazuh alert volume** | Single cycle processes thousands of alerts | `min_level` filter reduces noise; `search_after` pagination prevents memory spikes |
| **DefectDojo full re-scan** | Without checkpoint, every finding is re-processed | Checkpoint-based incremental sync with `fetch_limit` cap |
| **SQLite lock contention** | Single-writer limitation under high concurrency | Switch to Postgres backend for multi-instance deployments |
| **Frontend polling overhead** | 5-second interval creates API load | Consider WebSocket for live events; add `If-Modified-Since` headers |
| **Config save + reload** | Pipeline components fully re-initialized on config change | Hot reload only triggers when `mtime` changes; clients are lightweight |
| **Single Flask process** | No concurrent request handling | Deploy behind Gunicorn/uWSGI with multiple workers for production |
| **Network partitions** | External service unavailability stalls pipeline | Per-service timeouts (10-60s); graceful degradation (skip failed source, continue others) |
| **Dedup DB growth** | Unbounded hash accumulation | TTL-based garbage collection runs after each cycle (`ttl_hours: 168` default) |

### Recommended Production Topology

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │  (nginx/ALB)    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──┐  ┌───────▼────┐  ┌──────▼──────┐
    │ Web UI     │  │ Pipeline   │  │ Delivery    │
    │ (Flask x2) │  │ Worker x1  │  │ Worker x2   │
    └─────────┬──┘  └───────┬────┘  └──────┬──────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │  PostgreSQL 16  │
                    │  (shared state) │
                    └─────────────────┘
```

---

## 7. Key Integration Contracts

### Config JSON Schema (Frontend ↔ Backend)

The config object shape is identical in both directions. The frontend sends the same structure it receives:

```json
{
  "wazuh": { "base_url": "...", "username": "...", ... },
  "defectdojo": { "enabled": true, "base_url": "...", ... },
  "redmine": { "base_url": "...", "routing_rules": [...], ... },
  "pipeline": {
    "poll_interval": 300,
    "filter": { "min_severity": "low", ... },
    "dedup": { "enabled": true, "ttl_hours": 168, ... },
    "delivery": { "async_enabled": false, ... },
    "enrichment": { ... }
  },
  "storage": { "backend": "local", ... },
  "logging": { "level": "INFO", ... }
}
```

### Webhook History Event Schema

```json
{
  "id": "uuid",
  "receive_time": "2026-04-30T03:00:00+00:00",
  "origin": "webhook|poll",
  "alert_count": 5,
  "source_counts": { "wazuh": 3, "defectdojo": 2 },
  "stats": {
    "ingested": 5, "filtered": 1, "deduplicated": 1,
    "created": 2, "updated": 1, "failed": 0
  },
  "findings": [
    {
      "title": "...", "severity": "high", "source": "wazuh",
      "action": "created", "host": "web-01", "dedup_hash": "abc123..."
    }
  ]
}
```

### API Response Contract

All API responses follow this envelope:

```json
// Success
{ "status": "ok", "data_key": "..." }

// Error
{ "status": "error", "message": "Human-readable error description" }

// Warning (validation)
{ "status": "warning", "valid": true, "issues": ["..."] }
```
