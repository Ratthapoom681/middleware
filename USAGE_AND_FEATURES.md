# Workspace Usage And Features

This guide summarizes what is in this workspace, how to run it, and which features are implemented in the current codebase.

I based this guide on the tracked project files in the workspace and ignored generated/runtime folders such as `.venv`, `.uv-cache`, `.pytest_cache`, `__pycache__`, temporary pytest folders, and local database/cache artifacts.

## 1. What Is In This Workspace

This workspace contains one main application:

- `security-middleware/`: the actual Python application
- `README.md`: high-level overview of the middleware
- `implementation_plan.md`: the original design/implementation plan

The real product lives in `security-middleware/`.

## 2. What The Application Does

The middleware collects security findings from:

- Wazuh
- DefectDojo

It then:

- normalizes them into one internal finding model
- filters unwanted/noisy items
- maps severity into a shared scale
- deduplicates repeat findings
- enriches findings with extra context
- creates, updates, reopens, or recreates Redmine issues

It also includes:

- a Flask-based web UI for configuration and monitoring
- a Wazuh webhook receiver
- a live events view and dashboard
- local or Postgres-backed state storage

## 3. Main Features

### 3.1 Source Ingestion

#### Wazuh

- Supports Wazuh Manager API connection testing.
- Supports Wazuh Indexer/OpenSearch alert polling.
- Supports direct file-based ingestion from `alerts.json`.
- Applies a Wazuh-side minimum alert level before processing.
- Converts Wazuh alerts into the common `Finding` model.

#### DefectDojo

- Supports DefectDojo REST API v2.
- Can be enabled or disabled independently.
- Filters by severity list.
- Supports Product, Engagement, and Test scoping.
- Supports `active` and `verified` filtering.
- Supports `updated_since_minutes`.
- Supports `fetch_limit` as a processing cap.
- Maintains an incremental checkpoint so only newer findings are processed.
- Builds browser-facing links back to the originating DefectDojo finding.

### 3.2 Pipeline Processing

#### Unified Finding Model

The app normalizes Wazuh and DefectDojo items into a single internal model with:

- source and source ID
- title and description
- severity and raw severity
- host, endpoint, component, plugin, CVE, CVSS, tags
- raw payload for debugging
- enrichment metadata
- dedup key and dedup hash
- Redmine issue state

#### Filtering

Implemented filter capabilities:

- minimum unified severity
- excluded Wazuh rule IDs
- host include regex list
- title exclude regex list
- advanced JSON/raw-payload rules

Advanced JSON rules support:

- `keep` or `drop`
- source scoping: `wazuh`, `defectdojo`, or `any`
- match mode: `all` or `any`
- operators: `equals`, `not_equals`, `contains`, `regex`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `exists`

#### Severity Mapping

- Wazuh numeric levels are mapped into `info`, `low`, `medium`, `high`, `critical`.
- DefectDojo severities are normalized into the same scale.
- The normalized severity is mapped to a Redmine priority ID.

#### Deduplication

- Uses source-aware identity generation.
- Wazuh dedup keys include source, rule ID, title, host, source IP, and CVEs.
- DefectDojo dedup keys use scanner-aware logic for ZAP, Tenable/Nessus, and generic findings.
- Dedup hashes are SHA-256 based.
- Same-batch duplicates are collapsed.
- Existing findings within TTL are treated as repeats instead of new tickets.
- Expired hashes can create tickets again after TTL.

#### Enrichment

- Optional asset inventory lookup from YAML.
- Optional remediation/reference links for CVEs and MITRE technique IDs.
- Builds formatted Redmine descriptions.
- Wazuh tickets get a richer, operator-oriented layout.
- Raw alert/finding payloads are attached into the Redmine issue body.

### 3.3 Redmine Output

Implemented Redmine behaviors:

- create new issues
- update existing issues for repeats
- reopen closed issues
- recreate tickets if the stored Redmine issue no longer exists
- per-severity priority mapping
- optional dedup hash custom field
- optional parent device issues
- optional routing rules for tracker selection and parent behavior
- Redmine tracker discovery API for the UI

Routing rules support:

- source matching
- exact match
- prefix match
- regex match
- tracker override
- parent issue override

### 3.4 State Storage And Reliability

#### Local Mode

Local mode uses:

- SQLite for dedup state
- JSON file for DefectDojo checkpoint state
- JSONL file for dashboard history

Important local files:

- `security-middleware/data/dedup.db`
- `security-middleware/data/defectdojo_cursor.json`
- `security-middleware/data/dashboard_events.jsonl`

#### Postgres Mode

Postgres mode centralizes shared state so multiple middleware instances can coordinate safely.

Implemented shared tables include:

- dedup state
- checkpoint state
- ticket state cache
- outbound delivery queue
- ingest event staging
- dashboard event history

### 3.5 Async And Store-First Processing

The code supports advanced delivery modes under `pipeline.delivery`:

- `async_enabled`
- `worker_poll_interval`
- `worker_batch_size`
- `retry_delay_seconds`
- `recheck_ttl_minutes`
- `store_first_ingest`

These enable:

- asynchronous Redmine delivery via queue workers
- ticket-state recheck before deciding update/reopen/recreate
- store-first ingest where raw events are persisted before downstream processing
- a separate decision worker for persisted ingest events

Note:

- these advanced delivery capabilities exist in config and runtime code
- they are best configured through YAML today

### 3.6 Web UI And Monitoring

The web app is a Flask server serving a static operations console.

Current UI areas:

- Wazuh settings
- DefectDojo settings
- Redmine settings
- filter rules
- deduplication settings
- enrichment settings
- dashboard
- live events
- logging/system settings
- raw YAML preview/editor

Implemented UI capabilities:

- load current config
- save config
- raw YAML load/save
- config validation
- config backups
- restore previous config backups
- test Wazuh connection
- test DefectDojo connection
- test Redmine connection
- fetch Redmine trackers
- sync DefectDojo scope data
- preview DefectDojo matching/pending finding counts
- view recent persisted middleware events
- chart activity over time
- inspect live finding decisions

### 3.7 Webhook Support

- Wazuh webhook endpoint is implemented.
- Single-object or list payloads are supported.
- Webhook events can go through normal in-memory processing or store-first processing.
- Webhook history is persisted and shown in the dashboard/live events view.

### 3.8 Operational Features

- automatic config reload when `config.yaml` changes on disk
- fallback to the newest config backup if the main config is missing or invalid and no explicit config path is passed
- environment variable overrides for sensitive settings
- Dockerfile and `docker-compose.yml`
- optional local Postgres container in Docker Compose
- Amazon Linux / EC2 deployment instructions in the existing README

### 3.9 Testing And Debugging

Included test coverage covers:

- config loading and normalization
- filtering
- severity mapping
- deduplication
- Redmine client behavior
- state store behavior
- pipeline integration
- web UI/API round trips

Debug helpers included:

- `security-middleware/debug_pipeline.py`
- `security-middleware/debug_webhook.py`

## 4. How To Use It

### 4.1 Install

From the project folder:

```powershell
cd C:\Users\ifilm\Downloads\Document\security-middleware
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 4.2 Configure

Main config file:

- `security-middleware/config/config.yaml`

You can configure it in two ways:

- edit `config/config.yaml` directly
- start the web UI and edit it there

Important service settings to provide:

- Wazuh manager/indexer URLs and credentials
- DefectDojo URL and API key
- Redmine URL, API key, project ID, and tracker settings

### 4.3 Run Modes

Run these commands from `security-middleware/`.

#### Default mode: pipeline + web UI + webhook receiver

```powershell
python -m src.main
```

What this does:

- starts the middleware polling loop in a background thread
- starts the web UI
- exposes the webhook endpoint

Default URL:

- `http://127.0.0.1:5000`

#### Pipeline only

```powershell
python -m src.main --no-web
```

#### Single pipeline cycle

```powershell
python -m src.main --once
```

#### Connection test only

```powershell
python -m src.main --test
```

#### Async Redmine delivery worker only

```powershell
python -m src.main --delivery-worker
```

Use this when `pipeline.delivery.async_enabled: true`.

#### Persisted ingest decision worker only

```powershell
python -m src.main --decision-worker
```

Use this when `pipeline.delivery.store_first_ingest: true`.

#### Web UI only

```powershell
python -m web.server
```

This starts:

- the configuration UI
- the Wazuh webhook endpoint

It does not start background polling unless you use:

```powershell
python -m web.server --background-polling
```

#### Custom host/port

```powershell
python -m src.main --host 0.0.0.0 --port 5000
python -m web.server --host 0.0.0.0 --port 5000
```

### 4.4 Web UI Workflow

Recommended operator workflow:

1. Start `python -m src.main`
2. Open `http://127.0.0.1:5000`
3. Fill in Wazuh, DefectDojo, and Redmine settings
4. Use the connection test buttons
5. Save the config
6. Watch the Dashboard and Live Events sections

Useful UI-only features:

- restore config backups
- preview YAML
- edit raw YAML
- sync DefectDojo scope lists
- preview DefectDojo finding counts before enabling broad polling

### 4.5 Webhook Usage

Wazuh webhook endpoint:

- `POST /api/webhook/wazuh`

Local example:

```powershell
python C:\Users\ifilm\Downloads\Document\security-middleware\debug_webhook.py
```

History endpoint:

- `GET /api/webhook/history`

### 4.6 Docker Usage

From `security-middleware/`:

```powershell
docker-compose up -d
docker-compose logs -f middleware
```

Notes:

- Compose also starts a local Postgres container.
- The middleware service uses host networking in the provided compose file.
- If you want the middleware to use that bundled Postgres instance, use `127.0.0.1:5432` in `storage.postgres_dsn`.

## 5. Important Config Areas

### 5.1 Source Config

`wazuh` controls:

- manager API settings
- indexer settings
- SSL verification
- minimum level
- optional `alerts_json_path`

`defectdojo` controls:

- enable/disable
- base URL and API key
- SSL verification
- severity filter
- product/engagement/test scope
- active/verified flags
- updated-since window
- fetch limit
- checkpoint cursor path

`redmine` controls:

- base URL and API key
- project ID
- default tracker
- parent issue behavior
- parent tracker
- dedup custom field ID
- priority map
- routing rules

### 5.2 Pipeline Config

`pipeline.filter`:

- `min_severity`
- `exclude_rule_ids`
- `include_hosts`
- `exclude_title_patterns`
- `default_action`
- `json_rules`

`pipeline.dedup`:

- `enabled`
- `db_path`
- `ttl_hours`

`pipeline.enrichment`:

- `asset_inventory_enabled`
- `asset_inventory_path`
- `add_remediation_links`

`pipeline.delivery`:

- `async_enabled`
- `worker_poll_interval`
- `worker_batch_size`
- `retry_delay_seconds`
- `recheck_ttl_minutes`
- `store_first_ingest`

### 5.3 Storage Config

`storage.backend` can be:

- `local`
- `postgres`

Postgres-related fields:

- `postgres_dsn`
- `postgres_schema`
- `dedup_table`
- `checkpoint_table`
- `ticket_state_table`
- `outbound_queue_table`
- `ingest_event_table`

## 6. Environment Variable Overrides

Supported environment overrides in the loader include:

- `SECURITY_MIDDLEWARE_CONFIG`
- `WAZUH_BASE_URL`
- `WAZUH_USERNAME`
- `WAZUH_PASSWORD`
- `DEFECTDOJO_BASE_URL`
- `DEFECTDOJO_API_KEY`
- `STATE_BACKEND`
- `STATE_POSTGRES_DSN`
- `REDMINE_BASE_URL`
- `REDMINE_API_KEY`

## 7. API Endpoints

Implemented API routes:

### Config

- `GET /api/config`
- `POST /api/config`
- `GET /api/config/raw`
- `POST /api/config/raw`
- `GET /api/config/backups`
- `POST /api/config/backups/restore/<filename>`
- `POST /api/config/validate`
- `POST /api/config/test/<service>`

### Redmine

- `POST /api/redmine/trackers`

### DefectDojo

- `POST /api/defectdojo/scope-data`
- `POST /api/defectdojo/finding-count`

### Webhook and monitoring

- `POST /api/webhook/wazuh`
- `GET /api/webhook/history`

## 8. Testing And Debugging Commands

Run all tests:

```powershell
python -m pytest tests -v
```

Run web UI tests:

```powershell
python -m pytest tests/test_web_ui.py -v
```

Run pipeline debug helper:

```powershell
python debug_pipeline.py
python debug_pipeline.py --stage filter
python debug_pipeline.py --stage dedup
python debug_pipeline.py --verbose
```

## 9. Practical Notes And Caveats

- The default `python -m src.main` behavior starts both the pipeline and the web UI. It is not pipeline-only.
- Advanced `pipeline.delivery` features are implemented in code and config, but they are best managed in YAML.
- The CLI exposes a `--dry-run` flag, but I did not find implemented behavior tied to it in the current code. Treat it as reserved/incomplete for now.
- Dashboard history persists locally in JSONL or in Postgres, depending on storage backend.
- Config backups are created by the web UI before saves/restores, and the loader can fall back to the newest backup in some failure cases.

## 10. Recommended Starting Modes

If you want the simplest local setup:

1. Edit `security-middleware/config/config.yaml`
2. Run `python -m src.main`
3. Open `http://127.0.0.1:5000`
4. Test each connection from the UI
5. Watch the Dashboard and Live Events pages

If you want a more production-like setup:

1. Set `storage.backend: postgres`
2. Set `storage.postgres_dsn`
3. Optionally enable `pipeline.delivery.async_enabled: true`
4. Optionally enable `pipeline.delivery.store_first_ingest: true`
5. Run the main pipeline plus any required worker processes
