# Frontend Developer README

This document is for frontend work on the Security Middleware web UI.

The current frontend is a server-rendered static app:

- HTML: [index.html](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/index.html)
- CSS: [styles.css](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/css/styles.css)
- JavaScript: [app.js](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/js/app.js)
- Backend API: [server.py](C:/Users/ifilm/Downloads/Document/security-middleware/web/server.py)

There is no bundler, no framework, and no component system yet. The page is a single-screen admin console with section navigation.

## Goals

The UI is used for:

- editing and saving middleware config
- testing Wazuh, DefectDojo, and Redmine connections
- managing DefectDojo scope/filter controls
- editing advanced JSON filter rules
- monitoring live activity and dashboard summaries
- previewing generated YAML before save

The frontend should favor:

- operational clarity over decoration
- fast scanning for security operators
- explicit warnings for risky settings
- preserving all config fields during round-trip save/load

## Current Architecture

The browser loads `/`, which serves the static HTML shell.

The page then:

1. calls `/api/config`
2. hydrates the form with `populateForm()`
3. edits data in DOM fields and in-memory helpers like `chipData`
4. builds a config payload with `collectForm()`
5. saves to `/api/config`

There is one main global state object in [app.js](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/js/app.js):

- `config`
- `chipData`
- `defectDojoScopeData`
- `latestWebhookHistory`

## Main UI Sections

Navigation is driven by `data-section` and `page-<section>` IDs.

Current sections:

- `wazuh`
- `defectdojo`
- `redmine`
- `filter`
- `dedup`
- `enrichment`
- `dashboard`
- `live`
- `logging`
- `preview`

If you add a new section, update:

- the nav item in [index.html](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/index.html)
- the page container ID
- `sectionTitles` in [app.js](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/js/app.js)

## Key Frontend Patterns

### 1. Plain DOM manipulation

There is no reactive framework. The UI uses:

- `document.getElementById`
- `querySelectorAll`
- event listeners
- direct `.value`, `.checked`, and `.innerHTML`

When adding features, keep logic centralized in helper functions instead of scattering DOM updates.

### 2. Form hydration and collection

The two most important functions are:

- `populateForm(c)`
- `collectForm()`

If you add a new config field, update both or the UI will silently drop data on save.

### 3. Chips and multi-select state

Several inputs are not native arrays in the DOM, so they are tracked separately.

Examples:

- chip inputs for severity filters and include/exclude rules
- DefectDojo scope selectors

When adding a list-like field, check whether it belongs in:

- `chipData`
- a standard input
- a multi-select helper

### 4. JSON textarea rules

Advanced JSON filter rules use a textarea, but the saved config is structured JSON/YAML.

Relevant helpers:

- `setJsonTextarea()`
- `getJsonTextareaValue()`
- `loadJsonRuleExample()`

Examples are intentionally built into the UI so users do not start from an empty box.

## Backend Endpoints Used by the UI

Core config endpoints:

- `GET /api/config`
- `POST /api/config`
- `GET /api/config/raw`
- `POST /api/config/raw`
- `POST /api/config/validate`
- `GET /api/config/backups`
- `POST /api/config/backups/restore/<filename>`

Connection testing:

- `POST /api/config/test/wazuh`
- `POST /api/config/test/defectdojo`
- `POST /api/config/test/redmine`

Redmine:

- `POST /api/redmine/trackers`

DefectDojo:

- `POST /api/defectdojo/scope-data`
- `POST /api/defectdojo/finding-count`

Monitoring:

- `GET /api/webhook/history`

Important note:

- most UI actions send the full current config snapshot, not just one field
- if frontend code drops unknown fields, it can unintentionally erase backend config

## DefectDojo UI Notes

The DefectDojo page currently supports:

- severity chips
- active/verified flags
- updated-since and fetch-limit
- product/engagement/test scope selectors
- scope sync button
- finding count preview
- warnings for dangerous broad fetch settings

The scope selectors depend on returned API data and client-side narrowing:

- selected products narrow engagements
- selected engagements narrow tests

If you touch this flow, re-check:

- `syncDefectDojoScopeData()`
- `updateDefectDojoScopeFilters()`
- `previewDefectDojoFindingCount()`
- `renderDefectDojoWarnings()`

## Dashboard Notes

The dashboard currently renders from `/api/webhook/history`.

Relevant functions:

- `fetchLiveEvents()`
- `renderDashboard()`

The dashboard is now backed by persisted middleware event history, but the current frontend still treats it as a lightweight recent-events feed.

If the team moves to OpenSearch-backed monitoring, this page will likely be one of the biggest frontend refactors.

## Redmine UI Notes

The Redmine UI currently configures:

- project/tracker settings
- priority map
- routing rules

Routing rules are edited client-side and then saved back into config. If you change that editor, be careful not to break backward compatibility with existing saved YAML.

## Wazuh Ticket Formatting

Current product behavior:

- Wazuh tickets should be easy to read and point directly to the problem
- raw alert data must still be included
- DefectDojo ticket formatting should not be changed for now

That formatting logic is backend-owned in [enricher.py](C:/Users/ifilm/Downloads/Document/security-middleware/src/pipeline/enricher.py) and [redmine_client.py](C:/Users/ifilm/Downloads/Document/security-middleware/src/output/redmine_client.py).

The frontend should treat that as display-independent business logic unless the team explicitly decides to move preview/rendering into the UI.

## Local Development

Typical local run:

```powershell
& 'C:\Users\ifilm\Downloads\Document\security-middleware\.venv\Scripts\python.exe' -m web.server
```

Then open:

- [http://127.0.0.1:5000](http://127.0.0.1:5000)

There is no separate frontend dev server right now.

## Testing Guidance

Frontend coverage in this repo is mostly static/integration-style Python tests, not browser unit tests.

Useful files:

- [test_web_ui.py](C:/Users/ifilm/Downloads/Document/security-middleware/tests/test_web_ui.py)

When you add UI features, at minimum update tests that verify:

- new field tokens exist in HTML or JS
- new config fields round-trip through save/load
- new API responses are handled safely

Recommended quick check:

```powershell
& 'C:\Users\ifilm\Downloads\Document\security-middleware\.venv\Scripts\python.exe' -m pytest tests/test_web_ui.py -q
```

## Frontend Conventions

- Keep the UI dependency-free unless there is a strong reason to add a library.
- Preserve all existing config fields on save.
- Prefer small helper functions over long anonymous event handlers.
- Avoid inline business logic that belongs in the backend.
- Add examples and warnings for advanced/operator-facing controls.
- Treat this as an operations console, not a marketing site.

## Known Gaps

These are good candidates for frontend work:

- better auth/session UX once config API authentication is added
- improved dashboard widgets and historical filtering
- better queue/retry visibility once async delivery exists
- more structured editors for advanced JSON rules
- friendlier validation around dangerous Redmine/DefectDojo settings
- eventual migration to a componentized frontend if the UI grows much further

## Safe Frontend Workflow

When adding or changing UI fields:

1. Add the field in [index.html](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/index.html)
2. Hydrate it in `populateForm()`
3. Collect it in `collectForm()`
4. Add any helper rendering or validation in [app.js](C:/Users/ifilm/Downloads/Document/security-middleware/web/static/js/app.js)
5. Update backend config serialization if needed in [server.py](C:/Users/ifilm/Downloads/Document/security-middleware/web/server.py)
6. Add or update UI tests in [test_web_ui.py](C:/Users/ifilm/Downloads/Document/security-middleware/tests/test_web_ui.py)

That round-trip discipline is the most important thing in this codebase’s frontend.
