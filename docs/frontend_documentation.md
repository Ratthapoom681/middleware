# Frontend Documentation

## Security Middleware Pipeline — Web Dashboard & Configuration UI

---

## 1. Architecture Overview

The frontend is a **Single-Page Application (SPA)** served as static files by a Python Flask backend. It follows a **monolithic single-file architecture** where all UI logic, state management, and API communication are contained in a single HTML entry point backed by dedicated CSS and JavaScript files.

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER (SPA)                            │
│                                                                 │
│   index.html ──► app.js (logic + state + rendering)             │
│                  styles.css (design system + layout)             │
│                                                                 │
│   ┌──────────┐  ┌──────────────┐  ┌───────────┐  ┌───────────┐ │
│   │Dashboard │  │Config Editor │  │Live Events│  │ Settings  │ │
│   │  (Tab)   │  │   (Tab)      │  │  (Tab)    │  │  (Tab)    │ │
│   └──────────┘  └──────────────┘  └───────────┘  └───────────┘ │
│         │               │                │              │       │
│         ▼               ▼                ▼              ▼       │
│   ┌────────────────────────────────────────────────────────────┐│
│   │              Fetch API → Flask REST Endpoints              ││
│   └────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Key Characteristics

| Aspect | Detail |
|--------|--------|
| **Rendering Model** | Client-side rendering (CSR) — all DOM manipulation via vanilla JavaScript |
| **Bundling** | None — raw ES6 JavaScript served directly (no webpack/vite) |
| **Framework** | Zero-framework — vanilla HTML/CSS/JS |
| **Routing** | Tab-based in-page navigation (no URL routing / hash routing) |
| **Data Fetching** | Native `fetch()` API with JSON request/response |
| **Design Language** | Cyber-Industrial dark theme with glassmorphism and neon accents |

---

## 2. Technologies & Frameworks

| Technology | Version | Purpose |
|------------|---------|---------|
| **HTML5** | — | Semantic page structure |
| **CSS3** | — | Custom properties, grid, flexbox, animations |
| **Vanilla JavaScript** | ES6+ | Application logic, DOM manipulation, API calls |
| **Google Fonts** | Inter, JetBrains Mono | Typography (sans-serif UI + monospace code) |
| **Flask** | ≥3.0.0 | Static file serving via `send_from_directory` |

> [!NOTE]
> The frontend intentionally avoids build tools, transpilers, or UI frameworks. This keeps deployment simple — the Flask server serves raw static files directly from `web/static/`.

---

## 3. Folder Structure

```
web/
├── __init__.py               # Python package marker
├── server.py                 # Flask API server (serves static + REST endpoints)
├── FRONTEND_README.md        # Frontend-specific documentation
└── static/
    ├── index.html            # SPA entry point (~49KB) — full page structure
    ├── css/
    │   └── styles.css        # Design system + all component styles (~22KB)
    └── js/
        └── app.js            # Application logic + state + rendering (~72KB)
```

### File Responsibilities

#### `index.html` (Entry Point)
- Complete HTML structure with semantic sections
- Tab navigation container with 4 primary views
- Modal templates for connection testing, backup restore, etc.
- Inline `<meta>` tags for viewport and charset
- External stylesheet and script references

#### `styles.css` (Design System)
- CSS custom properties (design tokens) for colors, spacing, typography
- Dark theme with HSL-based color palette
- Component-level styles: cards, forms, tables, badges, modals, toasts
- Responsive breakpoints and layout utilities
- Micro-animations and transitions
- Bar chart styles for activity visualization

#### `app.js` (Application Core)
- Tab navigation controller
- Configuration CRUD (load, edit, save, validate, backup/restore)
- Service connection testing (Wazuh, DefectDojo, Redmine)
- Live event dashboard with auto-refresh polling
- Dashboard statistics aggregation and chart rendering
- Dynamic form generation for routing rules and filter JSON rules
- Toast notification system
- Error handling and retry logic

---

## 4. UI Components & Views

### 4.1 Tab Navigation

The SPA uses a tab-based navigation pattern. Each tab maps to a `<section>` element that is toggled via CSS `display` property.

| Tab | Purpose | Key Features |
|-----|---------|--------------|
| **Dashboard** | Pipeline overview | Activity stats, bar chart (7-day history), severity breakdown |
| **Configuration** | Config editor | Section-based forms for Wazuh, DefectDojo, Redmine, Pipeline, Storage |
| **Live Events** | Real-time monitor | Auto-refreshing webhook/polling event log with finding details |
| **Settings** | System management | Backup management, config validation, raw YAML editor |

### 4.2 Configuration Editor

The configuration editor provides structured forms for each config section:

```
Configuration Tab
├── Wazuh SIEM
│   ├── Manager API (base_url, username, password)
│   ├── Indexer API (indexer_url, indexer_username, indexer_password)
│   ├── SSL verification toggle
│   ├── Minimum alert level slider
│   └── File reader path (alerts.json)
│
├── DefectDojo
│   ├── Enable/disable toggle
│   ├── API connection (base_url, api_key, verify_ssl)
│   ├── Scope selectors (product_ids, engagement_ids, test_ids)
│   ├── Severity filter checkboxes
│   ├── Fetch parameters (limit, cursor_path, updated_since_minutes)
│   └── Finding count preview
│
├── Redmine
│   ├── API connection (base_url, api_key, project_id)
│   ├── Default tracker selection (with live fetch from Redmine)
│   ├── Parent issue configuration
│   ├── Dedup custom field ID
│   ├── Priority mapping table
│   └── Dynamic routing rules editor
│
├── Pipeline
│   ├── Polling interval and lookback
│   ├── Filter configuration (severity, exclusions, patterns)
│   ├── Advanced JSON filter rules builder
│   ├── Deduplication settings (enable, TTL, db_path)
│   └── Enrichment toggles
│
└── Storage
    ├── Backend selector (local / postgres)
    └── Postgres DSN and table names
```

### 4.3 Live Events Dashboard

```javascript
// Polling pattern (simplified)
setInterval(async () => {
    const response = await fetch('/api/webhook/history');
    const data = await response.json();
    renderEventList(data.history);
}, 5000); // 5-second refresh
```

Each event card displays:
- Timestamp and origin (webhook vs. polling)
- Source breakdown (Wazuh count, DefectDojo count)
- Per-finding detail rows: title, severity badge, action taken, dedup reason
- Routing metadata: matched rule, selected tracker, source link

### 4.4 Dashboard Chart

A custom CSS/JS bar chart renders 7-day activity history:
- Each bar represents one day's finding count
- Height is proportionally scaled to the maximum day's count
- Day labels and count labels are rendered dynamically
- Data is fetched from `/api/logs/stats` or derived from `/api/webhook/history`

---

## 5. State Management

### Approach: In-Memory Singleton State

The application uses a simple in-memory state object managed in `app.js`. There is no external state management library.

```javascript
// Conceptual state shape
const appState = {
    currentTab: 'dashboard',       // Active navigation tab
    config: { ... },               // Full config object from /api/config
    configDirty: false,            // Whether unsaved changes exist
    webhookHistory: [],            // Last 200 pipeline events
    connectionStatuses: {          // Per-service test results
        wazuh: null,
        defectdojo: null,
        redmine: null,
    },
    backups: [],                   // Available config backups
    redmineTrackers: [],           // Fetched tracker list
    defectdojoScopeData: {},       // Products, engagements, tests
};
```

### State Flow

```
User Action → DOM Event Handler → State Update → Re-render Component
                                       ↓
                              (if save) → fetch('/api/config', POST)
                                       → Toast notification
```

> [!IMPORTANT]
> State is **not persisted** across page reloads. All configuration state is re-fetched from the Flask API on page load. This ensures the frontend always reflects the latest `config.yaml` on disk.

---

## 6. API Consumption

### API Client Pattern

All API calls use the native `fetch()` API with a consistent pattern:

```javascript
async function apiCall(url, method = 'GET', body = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (data.status === 'error') {
        throw new Error(data.message || 'API error');
    }
    return data;
}
```

### API Endpoints Consumed

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /api/config` | GET | Load current configuration with defaults |
| `POST /api/config` | POST | Save configuration (creates backup automatically) |
| `GET /api/config/raw` | GET | Load raw YAML text |
| `POST /api/config/raw` | POST | Save raw YAML directly |
| `POST /api/config/validate` | POST | Validate config without saving |
| `GET /api/config/backups` | GET | List available backup files |
| `POST /api/config/backups/restore/:filename` | POST | Restore a specific backup |
| `POST /api/config/test/:service` | POST | Test connection to Wazuh/DefectDojo/Redmine |
| `POST /api/redmine/trackers` | POST | Fetch Redmine tracker list |
| `POST /api/defectdojo/scope-data` | POST | Fetch DefectDojo products/engagements/tests |
| `POST /api/defectdojo/finding-count` | POST | Preview finding count for current filters |
| `GET /api/webhook/history` | GET | Fetch last 200 pipeline events |
| `POST /api/webhook/wazuh` | POST | *(Consumed by Wazuh, not frontend)* |

---

## 7. Error Handling

### Frontend Error Strategy

```
┌──────────────────────────────────────────────────────────────┐
│                    Error Handling Flow                        │
│                                                              │
│  fetch() ──► HTTP Error?                                     │
│                │                                             │
│                ├─ Yes ──► response.status check              │
│                │           ├─ 400 → Validation error toast   │
│                │           ├─ 404 → Resource not found toast │
│                │           └─ 500 → Server error toast       │
│                │                                             │
│                └─ No ──► Parse JSON ──► data.status check    │
│                                          ├─ "error" → Toast │
│                                          ├─ "warning" → Toast│
│                                          └─ "ok" → Continue │
└──────────────────────────────────────────────────────────────┘
```

### Toast Notification System

All errors, warnings, and success messages are displayed via a custom toast notification system:

```javascript
function showToast(message, type = 'info') {
    // type: 'success', 'error', 'warning', 'info'
    // Creates a temporary DOM element with auto-dismiss after 5s
}
```

### Graceful Degradation

- **Network failures**: Catch blocks around all `fetch()` calls display user-friendly error messages
- **Missing data**: Templates use fallback values (`'N/A'`, `'unknown'`, `0`)
- **Service unavailability**: Connection test UI shows clear ✅/❌ indicators per service
- **Config validation**: Pre-save validation warns about default credentials, missing URLs, and risky settings

---

## 8. Design System

### Color Palette (CSS Custom Properties)

```css
:root {
    --bg-primary: hsl(220, 20%, 8%);       /* Deep dark background */
    --bg-secondary: hsl(220, 18%, 12%);    /* Card backgrounds */
    --bg-tertiary: hsl(220, 16%, 16%);     /* Input backgrounds */
    --text-primary: hsl(220, 20%, 90%);    /* Primary text */
    --text-secondary: hsl(220, 15%, 60%);  /* Muted text */
    --accent-cyan: hsl(190, 90%, 55%);     /* Primary accent */
    --accent-orange: hsl(30, 90%, 55%);    /* Warning accent */
    --severity-critical: hsl(0, 80%, 55%); /* Red */
    --severity-high: hsl(30, 90%, 55%);    /* Orange */
    --severity-medium: hsl(45, 90%, 55%);  /* Yellow */
    --severity-low: hsl(210, 70%, 55%);    /* Blue */
    --severity-info: hsl(0, 0%, 60%);      /* Gray */
}
```

### Typography

| Element | Font | Weight |
|---------|------|--------|
| Headings | Inter | 600–700 |
| Body text | Inter | 400 |
| Code / hashes | JetBrains Mono | 400 |
| Badges | Inter | 600 |

### Component Library

| Component | Description |
|-----------|-------------|
| **Card** | Glassmorphic container with subtle border and backdrop blur |
| **Form Group** | Label + input/select with consistent spacing |
| **Badge** | Color-coded severity/status indicators |
| **Toggle** | Custom CSS switch for boolean settings |
| **Table** | Styled data table with alternating row colors |
| **Modal** | Overlay dialog for confirmations and test results |
| **Toast** | Auto-dismissing notification banner |
| **Bar Chart** | CSS-driven vertical bar chart for activity history |
| **Accordion** | Collapsible sections for routing rules and JSON filters |

---

## 9. Best Practices for Scalability & Performance

### Current Optimizations

- **No build step**: Zero compilation overhead — instant deployment
- **Single HTTP request**: All CSS and JS loaded in one round-trip each
- **Lazy rendering**: Tab content only updates when the tab is active
- **Event delegation**: Minimal event listeners using delegation patterns
- **Polling throttle**: Live events poll at 5-second intervals (not continuous)

### Recommendations for Scale

| Concern | Recommendation |
|---------|----------------|
| **Bundle size** | If app.js grows beyond ~100KB, split into ES modules |
| **State management** | Consider a lightweight store (Zustand, Nanostores) if state complexity grows |
| **Component reuse** | Extract common patterns (cards, forms) into Web Components |
| **API caching** | Add `Cache-Control` headers for static config reads |
| **WebSocket** | Replace polling with WebSocket for live events when latency matters |
| **Accessibility** | Add ARIA labels, keyboard navigation, and focus management |
| **Testing** | Add Playwright/Cypress E2E tests for critical flows (config save, connection test) |
| **i18n** | Externalize strings into a JSON locale file for multi-language support |

### Security Considerations

- **No client-side secrets**: All API keys and passwords are stored in `config.yaml` server-side
- **CSRF**: Flask should add CSRF protection for mutation endpoints
- **XSS**: Use `textContent` instead of `innerHTML` for user-generated content
- **Input validation**: All config values are validated server-side by `_build_config()` before persistence

---

## 10. Development Workflow

### Running the Frontend

```bash
# Start the Flask development server (serves both API and static files)
python -m web.server --debug --port 5000

# Or start the full pipeline with embedded Web UI
python -m src.main --port 5000 --debug
```

### Editing the Frontend

1. Edit files in `web/static/` (HTML, CSS, JS)
2. Refresh the browser — no build step required
3. Flask's `debug` mode enables auto-reloading for `server.py` changes

### File Size Reference

| File | Size | Lines |
|------|------|-------|
| `index.html` | ~49KB | ~1200 |
| `styles.css` | ~22KB | ~800 |
| `app.js` | ~72KB | ~2000 |

---

## 11. Key Patterns for Onboarding Developers

### Tab Switching

```javascript
function switchTab(tabName) {
    // 1. Update nav button active states
    // 2. Hide all section containers
    // 3. Show the selected section
    // 4. Trigger data refresh for the active tab
}
```

### Dynamic Form Rendering (Routing Rules)

```javascript
function renderRoutingRules(rules) {
    const container = document.getElementById('routing-rules');
    container.innerHTML = '';
    rules.forEach((rule, index) => {
        const row = createRoutingRuleRow(rule, index);
        container.appendChild(row);
    });
}
```

### Config Save Flow

```
User clicks "Save" → Collect form values → Build config JSON
                                               ↓
                              POST /api/config → Server validates
                                               → Creates timestamped backup
                                               → Writes config.yaml
                                               → Returns success/error
                                               ↓
                                     Toast notification → Refresh displayed config
```
