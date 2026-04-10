# Security Middleware Pipeline

**Wazuh / DefectDojo → Middleware → Redmine**

A Python middleware service that ingests security findings from **Wazuh SIEM** and **DefectDojo**, processes them through a normalization pipeline, and creates/updates tickets in **Redmine**.

---

## Architecture

```
 ┌─────────────────┐     ┌─────────────────────────────────────────────┐     ┌──────────────┐
 │  Log Collection  │     │              MIDDLEWARE                     │     │              │
 │  ───────────────│     │                                             │     │              │
 │  Syslog, Agents ├────►│  ┌────────┐  ┌────────┐  ┌─────┐  ┌─────┐ │     │   REDMINE    │
 │                 │     │  │ Filter │→│Severity│→│Dedup│→│Enrich│──────►│              │
 │  Wazuh SIEM     │     │  │        │  │ Mapper │  │     │  │     │ │     │  Issue       │
 └─────────────────┘     │  └────────┘  └────────┘  └─────┘  └─────┘ │     │  Tracker     │
                         │                                             │     │              │
 ┌─────────────────┐     │                                             │     │              │
 │  DefectDojo     ├────►│                                             │     │              │
 │  Vuln Mgmt      │     └─────────────────────────────────────────────┘     └──────────────┘
 └─────────────────┘
```

## Pipeline Stages

| Stage | Description |
|-------|-------------|
| **Filter** | Drop noise: minimum severity, excluded rule IDs, host/title patterns |
| **Severity Mapper** | Normalize Wazuh levels (0–15) and DefectDojo strings → unified scale → Redmine priority |
| **Deduplicator** | SHA-256 hash-based dedup with SQLite storage and configurable TTL |
| **Enricher** | Add asset metadata, remediation links, CVSS context; format Redmine description |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

Edit `config/config.yaml` with your API credentials:

```yaml
wazuh:
  base_url: "https://your-wazuh:55000"
  username: "api-user"
  password: "your-password"

defectdojo:
  base_url: "https://your-defectdojo/api/v2"
  api_key: "Token your-api-key"

redmine:
  base_url: "https://your-redmine"
  api_key: "your-redmine-api-key"
  project_id: "security-incidents"
```

Or use environment variables:
```bash
export WAZUH_BASE_URL="https://your-wazuh:55000"
export WAZUH_USERNAME="api-user"
export WAZUH_PASSWORD="secret"
export DEFECTDOJO_API_KEY="Token your-key"
export REDMINE_API_KEY="your-key"
```

### 3. Run

```bash
# Continuous polling mode
python -m src.main

# Single cycle (useful for cron)
python -m src.main --once

# Test connections only
python -m src.main --test

# Custom config path
python -m src.main -c /path/to/config.yaml
```

### 4. Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f middleware

# Run single cycle
docker-compose run middleware --once
```

---

## Configuration Reference

### Filter Rules

```yaml
pipeline:
  filter:
    min_severity: "medium"          # Drop anything below medium
    exclude_rule_ids: ["550"]       # Ignore specific Wazuh rule IDs
    include_hosts: ["web-.*"]       # Only process these hosts (regex)
    exclude_title_patterns:         # Drop findings matching these titles
      - "^Syscheck.*"
```

### Severity Mapping

| Wazuh Level | DefectDojo | Unified | Redmine Priority |
|-------------|------------|---------|------------------|
| 15          | Critical   | critical | 5 (Immediate)   |
| 12–14       | High       | high     | 4 (Urgent)      |
| 7–11        | Medium     | medium   | 3 (High)        |
| 4–6         | Low        | low      | 2 (Normal)      |
| 0–3         | Info       | info     | 1 (Low)         |

### Deduplication

```yaml
pipeline:
  dedup:
    enabled: true
    db_path: "data/dedup.db"      # SQLite database location
    ttl_hours: 168                 # Re-create ticket after 7 days
```

---

## Project Structure

```
security-middleware/
├── config/
│   └── config.yaml              # Configuration
├── src/
│   ├── main.py                  # Entry point
│   ├── config.py                # Config loader
│   ├── models/
│   │   └── finding.py           # Unified data model
│   ├── sources/
│   │   ├── wazuh_client.py      # Wazuh API client
│   │   └── defectdojo_client.py # DefectDojo API client
│   ├── pipeline/
│   │   ├── filter.py            # Filter stage
│   │   ├── severity_mapper.py   # Severity mapping
│   │   ├── deduplicator.py      # Deduplication
│   │   └── enricher.py          # Enrichment
│   └── output/
│       └── redmine_client.py    # Redmine API client
├── tests/                       # Unit & integration tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_filter.py -v
```

---

## License

Internal use only.
