# Security Middleware Pipeline

**Wazuh / DefectDojo → Middleware → Redmine**

A Python middleware service that ingests security findings from **Wazuh SIEM** and **DefectDojo**, processes them through a normalization pipeline, and creates/updates tickets in **Redmine**.

---

## Engineering Docs

- [Implementation Plan](C:/Users/ifilm/Downloads/Document/security-middleware/IMPLEMENTATION_PLAN.md)
- [Frontend Developer README](C:/Users/ifilm/Downloads/Document/security-middleware/web/FRONTEND_README.md)

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
| **Deduplicator** | SHA-256 hash-based dedup with local SQLite or shared Postgres storage and configurable TTL |
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

# Run the Redmine delivery worker for queued jobs
python -m src.main --delivery-worker

# Run the persisted-ingest decision worker
python -m src.main --decision-worker

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

### 5. Quick Start — Amazon Linux (EC2)

Step-by-step deployment on **Amazon Linux 2023** or **Amazon Linux 2** running on EC2.

#### Prerequisites

```bash
# Amazon Linux 2023
sudo dnf update -y
sudo dnf install -y python3.11 python3.11-pip git sqlite

# Amazon Linux 2 (if python3.11 is not in the default repo)
sudo yum update -y
sudo amazon-linux-extras install python3.8 -y
sudo yum install -y git sqlite
```

#### Clone & Setup

```bash
# Clone the repository
cd /opt
sudo git clone https://github.com/Ratthapoom681/middleware.git security-middleware
sudo chown -R ec2-user:ec2-user security-middleware
cd security-middleware

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### Configure (environment variables recommended on EC2)

```bash
# Create an env file for secrets
sudo mkdir -p /etc/security-middleware
sudo tee /etc/security-middleware/env > /dev/null <<EOF
WAZUH_BASE_URL=https://your-wazuh-manager:55000
WAZUH_USERNAME=api-user
WAZUH_PASSWORD=your-password
DEFECTDOJO_BASE_URL=https://your-defectdojo/api/v2
DEFECTDOJO_API_KEY=Token your-api-key
REDMINE_BASE_URL=https://your-redmine
REDMINE_API_KEY=your-redmine-api-key
EOF

# Lock down permissions
sudo chmod 600 /etc/security-middleware/env
sudo chown ec2-user:ec2-user /etc/security-middleware/env
```

#### Test the connection

```bash
cd /opt/security-middleware
source venv/bin/activate
set -a; source /etc/security-middleware/env; set +a

# Verify connectivity to Wazuh, DefectDojo, Redmine
python -m src.main --test

# Run a single cycle to confirm the pipeline works
python -m src.main --once
```

#### Run as a systemd service (persistent)

```bash
sudo tee /etc/systemd/system/security-middleware.service > /dev/null <<EOF
[Unit]
Description=Security Middleware Pipeline
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/security-middleware
EnvironmentFile=/etc/security-middleware/env
ExecStart=/opt/security-middleware/venv/bin/python -m src.main
Restart=on-failure
RestartSec=30

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/security-middleware/data

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable security-middleware
sudo systemctl start security-middleware

# Check status and logs
sudo systemctl status security-middleware
sudo journalctl -u security-middleware -f
```

#### (Optional) CloudWatch log forwarding

```bash
# Install the CloudWatch agent
sudo yum install -y amazon-cloudwatch-agent

# Add middleware logs to the CloudWatch config (/opt/aws/amazon-cloudwatch-agent/etc/)
# Point it at the journal for the security-middleware unit:
#   "collect_list": [{
#     "log_group_name": "/ec2/security-middleware",
#     "log_stream_name": "{instance_id}",
#     "journal_log": { "unit": "security-middleware" }
#   }]

sudo systemctl restart amazon-cloudwatch-agent
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

### Shared State Storage

```yaml
storage:
  backend: "postgres"              # local or postgres
  postgres_dsn: "postgresql://middleware:secret@db/security"
  postgres_schema: "middleware"
  dedup_table: "middleware_seen_hashes"
  checkpoint_table: "middleware_checkpoints"
  ticket_state_table: "middleware_ticket_state"
  outbound_queue_table: "middleware_outbound_queue"
  ingest_event_table: "middleware_ingest_events"

pipeline:
  delivery:
    async_enabled: false
    worker_poll_interval: 10
    worker_batch_size: 25
    retry_delay_seconds: 60
    recheck_ttl_minutes: 15
    store_first_ingest: false
```

When `storage.backend` is set to `postgres`:
- dedup state moves from local SQLite into Postgres
- DefectDojo incremental checkpoints move from local JSON files into Postgres
- ticket-state cache, ingest-event staging, and outbound queue can use the same shared Postgres schema
- multiple middleware instances can share the same state safely

When `pipeline.delivery.store_first_ingest` is enabled:
- raw Wazuh and DefectDojo payloads are persisted into `storage.ingest_event_table` before filter/dedup/enrich runs
- the normal poller can process those persisted events immediately, or you can drain them with `python -m src.main --decision-worker`
- DefectDojo checkpoints only advance after the persisted ingest batch has been processed successfully

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
