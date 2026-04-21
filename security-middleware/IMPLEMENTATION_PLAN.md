# Implementation Plan

This document turns the planned architecture changes into an implementable roadmap for the current codebase.

It is written against the current repository shape:

- pipeline entrypoint: `src/main.py`
- state storage: `src/state_store.py`
- dashboard event history: `src/dashboard_history.py`
- source clients: `src/sources/`
- pipeline stages: `src/pipeline/`
- Redmine output: `src/output/redmine_client.py`
- web UI/API: `web/server.py`, `web/static/`

## Goals

- move from direct inline ticket delivery toward a store-first pipeline
- keep `Postgres` as the source of truth for state and queueing
- use `OpenSearch` for searchable event history and dashboards
- preserve current Wazuh and DefectDojo ingestion behavior during migration
- keep Wazuh ticket formatting readable
- do not change DefectDojo ticket formatting yet

## Non-Goals

- do not use OpenSearch as the dedup/checkpoint database
- do not replace the entire UI in one step
- do not remove the current synchronous flow until the async path is proven

## Key Architectural Decision

Use:

- `Postgres` for authoritative middleware state
- `OpenSearch` for historical events and monitoring

Why:

- dedup, checkpoints, ticket mapping, retries, and queues need transactional updates
- dashboards, timeline queries, and lookback searches fit OpenSearch much better

## Current Reusable Building Blocks

### Already reusable with limited changes

- `src/main.py`
  - current orchestration entrypoint
  - can be split into ingest, decision, and delivery workers over time

- `src/state_store.py`
  - already owns shared Postgres state for dedup and checkpoints
  - best place to grow queue tables and ticket-state tables

- `src/dashboard_history.py`
  - current durable event history abstraction
  - can become the adapter boundary for OpenSearch event writes later

- `src/pipeline/filter.py`
  - already handles business filtering and JSON rules

- `src/pipeline/deduplicator.py`
  - already centralizes dedup decisions
  - should remain focused on local/shared state, not live Redmine API calls

- `src/pipeline/enricher.py`
  - already owns description formatting and enrichment
  - correct place for source-specific Redmine presentation rules

- `src/output/redmine_client.py`
  - should become a delivery adapter used by an outbound worker

- `web/server.py`
  - already exposes config, preview, test, and monitoring endpoints
  - will need new queue and monitoring endpoints later

## Target Flow

Target processing order:

1. ingest raw payload
2. persist raw event immediately
3. normalize into canonical middleware event fields
4. run filter rules
5. run dedup against Postgres state
6. reconcile ticket state if needed
7. enrich surviving findings
8. enqueue Redmine work
9. deliver to Redmine asynchronously
10. store delivery outcome for monitoring and retries

Do not enrich everything before filter/dedup. That wastes work at high volume.

## Target Data Model

### Postgres tables

Add or evolve these tables under the configured middleware schema:

- `middleware_seen_hashes`
  - existing dedup registry
  - keep as the canonical dedup table

- `middleware_checkpoints`
  - existing DefectDojo checkpoint table
  - keep as the canonical checkpoint table

- `middleware_ticket_state`
  - `dedup_hash`
  - `redmine_issue_id`
  - `issue_state`
  - `tracker_id`
  - `subject`
  - `ticket_exists`
  - `last_ticket_check_at`
  - `last_ticket_seen_at`
  - `last_delivery_status`
  - `last_error`

- `middleware_outbound_queue`
  - `job_id`
  - `dedup_hash`
  - `action`
  - `payload`
  - `status`
  - `attempt_count`
  - `next_attempt_at`
  - `locked_at`
  - `locked_by`
  - `last_error`
  - `created_at`
  - `updated_at`

- `middleware_ingest_events`
  - optional staging table if we want Postgres-backed store-first ingest before OpenSearch is ready
  - raw payload plus normalized key fields

### OpenSearch indices

Keep middleware telemetry separate from Wazuh-managed indices.

Recommended index families:

- `middleware-events-*`
- `middleware-delivery-*`
- `middleware-errors-*`

Recommended event fields:

- `event_id`
- `source`
- `source_id`
- `event_timestamp`
- `processed_timestamp`
- `severity`
- `rule_id`
- `decoder_name`
- `host`
- `srcip`
- `found_by`
- `endpoint_url`
- `matched_filter_rule`
- `dedup_hash`
- `dedup_reason`
- `selected_tracker`
- `queue_action`
- `delivery_status`
- `redmine_issue_id`
- `source_link`
- raw payload

## Worker Split

### Phase 1 workers

- `ingest worker`
  - receives webhook/poll data
  - normalizes and stores events

- `decision worker`
  - reads stored events
  - runs filter and dedup
  - creates queue actions

- `delivery worker`
  - reads pending queue jobs
  - calls `RedmineClient`
  - updates ticket state and queue status

### Phase 2 workers

- `reconcile worker`
  - rechecks stale or suspicious ticket mappings
  - handles `recheck_ticket`, missing tickets, and closed-ticket transitions

- `analytics writer`
  - pushes processed event envelopes into OpenSearch

## Queue Actions

Use explicit queue actions instead of ad-hoc state transitions:

- `create_ticket`
- `update_ticket`
- `reopen_ticket`
- `recreate_ticket`
- `recheck_ticket`

Rules:

- dedup should not call Redmine directly for every decision
- delivery worker owns Redmine mutations
- reconcile worker owns stale ticket verification

## Phased Migration Plan

### Phase 0: correctness and safety

- finish remaining correctness fixes in current flow
- add auth for webhook/config endpoints
- finish removing SQLite-specific correctness gaps
- keep current synchronous pipeline intact as fallback

### Phase 1: Postgres ticket cache and queue

- extend `src/state_store.py` with:
  - ticket-state CRUD
  - outbound queue CRUD
  - queue locking helpers
- keep current ingest path in `src/main.py`
- change Redmine sending from direct inline mutation to queue writes behind a feature flag
- add delivery worker entrypoint

### Phase 2: store-first event persistence

- add canonical ingest-event storage abstraction
- persist raw Wazuh and DefectDojo payloads before processing
- keep normalized fields beside raw payload
- update webhook and polling paths to write ingest records first

### Phase 3: ticket reconcile flow

- add `middleware_ticket_state`
- add `recheck_ticket` queue action
- implement stale-check TTL logic
- move closed/missing ticket recovery logic out of inline dedup decisions

### Phase 4: OpenSearch event history

- add OpenSearch client/config
- write processed middleware events into middleware-owned indices
- move dashboard reads away from local/Postgres history into OpenSearch-backed queries

### Phase 5: UI and monitoring upgrades

- add queue status APIs in `web/server.py`
- add delivery/retry/reconcile widgets in the dashboard
- expose time-range queries and top failure reasons
- preserve current config editor workflow

### Phase 6: retire direct synchronous Redmine path

- make queue-based delivery the default
- keep direct path only as a temporary fallback or remove it after soak time

## File-by-File Ownership

### `src/config.py`

Add configuration for:

- OpenSearch connection settings
- queue worker tuning
- reconcile TTLs
- feature flags for async delivery and store-first ingest

### `src/state_store.py`

Primary owner for:

- ticket-state table
- outbound queue table
- queue locking
- retry scheduling
- future migration helpers

### `src/main.py`

Refactor toward:

- orchestrator for ingest and decision flow
- minimal shared bootstrapping logic
- worker-specific entrypoints

### `src/pipeline/deduplicator.py`

Keep focused on:

- dedup key/hash generation
- local/shared state lookup
- returning `new` vs `repeat`

Do not make it responsible for live Redmine rechecks.

### `src/pipeline/enricher.py`

Keep focused on:

- human-readable ticket descriptions
- source-specific formatting
- asset and remediation enrichment

### `src/output/redmine_client.py`

Treat as:

- delivery adapter
- ticket fetch/update/create helper for delivery and reconcile workers

### `web/server.py`

Add APIs later for:

- queue stats
- delivery failures
- reconcile status
- historical dashboard queries

## Frontend Impact

Frontend guidance lives in:

- `web/FRONTEND_README.md`

The frontend does not need to lead this migration. Backend state and queue abstractions should land first, then the UI should expose:

- queue depth
- retry count
- last delivery errors
- reconcile activity
- OpenSearch-backed timeline charts

## Testing Plan

### Unit tests

- queue enqueue/dequeue/lock behavior
- ticket-state transitions
- dedup decisions with cached ticket state
- Wazuh ticket formatting

### Integration tests

- ingest -> queue -> create ticket
- repeat finding -> update ticket
- closed ticket -> reopen flow
- missing ticket -> recreate flow
- Redmine failure -> retry scheduling

### Migration tests

- local mode still works
- Postgres mode still works
- OpenSearch disabled mode remains safe
- config round-trip preserves new storage settings

## Recommended First Slice

Implement this first:

1. add `middleware_ticket_state`
2. add `middleware_outbound_queue`
3. add queue helpers to `src/state_store.py`
4. add a delivery worker that reads the queue and calls `RedmineClient`
5. keep current synchronous flow behind a fallback flag

That slice gives the biggest architectural gain without forcing a full ingest rewrite on day one.
