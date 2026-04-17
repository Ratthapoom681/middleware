# Dedup Logic Discussion

## Problem Summary

The current pipeline has a logic conflict:

- The dedup stage drops repeated findings before they reach Redmine.
- The Redmine client contains update logic for repeated findings.

Because of that, duplicate occurrences inside the dedup TTL are never able to update an existing Redmine issue. The system behaves like "drop duplicates" instead of "track repeated occurrences."

## Current Behavior

Today the flow is roughly:

1. Ingest findings
2. Filter
3. Map severity
4. Deduplicate
5. Enrich
6. Output to Redmine

The issue is step 4. Once a finding hash is considered already seen, it is removed from the batch. That means step 6 never gets a chance to decide whether the existing issue should be updated.

## Better Mental Model

Dedup should not mean "throw repeated findings away."

A better model is:

- Identify whether a finding is new or already known
- Decide what action should happen next
- Persist that state only after the output action succeeds

This turns dedup into correlation / lifecycle tracking rather than simple suppression.

## Recommended Action States

For each finding hash, the system should decide one of these actions:

- `create`
  First time the finding has been seen and no tracked issue exists.

- `update`
  The finding has been seen before and should add a new occurrence to an existing issue.

- `reopen_or_create`
  The finding was seen in the past, but the tracked issue is closed, invalid, or outside the active window.

- `ignore`
  The same hash appears multiple times in the same batch, and one action already represents it.

## Suggested Pipeline Shape

The pipeline should move toward this:

1. Ingest
2. Filter
3. Map severity
4. Enrich
5. Correlate findings into actions
6. Execute Redmine actions
7. Persist state only for successful actions

This avoids the current conflict between dedup and Redmine updates.

## Why Persist After Output Success

This is an important design rule.

If the system records a hash as "seen" before Redmine creation/update succeeds, then a failed Redmine call can leave the finding marked as processed even though nothing was created or updated.

That can cause silent data loss.

Safer rule:

- Only mark a finding as handled after Redmine succeeds.

## Suggested Local State Model

Instead of only storing `seen_hashes`, store correlation state such as:

- `hash`
- `source`
- `title`
- `first_seen`
- `last_seen`
- `occurrence_count`
- `redmine_issue_id`
- `issue_status`
- `last_action`
- `last_error`

This gives the system enough information to make deterministic decisions without repeatedly trying to rediscover issue state through fuzzy Redmine searches.

## Suggested Decision Object

Instead of returning `list[Finding]`, the correlation stage can return structured decisions.

Example:

```python
from dataclasses import dataclass
from typing import Literal


@dataclass
class FindingDecision:
    finding: Finding
    action: Literal["create", "update", "ignore", "reopen_or_create"]
    dedup_hash: str
    existing_issue_id: int | None = None
    occurrence_count: int = 1
```

This makes the next stage explicit instead of hiding behavior inside filtered lists.

## Batch Handling

Same-batch duplicates should usually collapse into one decision.

Example:

- 5 identical findings arrive in one batch
- system creates one `FindingDecision`
- `occurrence_count = 5`

That gives cleaner Redmine behavior and avoids repeated create/update calls for identical events in the same cycle.

## Recommended Execution Rules

For each dedup hash:

- No local record:
  - create a new Redmine issue

- Local record with open tracked issue:
  - update that issue with a new occurrence note

- Local record exists but issue is closed:
  - reopen the issue, or create a new one depending on policy

- Same hash repeated within same batch:
  - fold into one action and increment occurrence count


## Naming Improvement

`DeduplicatorStage` is starting to do more than dedup.

A clearer name would be one of:

- `CorrelationStage`
- `FindingStateStage`
- `FindingLifecycleStage`

This better reflects what the component should be responsible for.

## Smallest Safe Refactor

If we want an incremental change instead of a full redesign:

1. Keep SQLite
2. Change the stage to return two groups:
   - `new_findings`
   - `repeat_findings`
3. Send `new_findings` through create logic
4. Send `repeat_findings` through update logic
5. Write DB state only after Redmine succeeds
6. Store `redmine_issue_id` locally so updates do not depend on subject matching

This would fix the core behavior without requiring a full architecture rewrite.

## Preferred Long-Term Design

The cleanest long-term design is:

- Replace simple dedup with correlation decisions
- Store `hash -> issue id -> timestamps -> counts -> state`
- Let the Redmine client execute explicit `create` / `update` / `reopen_or_create`
- Persist state only after successful output

## Benefits

This approach would give us:

- no conflict between dedup and issue updates
- fewer duplicate tickets
- reliable occurrence tracking
- simpler auditability
- less dependence on fragile Redmine search behavior
- a clean foundation for reopen/escalate/parent-ticket features later

## Open Questions

Before implementation, we should decide:

1. Should repeated findings update the same issue forever, or only within a TTL window?
2. If an issue is closed and the finding returns, should we reopen it or create a new issue?
3. Should same-batch duplicates produce one note with a count, or one note per occurrence?
4. Is Redmine the source of truth for issue state, or should the local SQLite registry be the source of truth?
5. Should parent device issues be linked during `create` only, or also be revisited during `update` / `reopen`?

## Recommendation

Short term:

- implement local `hash -> redmine_issue_id` tracking
- stop dropping repeated findings before output
- write dedup state only after output success

Long term:

- convert `DeduplicatorStage` into a `CorrelationStage`
- return action decisions rather than only filtered findings

---

## Architecture Resolution (2026-04-16)

**Decision:** The advanced SIEM Correlation Engine (grouping similar attacks into campaigns) has been deemed out of scope. We will stick strictly to the **Deduplicator Summary Flush** approach. 

**Justification:** 
- SIEM correlation is better suited for Wazuh Rules (XML) rather than the Python middleware output stage. 
- The "Summary Flush" logic we deployed (which drops duplicate events locally but flushes the final count to Redmine at the end of the polling cycle) successfully resolves the "Dedup Drop vs Update Conflict" by providing 100% data visibility without rate-limiting the Redmine API.
- We do not need to convert Deduplicator into a Stateful Correlation Machine at this time.
