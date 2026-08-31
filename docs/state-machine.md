# State machine and durable outbox

State is opt-in. Canary opens SQLite only when a database path, notification
target, or explicit maintenance-silence change requires persistence. Otherwise
every run is stateless.

## Health states

Canary persists four states:

| State | Meaning |
| --- | --- |
| `UNKNOWN` | No conclusive healthy or unhealthy history yet. |
| `UP` | Healthy, or temporarily failing below the configured threshold. |
| `PENDING_DOWN` | Initial failures have not reached `--retries`. |
| `DOWN` | Consecutive failures reached `--retries`. |

The transition contract is:

```text
no row + success --------------------> UP
no row + failure below threshold ----> PENDING_DOWN
PENDING_DOWN + threshold failure ----> DOWN + ALERT
UP + failure below threshold --------> PENDING_DOWN
PENDING_DOWN + success --------------> UP (failure counter reset)
DOWN + failure ----------------------> DOWN
DOWN + threshold successes ----------> UP + RECOVERY
```

`--retries` is the failure threshold and defaults to `1`.
`--recoveryThreshold` defaults to `1`. While DOWN, successful runs increment a
separate success counter; a later failure resets that counter. A successful
sample below the recovery threshold does not send a reminder or recovery.

The first successful observation creates `UP` state but does not send a
recovery. A recovery notification exists only for a DOWN incident that Canary
previously announced.

## Transaction boundary

Each state update executes under `BEGIN IMMEDIATE`. Canary reads the current
row, applies counters and scheduling rules, writes the new row, and inserts all
notification events before committing. Concurrent processes therefore cannot
lose a counter update or independently enqueue the same due reminder.

```text
check result
     |
     v
BEGIN IMMEDIATE
  state read -> transition/counter decision -> state + outbox writes
COMMIT
     |
     v
claim due outbox event -> deliver -> sent or pending with retry time
```

SQLite uses WAL mode and a 5000 ms busy timeout. Existing 0.1 databases migrate
in place. Legacy DOWN rows are marked as already announced during migration so
an upgrade does not create a duplicate alert.

## Outbox delivery

Each notification target owns a separate outbox row. Rows move through
`pending`, `delivering`, `sent`, or `cancelled`. Failed delivery increments the
attempt count and computes a bounded exponential delay with deterministic
jitter. A five-minute claim lease recovers rows left `delivering` after a
crashed process.

State and events are durable together, but network delivery cannot be exactly
once. The contract is at-least-once because a crash can happen between provider
acceptance and the SQLite `sent` update.

## Cooldown and reminders

A positive `--cooldown` delays a new DOWN alert if another DOWN-class event for
the identity was queued too recently. If the incident remains DOWN, the first
run after cooldown queues a catch-up alert.

A positive `--repeatInterval` allows `[REMINDER]` events on failed runs that
remain DOWN. Both the repeat interval and cooldown must have elapsed, so the
effective gap is `max(cooldown, repeatInterval)`. Because Canary has no resident
timer, events can be late by up to the scheduler interval.

## Maintenance silence

`--silenceUntil` stores a UTC end time on the check identity. Omitting the
option on later runs preserves the stored value. During the window:

- health checks, failure counts, and recovery counts continue;
- new alerts and reminders are not enqueued;
- already-pending events for the identity are not claimed;
- recovery cancels an undelivered alert for an incident that was never
  announced, and no misleading recovery is generated.

If the service remains DOWN after the window, the first later failed run queues
a catch-up alert. `--silenceUntil clear` sets the stored end to zero. Always use
a stable `--id` and database path for every scheduled invocation that should
share a maintenance window.

## Identity and storage

State belongs to `--id`, not inherently to a target. Without an explicit ID,
Canary creates a compatibility identity from the check type and public target.
It removes URL userinfo, queries, fragments, local-command arguments, and
assertions. Distinct checks that share those public parts therefore need
explicit IDs.

Database resolution is CLI `--db`, then `CANARY_DB`, then TOML `db`, then
`~/.config/canary/state.db` when persistence was requested. Changing an ID or
database starts an independent history.

For operational inspection:

```bash
sqlite3 /var/lib/canary/state.db \
  "SELECT id,status,fail_count,success_count,last_check FROM canary_state;"
sqlite3 /var/lib/canary/state.db \
  "SELECT check_id,status,attempt_count,next_attempt,event_kind FROM notification_outbox;"
```

Treat schema details as operational diagnostics rather than a public write API;
only Canary should modify these tables.
