# Architecture

Canary is a single-run health-check process. A scheduler starts one command,
Canary performs one check, optionally records its state and sends a transition
notification, then exits with the documented status code.

## Application boundary

The implementation separates argument parsing from application behavior:

```text
process arguments
      |
      v
canary/cli.nim  -- builds -->  CanaryConfig
                                      |
                                      v
                               app.run(config)
                                      |
                 +--------------------+-------------------+
                 |                    |                   |
                 v                    v                   v
              check result       state tracking     notification
```

- `src/canary.nim` is the minimal executable entrypoint.
- `src/canary/cli.nim` is the thin `nim-confutils` adapter. It resolves built-in,
  TOML, environment, and CLI values, converts them into the typed model, and
  contains no check implementation.
- `src/canary/config.nim` defines `CanaryConfig`, `CommonConfig`, and the seven
  command-specific configurations. Validation operates on this model and does
  not depend on a parser.
- `src/canary/app.nim` validates and executes a configuration, formats the
  result, coordinates optional state and notifications, and returns an exit
  code. It never terminates the process itself.
- `src/checks/` contains the check implementations. These functions return a
  `CheckResult` and do not print or terminate the process.
- `src/checks/http_timing.nim` is the opt-in in-process libcurl boundary. It
  performs the timed HTTP request, captures body and headers for the same
  assertions, and converts libcurl's cumulative counters into separate phases.
- `src/checks/http_transport.nim` runs ordinary HTTP requests through Nim's
  asynchronous client with one deadline for connection, TLS, redirects, and
  response transfer. Each HTTPS hop verifies its certificate and host identity.
- `src/process_child.nim` owns helper-process groups, Windows Job Objects, and
  nonblocking output reads; `src/process_runner.nim` applies the execution and
  output-collection deadline.

The adapter resolves configuration as built-in defaults, then TOML, then
`CANARY_*` environment variables, then CLI options. It reads an explicit
`--config PATH` or the optional platform default described in
[`configuration.md`](configuration.md). The resulting model reaches checks and
orchestration without any parser dependency.

## Check identity

State belongs to a check identity, not necessarily to its network target. By
default Canary generates the legacy identity from the check type, public
target, and port where applicable. URL credentials, queries, and fragments are
not included.

Use `--id NAME` to set an explicit identity. This is important when two checks
use the same URL but assert different status codes, content, or headers:

```bash
canary http https://api.example.test/health --status 200 --id api-status
canary http https://api.example.test/health --search ready --id api-readiness
```

Those commands maintain independent state even when they share a database.
The same applies to command checks: generated IDs intentionally omit argv and
output assertions because they can contain secrets, so distinct probes of one
executable should have explicit IDs.

IDs are opaque, case-sensitive strings of at most 128 characters. They may not
have surrounding whitespace or contain control characters. Choose a stable ID:
changing it starts a new state history.

## Error and exit boundary

Configuration validation happens before network access. `app.run(config)` maps
the result to the public exit-code contract:

- `0`: completed check is `UP`;
- `1`: completed check is `DOWN`;
- `2`: invalid configuration;
- `3`: unexpected internal failure.

State or notification failures are reported separately and do not change the
completed check's exit code.

## State machine and notification outbox

The persisted states are `UNKNOWN`, `UP`, `PENDING_DOWN`, and `DOWN`. A failed
check below `--retries` enters `PENDING_DOWN`; a success before the threshold
returns it to `UP`. While `DOWN`, Canary counts consecutive successes and only
recovers after `--recoveryThreshold` (default `1`).

The state update and one outbox row per notification target are committed in a
single `BEGIN IMMEDIATE` transaction. Delivery happens after the commit. Failed
rows return to `pending` with bounded exponential backoff and deterministic
jitter. A short `delivering` lease lets another process recover work abandoned
by a crashed process while preventing concurrent Canary runs from normally
sending the same row together. This provides durable at-least-once delivery;
providers can still observe a duplicate if the process exits after sending but
before recording `sent`.

Cooldown, repeat, and maintenance decisions use the same transaction. Each
state row stores the last queued notification, whether the current DOWN
incident has been announced, and an absolute `silenced_until` timestamp.
Therefore concurrent processes cannot both decide that the same reminder is
due. Cooldown gates DOWN-class alerts; recovery remains immediate. A configured
repeat interval produces a reminder only on a failed check run where both it
and the cooldown have elapsed. A successful sample during a multi-run recovery
threshold does not create a DOWN reminder.

A silence is durable and owned by the check ID. It does not freeze health
state: failure and recovery thresholds keep advancing. The outbox claim query
also checks the state row, so already-pending events for a silenced check are
not delivered by another process. An outage that outlives the window receives
a catch-up alert on the next run. If recovery occurs during the window, a
pending DOWN alert is cancelled and the unannounced incident does not generate
a recovery message.
