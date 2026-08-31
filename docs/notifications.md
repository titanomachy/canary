# Notifications

Canary sends notifications for state transitions, optional DOWN reminders, and
provider delivery tests. Check-originated notifications use the SQLite state
machine and durable outbox; `notify test` sends immediately without changing
check state.

## Configure targets

Repeat `--notify` on the CLI, use a TOML array, or separate multiple environment
values with newlines:

```bash
export CANARY_NOTIFY='https://hooks.example.test/canary'
canary http https://api.example.test/health --id production-api
```

```toml
notify = [
  "https://hooks.example.test/canary",
  "pushover://USER_KEY@API_TOKEN"
]
```

Prefer a protected environment/service file or untracked TOML file. Full URLs
often contain credentials and CLI arguments are commonly visible to other
local tools. Canary output identifies only the provider scheme and host.

## Providers and payloads

| Provider | URL | Request contract |
| --- | --- | --- |
| Slack | `https://hooks.slack.com/...` | JSON POST with `text`. |
| Discord | `https://discord.com/...` or `https://discordapp.com/...` | JSON POST with `content`. |
| Pushover | `pushover://USER_KEY@API_TOKEN` | Form POST to the Pushover Messages API. |
| Generic webhook | `http://...` or `https://...` | JSON POST with equal `text` and `content`. |

Any HTTP 2xx response is success. Other statuses, timeouts, and transport
failures are delivery failures. Slack and Discord routing is selected from the
webhook hostname; other HTTP(S) hosts use the generic payload.

Transition messages contain the explicit or generated check name, transition,
event kind, attempt, check latency, cause, and UTC timestamp. Event prefixes are
`[ALERT]`, `[REMINDER]`, and `[RECOVERY]`. The message does not include raw URL
credentials, notification paths, query values, command output, or command
arguments.

## Test a provider

Use a delivery test to validate target shape and credentials without creating
or changing check state:

```bash
CANARY_NOTIFY='https://hooks.slack.com/services/...' \
  canary notify test slack
```

Provider names are `slack`, `discord`, `pushover`, and `webhook`. The command
validates every configured URL before sending any message, so a mixed or
mismatched target list cannot produce partial test delivery. It exits `0` if
all deliveries succeed, `1` on delivery failure, and `2` for invalid input.

The repository's [local demo](../examples/README.md) tests a generic mock
webhook entirely on loopback.

## Durable delivery

For a check invocation, Canary commits its state transition and one outbox row
per notification target in the same `BEGIN IMMEDIATE` transaction. It delivers
only after the commit. A failed event returns to `pending` with bounded
exponential backoff plus deterministic jitter; the maximum delay is five
minutes. Later Canary invocations process due rows.

A claimed row receives a five-minute `delivering` lease. This normally prevents
concurrent processes from sending the same row, while allowing another process
to recover work abandoned by a crash. The guarantee is at-least-once: a
provider may observe a duplicate if the process sends successfully and exits
before recording `sent`.

Delivery results are written to stderr. JSON check output additionally includes
a `notifications` array with the public target, `sent` or `retry` status,
attempt number, and the next Unix retry timestamp when applicable. Notification
or database failures never replace the completed check's exit code.

## Cooldowns, reminders, and silence

`--cooldown SECONDS` sets the minimum gap between DOWN-class notifications.
`--repeatInterval SECONDS` requests reminders while a check remains DOWN; the
effective reminder gap is the larger value. Recovery is not delayed by a
cooldown. Timers are evaluated only when Canary runs, so schedule probes more
frequently than the desired reminder precision.

`--silenceUntil 2026-08-30T18:00:00Z` persists an absolute UTC maintenance end
for the check identity. Health and thresholds continue updating, but pending
and new delivery is held. Use `--silenceUntil clear` to end it early. The
complete behavior, including catch-up and recovery cancellation, is in the
[state-machine contract](state-machine.md).
