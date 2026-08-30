# Configuration

Canary loads typed defaults through `nim-confutils` and converts the selected
command to the parser-independent `CanaryConfig` model. Targets remain
positional command arguments: this first configuration phase does not define
named or scheduled checks.

## Sources and precedence

Values are resolved from lowest to highest priority:

```text
built-in defaults < TOML < CANARY_* environment variables < CLI options
```

For example, `CANARY_TIMEOUT=2000` overrides `timeout = 3000` in TOML, and
`--timeout 1000` overrides both. Both `--option value` and `--option=value`
remain supported.

Use an explicit file with `--config PATH`. Without that option Canary looks at:

```text
$XDG_CONFIG_HOME/canary/config.toml
```

When `XDG_CONFIG_HOME` is empty or unset, the path is
`~/.config/canary/config.toml`. A missing default file is silently ignored and
is never created. A missing explicitly requested file, an unreadable file,
invalid TOML, or a wrong value type is a configuration error with exit code 2.

## TOML structure

Shared defaults live at the top level. Command-specific defaults use a table
named after the command. The repository's
[`examples/canary.toml`](../examples/canary.toml) is safe to copy because it
contains no credentials.

```toml
retries = 2
recoveryThreshold = 2
cooldown = 900
repeatInterval = 3600
# silenceUntil = "2026-08-30T18:00:00Z"
json = false
db = "/var/lib/canary/state.db"
# Store real URLs only in a protected, untracked file.
notify = ["https://hooks.example.invalid/private-token"]

[http]
timeout = 3000
status = 200
maxRedirects = 3
# statusRange = "2xx,304" # Replaces the exact status assertion when set.
# maxLatency = 500 # Maximum total HTTP response time; legacy option name
# verbose = true # Include curl-style transport phases in output.
# responseHeader = "Content-Type: application/json"
# regex = "ready|healthy"
# jsonField = "service.status=ready"

[ssl]
timeout = 5000
minDays = 21
port = 443

[tcp]
timeout = 3000
# request = "PING\r\n"
# expected = "PONG"

[dns]
timeout = 3000
type = "A"
# resolver = "1.1.1.1"
# expected = ["192.0.2.10", "192.0.2.11"]

[command]
timeout = 3000
exitCode = 0
# arg = ["--mode", "health"]
# outputMatch = "ready"
```

The common keys are `id`, `notify`, `db`, `retries`, `recoveryThreshold`,
`cooldown`, `repeatInterval`, `silenceUntil`, and `json`. `notify` is a TOML
array of notification URLs. `retries` is the failure threshold retained for
CLI compatibility;
`recoveryThreshold` is the number of consecutive successful checks required to
leave `DOWN`. `cooldown` and `repeatInterval` are non-negative seconds;
zero disables each feature. `silenceUntil` is an absolute UTC timestamp such
as `2026-08-30T18:00:00Z`, or `clear` to remove a persisted silence. Available
command keys are:

| Table | Keys |
| --- | --- |
| `[http]` | `timeout`, `status`, `statusRange`, `maxLatency`, `verbose`, `search`, `regex`, `headers`, `responseHeader`, `jsonField`, `methodStr`, `body`, `maxRedirects` |
| `[ssl]` | `minDays`, `port`, `timeout` |
| `[tcp]` | `port`, `request`, `expected`, `timeout` |
| `[udp]` | `port`, `payload`, `expected`, `timeout` |
| `[dns]` | `type`, `expected`, `resolver`, `timeout` |
| `[icmp]` | `count`, `timeout` |
| `[command]` | `arg`, `timeout`, `exitCode`, `outputMatch` |

The established HTTP key `maxLatency` is retained for compatibility. It limits
the total HTTP response time defined in the
[baseline contract](baseline-contract.md), not only one network phase.
`verbose = true`, `CANARY_VERBOSE=true`, or CLI `--verbose` enables the
libcurl-backed phase measurements. `--timing` is a CLI-only alias. The
structured fields and exact phase boundaries are defined in the
[CLI contract](cli-contract.md).

Targets (`url` or `host`) are intentionally not loaded from TOML or the
environment. Supply exactly one target after the command.

IPv6 URL targets use bracket notation, for example
`http://[2001:db8::10]:8080/health`. Host arguments accept a bare IPv6 literal
or a bracketed one. Resolver values with a custom port must use brackets, such
as `[2001:db8::53]:5353`, to separate the address from the port.

`status` checks one exact HTTP code. A non-empty `statusRange` replaces it and
accepts a comma-separated combination of exact codes (`204`), inclusive ranges
(`200-299`), and classes (`2xx`). `responseHeader = "Name"` checks presence;
adding `: value` also requires that substring in the response value.
`jsonField` traverses objects with dotted components and arrays with numeric
components, then compares the scalar's plain text exactly—for example,
`replicas.0.healthy=true`. Assertions are combined: every configured assertion
must pass. Use an explicit `id` when the same URL has multiple assertion sets
that need independent retry and notification state.

DNS `type` accepts `A`, `AAAA`, `CNAME`, `MX`, or `TXT`. `expected` is an array
of required answers; extra answers do not fail the check. MX expectations use
`priority hostname`, such as `10 mail.example.test`. `resolver` accepts an IP
literal with an optional port (`192.0.2.53:5353` or `[2001:db8::53]:5353`); an
empty value uses the first nameserver in `/etc/resolv.conf`. The DNS timeout
bounds the whole UDP query and any TCP retry needed for a truncated response.

For TCP, `request` is optional and is transmitted verbatim after connecting.
A non-empty `expected` requires that substring in the response; without a
request, this matches a server-first banner. The timeout is one total deadline
for connecting, sending, and receiving. Requests, expectations, and buffered
responses are limited to 65,536 bytes. With neither key, TCP remains a
connect-only check. Use an explicit `id` when multiple probes against the same
host and port need independent retry and notification state.

For `command`, `arg` is an array whose elements become separate argv values;
neither the executable nor its arguments pass through a shell. `exitCode`
accepts `0` through `255` and defaults to `0`. A non-empty `outputMatch` is a
case-sensitive literal substring assertion against combined stdout and stderr.
The one `timeout` covers the complete child-process run, and a timeout always
fails. Arguments, captured output, and match text stay out of public results,
state IDs, and notification messages. The generated identity contains only the
executable, so use an explicit `id` for different probes of the same program.

## Environment variables and secrets

Environment names use the `CANARY_` prefix and the uppercased option name:
`CANARY_RETRIES`, `CANARY_RECOVERYTHRESHOLD`, `CANARY_COOLDOWN`,
`CANARY_REPEATINTERVAL`, `CANARY_SILENCEUNTIL`, `CANARY_DB`, `CANARY_TIMEOUT`,
`CANARY_STATUS`, `CANARY_STATUSRANGE`, `CANARY_MAXLATENCY`, `CANARY_VERBOSE`, `CANARY_NOTIFY`,
`CANARY_REQUEST`, `CANARY_EXPECTED`, `CANARY_TYPE`, `CANARY_RESOLVER`,
`CANARY_ARG`, `CANARY_EXITCODE`, `CANARY_OUTPUTMATCH`, and `CANARY_HEADERS`, for
example. `CANARY_ARG` separates multiple command arguments with newlines.
Camel-case
option names do not gain an extra underscore: use `CANARY_MINDAYS` and
`CANARY_MAXREDIRECTS`. The same rule gives `CANARY_REPEATINTERVAL` and
`CANARY_SILENCEUNTIL`.

## Notification scheduling and silence

Notification scheduling belongs to the state identity, not to a process. Use a
stable explicit `id` and the same SQLite database for every scheduled
invocation. The stored values let concurrent Canary processes decide inside
one `BEGIN IMMEDIATE` transaction whether a notification is due.

`cooldown` is the minimum gap between DOWN-class notifications. It applies to
a new flapping DOWN incident and to reminders, but not to recovery. If a DOWN
transition occurs inside cooldown, the first check run after cooldown queues
the catch-up alert if the service is still down. `repeatInterval` queues a
reminder only on a failed run while the state remains `DOWN`; a successful
sample below the recovery threshold does not create a misleading reminder. The
effective gap is `max(cooldown, repeatInterval)`. These are run-driven timers,
so actual delivery may be later than the requested interval by up to the check
schedule interval.

`silenceUntil` establishes a durable maintenance window. The current health
state, failure threshold, and recovery threshold continue normally. New
notifications for that check and delivery of its pending outbox rows are held
until the UTC end. If the incident remains down, the first later run emits a
catch-up alert. Recovery during the silence cancels an undelivered DOWN alert,
and no recovery message is emitted for an incident that was never announced.
Omitting `silenceUntil` on later runs preserves the stored end time. Pass
`--silenceUntil clear` (or configure `silenceUntil = "clear"`) to end it early.

Prefer the environment for notification URLs, bearer tokens, and authorization
headers so they are absent from shared process listings and checked-in TOML:

```bash
export CANARY_NOTIFY='https://hooks.example.invalid/private-token'
export CANARY_HEADERS='Authorization: Bearer private-token'
canary http https://api.example.test/health
```

Use one URL in `CANARY_NOTIFY`, or separate multiple URLs with a newline. On
the CLI, repeat `--notify URL` once per endpoint; comma-splitting is not used.
A separately protected, untracked TOML file may instead contain a `notify`
array. Avoid command-line notification URLs because process arguments are
commonly visible to other local tooling.

Test credentials and provider payload compatibility without changing check
state:

```bash
CANARY_NOTIFY='https://hooks.slack.com/services/...' \
  canary notify test slack
```

The supported provider names are `slack`, `discord`, `pushover`, and `webhook`.
The command exits `0` after successful delivery, `1` after a delivery failure,
and `2` for invalid configuration or a provider/URL mismatch. Output contains
only the scheme and host, never the webhook path, query, or credentials.

Generic `http` and `https` webhooks receive one JSON POST containing both
`text` and `content`, with the same notification message in each field. This
keeps the generic contract usable by simple receivers while Slack receives
only `text` and Discord only `content`. Any HTTP 2xx response is success; every
other status or transport failure remains eligible for durable retry when the
notification originated from a check transition.

Environment variables are still visible to the process and may be observable
to sufficiently privileged local users. Protect service-manager environment
files with restrictive permissions and do not commit real secrets.

## Validation and command behavior

All sources use the same type conversion and parser-independent validation.
Invalid ports, timeouts, retry counts, methods, status codes, hostnames, header
syntax, and other check settings therefore exit with code 2 before network
access. `--help`, command help, `--version`, result output, and exit codes remain
part of the black-box CLI contract in [`cli-contract.md`](cli-contract.md).
