# canary

A lightweight, stateless-by-default service health and uptime monitoring CLI in Nim. Designed to integrate seamlessly with schedulers like [Metronome](https://github.com/titanomachy/Metronome)/[Metronome-Web](https://github.com/titanomachy/Metronome-Web) as a self-hosted replacement for services like Uptime Robot.

---

## Philosophy & Architecture

Many monitoring solutions are heavy background daemons bundling their own schedulers, web servers, and persistent services. **Canary** adheres to the Unix philosophy: *do one thing and do it well*.

1. **Stateless & Fast:** Without `--db`, `CANARY_DB`, or `--notify`, Canary executes one targeted health check without writing state and exits immediately.
2. **Orchestrated by Metronome/Metronome-Web:** [Metronome](https://github.com/titanomachy/Metronome)/[Metronome-Web](https://github.com/titanomachy/Metronome-Web) manages the cron/interval schedule, asynchronous job execution, run history, and Apache ECharts response-time visualisations.
3. **Smart State Tracking & Alerting:** Powered by [nim-sqlite](https://github.com/titanomachy/nim-sqlite), Canary records endpoint status and failure counts in an embedded SQLite database (`~/.config/canary/state.db`). Notifications (Pushover, Slack, Discord, Webhooks) are dispatched **only on state transitions** (`UP -> DOWN` and `DOWN -> UP`), eliminating alert fatigue and false positives.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Metronome/Metronome-Web                         │
│ (Cron/Interval Scheduler, Multi-process Execution, Dashboard, Charts)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                        triggers periodic process
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │        canary         │
                        │(HTTP/SSL/TCP/UDP/DNS) │
                        └───────────┬───────────┘
                                    │
             ┌──────────────────────┴──────────────────────┐
             ▼                                             ▼
    ┌─────────────────────────┐                   ┌─────────────────┐
    │     SQLite State DB     │                   │  Notifications  │
    │  (~/.config/canary/..)  │──────────────────►│ (Pushover/Slack)│
    │ (WAL Mode, Retries & Δ) │ (on state change) │  (UP <-> DOWN)  │
    └─────────────────────────┘                   └─────────────────┘
```

---

## Installation & Building

The supported platform, exit codes, state behavior, and notification-failure
semantics are defined in the [baseline contract](docs/baseline-contract.md).

### Requirements
- Nim >= 2.0.0 (tested on Nim 2.2+)
- Linux (the only supported platform in the `0.1.x` series)
- SQLite development libraries (`libsqlite3-dev` / `sqlite-devel`)
- OpenSSL command-line tools for TLS certificate checks
- The libcurl shared library for optional HTTP `--verbose`/`--timing` phase
  measurements (the curl executable is not used)
- `ping` (usually provided by `iputils-ping`) for ICMP checks
- C compiler (GCC or Clang)

### Building from source
```bash
git clone https://github.com/titanomachy/canary.git
cd canary

# Install dependencies (nim-confutils, TOML serialization, and nim-sqlite)
nimble install -d

# Compile the binary
nimble build -y
```

The compiled binary is produced as `./build/canary`.

---

## Commands, Options & Examples

Canary uses a thin `nim-confutils` adapter for typed CLI, environment, and TOML
configuration. Parsing remains isolated from the application layer; see
[Configuration](docs/configuration.md) and [Architecture](docs/architecture.md).

Defaults are resolved as `built-in < TOML < CANARY_* environment < CLI`.
Pass `--config PATH` explicitly or place defaults in
`$XDG_CONFIG_HOME/canary/config.toml` (falling back to
`~/.config/canary/config.toml`). A missing default file is ignored; a missing
explicit file is an error. Targets remain required positional arguments.

Every command accepts `--id NAME` to give state an explicit identity. Use it
when checks share a target but have different assertions, so their retry and
notification histories remain independent.

### Elapsed-time measurements

Every check measures elapsed time with Nim's monotonic `getMonoTime()` clock,
so corrections to the system wall clock cannot make a measurement jump forward
or backward. The timer starts when the check function starts and ends when its
result has been received and classified:

- HTTP includes client setup, redirects, receiving the complete response body,
  and processing the configured status, header, text, regex, and JSON
  assertions. **The response time is the total elapsed time from starting the
  HTTP check through receiving and processing the complete response.** A
  request failure or timeout is measured until that failure is classified.
  With `--verbose` (alias `--timing`), the same HTTP operation also reports
  libcurl transport phases. These do not replace the complete response time.
- SSL includes both OpenSSL invocations, certificate extraction, expiration
  parsing, and validity classification. The certificate's absolute expiration
  date is intentionally compared with the wall clock; only elapsed duration
  uses the monotonic clock.
- TCP includes address resolution, connection, and any configured send and
  response match. UDP includes address resolution, sending, receiving, and the
  optional response match. DNS includes the hosts-file or resolver query,
  possible UDP-to-TCP fallback, and answer processing. ICMP includes the
  complete `ping` helper-process run and exit classification.

On some systems a monotonic clock does not count time spent in system suspend.
For normal uptime checks while the system is active, `getMonoTime()` is still
the correct clock because it is unaffected by wall-clock adjustments.

---

### 1. HTTP / HTTPS Checks (`canary http`)
Monitor web applications, REST APIs, and websites with optional keyword matching, custom headers, and HTTP verbs.

```bash
# Basic check (expects HTTP 200)
./canary http https://example.com

# Assert required keyword in response body
./canary http https://example.com --search "Example Domain"

# Custom headers & Bearer authentication token
./canary http https://api.example.com/v1/health \
  --headers "Authorization: Bearer MY_SECRET_TOKEN,User-Agent: Canary/1.0"

# POST request with JSON body payload
./canary http https://api.example.com/v1/ping \
  --methodStr POST --body '{"ping": true}' --status 201

# Accept a status class and assert total response time, a header, and JSON content
./canary http https://api.example.com/v1/health \
  --statusRange '2xx' --maxLatency 500 \
  --responseHeader 'Content-Type: application/json' \
  --jsonField 'service.status=ready'

# Structured JSON output & Retries (alert only after 2 consecutive failures)
./canary http https://myapp.com --retries 2 --json --notify "https://hooks.slack.com/services/..."

# Curl-style phase timings in human output and structured JSON
./canary http https://example.com --verbose
./canary http https://example.com --timing --json
```

**Options:**
| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | `string` | *required* | Target URL to test (*positional argument*) |
| `-t=, --timeout=` | `int` | `5000` | Timeout in milliseconds |
| `-s=, --status=` | `int` | `200` | Expected HTTP status code |
| `--statusRange=` | `string` | `""` | Accepted codes, ranges, or classes, such as `200,204,3xx` (overrides `--status`) |
| `--maxLatency=` | `int` | `0` | Maximum total HTTP response time in milliseconds; `0` disables the assertion (option name retained for compatibility) |
| `--search=` | `string` | `""` | Substring that must be present in response body |
| `--regex=` | `string` | `""` | Regular expression that must match the response body |
| `--headers=` | `string` | `""` | Request headers separated by commas or newlines |
| `--responseHeader=` | `string` | `""` | Required response header as `Name` or `Name: value-substring` |
| `--jsonField=` | `string` | `""` | Required JSON scalar as `dotted.path=value`; numeric components index arrays |
| `-m=, --methodStr=` | `string` | `"GET"` | HTTP method (`GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`) |
| `-b=, --body=` | `string` | `""` | Payload body for POST/PUT requests |
| `--maxRedirects=` | `int` | `5` | Maximum number of redirects to follow |
| `-v, --verbose` (`--timing`) | `bool` | `false` | Report DNS, TCP-connect, TLS-handshake, TTFB, transfer, and total transport timings |
| `-r=, --retries=` | `int` | `1` | Consecutive failure count required before DOWN alert |
| `--recoveryThreshold=` | `int` | `1` | Consecutive successes required before recovery alert |
| `--id=` | `string` | `""` | Stable explicit state identity (recommended when a target has multiple assertions) |
| `-n=, --notify=` | repeatable string | none | Notification URL; repeat for multiple endpoints |
| `-d=, --db=` | `string` | `""` | Path to SQLite database (optional, see State Tracking) |
| `-j, --json` | `bool` | `false` | Output result as structured JSON object |

#### Terminal Output Examples:
```text
$ ./canary http https://example.com --search "Example Domain"
HTTP OK - https://example.com - Status: 200 OK - Response time: 42ms

$ ./canary http https://example.com/not-found
HTTP ERROR - https://example.com/not-found - Status: 404 Not Found (Expected: 200) - Response time: 18ms
[exit code: 1]

$ ./canary http https://example.com --methodStr HEAD --json
{"check":"http","target":"https://example.com","status":"UP","latency_ms":35,"message":"HTTP OK - https://example.com - Status: 200 OK - Response time: 35ms","details":"Status: 200 OK","response_time_ms":35}

$ ./canary http https://example.com --verbose
HTTP OK - https://example.com - Status: 200 OK - Response time: 38ms - Timings: DNS 2.104ms, TCP 7.315ms, TLS 13.842ms, TTFB 12.006ms, Transfer 0.184ms, Total 35.451ms

$ ./canary http https://example.com --timing --json
{"check":"http","target":"https://example.com","status":"UP","latency_ms":38,"message":"HTTP OK - https://example.com - Status: 200 OK - Response time: 38ms - Timings: DNS 2.104ms, TCP 7.315ms, TLS 13.842ms, TTFB 12.006ms, Transfer 0.184ms, Total 35.451ms","details":"Status: 200 OK","response_time_ms":38,"timings_ms":{"dns":2.104,"tcp_connect":7.315,"tls_handshake":13.842,"ttfb":12.006,"transfer":0.184,"total":35.451}}
```

Human-readable HTTP output calls this measurement `Response time`. HTTP JSON
adds the precise `response_time_ms` field; the equal-valued `latency_ms` field
remains available for compatibility with existing consumers.

Timing mode performs the request in process through libcurl; it does not start
the `curl` executable and does not expose the URL, request body, or headers in a
child-process argument list. The phase values are floating-point milliseconds,
rounded to three decimal places:

- `dns`: start through name resolution;
- `tcp_connect`: end of DNS through an established TCP connection;
- `tls_handshake`: end of TCP connect through TLS completion (`0` for HTTP);
- `ttfb`: end of TCP/TLS setup through the first response byte;
- `transfer`: first response byte through completion of the response body;
- `total`: the summed libcurl transport time, including redirects.

`response_time_ms` remains the integer monotonic duration of the whole Canary
HTTP check, including transport setup and local response assertions. Therefore
it can be slightly higher than `timings_ms.total`; `--maxLatency` continues to
apply to `response_time_ms`. A phase is `0` when it does not apply or was not
completed before a transport failure. Timing fields are omitted unless the
mode was requested.

---

### 2. SSL / TLS Certificate Expiry (`canary ssl`)
Monitor certificate validity and days remaining before expiration.

```bash
# Alert if certificate expires within 14 days (default)
./canary ssl example.com

# Alert if certificate expires within 30 days on a custom port
./canary ssl secure.example.com --minDays 30 --port 8443

# Dispatch notification and log as JSON
./canary ssl example.com --minDays 14 --json --notify "pushover://USER@TOKEN"
```

**Options:**
| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `host` | `string` | *required* | Hostname or URL (*positional argument*) |
| `-m=, --minDays=` | `int` | `14` | Minimum days remaining threshold before alerting |
| `-p=, --port=` | `int` | `443` | SSL/TLS port |
| `-t=, --timeout=` | `int` | `5000` | Timeout in milliseconds |
| `-r=, --retries=` | `int` | `1` | Consecutive failure count required before DOWN alert |
| `--recoveryThreshold=` | `int` | `1` | Consecutive successes required before recovery alert |
| `--id=` | `string` | `""` | Stable explicit state identity |
| `-n=, --notify=` | repeatable string | none | Notification URL; repeat for multiple endpoints |
| `-j, --json` | `bool` | `false` | Output result as JSON object |

#### Terminal Output Examples:
```text
$ ./canary ssl example.com
SSL OK - example.com certificate valid (59 days left) - Latency: 48ms

$ ./canary ssl example.com --json
{"check":"ssl","target":"example.com","status":"UP","latency_ms":43,"message":"SSL OK - example.com certificate valid (59 days left) - Latency: 43ms","details":"Expiration: Oct 27 22:17:21 2026 GMT (Days left: 59)"}
```

---

### 3. TCP Port Checks (`canary tcp`)
Verify network services (databases, SSH, mail servers) are listening and accepting connections.

```bash
# Check PostgreSQL on port 5432
./canary tcp 127.0.0.1 -p 5432

# Check SSH on remote host with custom timeout and retries
./canary tcp 192.168.1.10 -p 22 --timeout 2000 --retries 2

# Match a server-first SSH banner
./canary tcp 192.168.1.10 -p 22 --expected "SSH-2.0-"

# Send a protocol request and require a response substring
./canary tcp 127.0.0.1 -p 9000 --request "PING" --expected "PONG"
```

`--expected` waits for a matching response substring. It can be used without
`--request` for server-first protocols such as SSH or SMTP banners. When
`--request` is set, its bytes are sent verbatim before Canary reads the
response. The single `--timeout` covers connection, transmission, and response
matching. Omitting both options preserves the connect-only port check.

#### Terminal Output Examples:
```text
$ ./canary tcp example.com -p 443
TCP OK - example.com:443 - Latency: 10ms

$ ./canary tcp 127.0.0.1 -p 9000 --request PING --expected PONG
TCP OK - 127.0.0.1:9000 - Latency: 1ms

$ ./canary tcp example.com -p 444 --timeout 1000
TCP TIMEOUT - example.com:444 - After 1001ms
[exit code: 1]
```

---

### 4. ICMP Ping Checks (`canary icmp`)
Verify host reachability via ICMP echo packets.

```bash
# Standard ping (1 packet)
./canary icmp 1.1.1.1

# Send multiple packets
./canary icmp router.local --count 3
```

`--count` accepts 1 through 100 packets. `--timeout` bounds the complete
`ping` process and defaults to 5000 milliseconds.

#### Terminal Output Examples:
```text
$ ./canary icmp 127.0.0.1
ICMP OK - 127.0.0.1 - Latency: 4ms
```

---

### 5. DNS Resolution Checks (`canary dns`)
Query `A`, `AAAA`, `CNAME`, `MX`, or `TXT` records with a bounded timeout.
Canary uses the first nameserver in `/etc/resolv.conf` by default. Select a
specific resolver with `--resolver IP` (an optional `:PORT` is supported for
local/testing resolvers).

```bash
# Basic DNS resolution
./canary dns example.com

# Require both addresses; additional answers remain acceptable
./canary dns example.com --type A \
  --expected "192.0.2.10" --expected "192.0.2.11"

# Query MX through a selected resolver
./canary dns example.com --type MX \
  --expected "10 mail.example.com" --resolver "1.1.1.1" --timeout 2000

# TXT values are compared exactly and case-sensitively
./canary dns example.com --type TXT --expected "canary=ready"
```

#### Terminal Output Examples:
```text
$ ./canary dns example.com
DNS OK - example.com A records: 192.0.2.10, 192.0.2.11 - Latency: 7ms
```

`--expected` is repeatable. Every configured value must be present, while
unconfigured extra answers are allowed. Names in `CNAME`/`MX` answers are
matched case-insensitively without a trailing dot; `AAAA` values are
canonicalized before comparison. Truncated UDP replies are retried over TCP
within the same total timeout.

---

### 6. UDP Checks (`canary udp`)
Check UDP service reachability (e.g. DNS or NTP). Canary reports `UP` only after
receiving a response before the timeout. Use `--expected` to require a substring
in that response.

```bash
./canary udp 127.0.0.1 -p 9000 --payload "ping" --expected "pong"
```

---

## IPv6

Every network check supports IPv6 literals. HTTP and HTTPS URLs use standard
bracket notation. Host arguments for TCP, UDP, TLS, DNS, and ICMP accept either
the bare literal or brackets; output that combines an address and port always
uses `[address]:port` so it remains unambiguous.

```bash
# HTTP over IPv6
./canary http 'http://[2001:db8::10]:8080/health'

# TCP and UDP host arguments
./canary tcp 2001:db8::20 --port 443
./canary udp '[2001:db8::53]' --port 9000 --payload ping

# Query through an IPv6 DNS resolver on a custom port
./canary dns example.com --type AAAA \
  --resolver '[2001:db8::53]:5353' --expected '2001:db8::10'

# TLS and ICMP literals
./canary ssl 'https://[2001:db8::30]/'
./canary icmp 2001:db8::40
```

TCP tries the IPv4 and IPv6 addresses returned by the system resolver within
one check deadline. UDP sends the probe through every resolved address family
and accepts the first response. An IPv6 ICMP literal selects `ping -6`
explicitly; hostname targets retain the resolver behavior of the installed
Linux `ping` implementation.

---

## SQLite State Tracking & Flapping Protection

State tracking is opt-in through `--db`, `CANARY_DB`, or `--notify`. Without one
of these inputs Canary does not create or update a database. When enabled,
Canary uses the [nim-sqlite](https://github.com/titanomachy/nim-sqlite) library
for embedded state persistence.

Without `--id`, state IDs use a public form of URL targets: userinfo, query
parameters, and fragments are removed before persistence. Checks that differ
only in query values or expectations therefore share generated state. Give each
such check a stable `--id` to keep their state independent:

```bash
./canary http https://api.example.test/health --status 200 --id api-status
./canary http https://api.example.test/health --search ready --id api-readiness
```

### 1. Database Location Resolution
Canary locates the SQLite database in the following order:
1. Explicit CLI flag: `--db /path/to/state.db`
2. Environment variable: `CANARY_DB`
3. TOML setting: `db = "/path/to/state.db"`
4. Default fallback: `~/.config/canary/state.db` (created when state is requested)

### 2. Concurrency & WAL Mode
To ensure concurrent checks executed simultaneously by Metronome-Web never lock or block each other, Canary initializes SQLite with:
- `PRAGMA journal_mode = WAL;` (Write-Ahead Logging)
- `PRAGMA busy_timeout = 5000;` (Wait up to 5 seconds on concurrent writes)

### 3. Database Schema & Inspection
The `canary_state` table records the state, consecutive failure count, and last check timestamp for each target:

```sql
CREATE TABLE IF NOT EXISTS canary_state (
  id TEXT PRIMARY KEY,          -- e.g. 'http_https://example.com', 'ssl_example.com_443'
  status TEXT NOT NULL,         -- 'UNKNOWN', 'UP', 'PENDING_DOWN', or 'DOWN'
  fail_count INTEGER NOT NULL,  -- Consecutive failures (for flapping protection)
  success_count INTEGER NOT NULL, -- Consecutive successes while DOWN
  last_check INTEGER NOT NULL   -- Unix timestamp of last check
);
```

#### Inspecting the state database:
```bash
$ sqlite3 ~/.config/canary/state.db "SELECT id, status, fail_count, datetime(last_check, 'unixepoch') FROM canary_state;"
```
```text
╭──────────────────────────────┬────────┬────────────┬──────────────────────╮
│              id              │ status │ fail_count │ datetime(last_check) │
╞══════════════════════════════╪════════╪════════════╪══════════════════════╡
│ ssl_example.com_443          │ UP     │          0 │ 2026-08-29 01:06:10  │
│ http_https://example.com     │ UP     │          0 │ 2026-08-29 01:06:12  │
│ tcp_127.0.0.1_5432           │ UP     │          0 │ 2026-08-29 01:08:44  │
│ dns_myserver.local           │ DOWN   │          3 │ 2026-08-29 01:09:12  │
╰──────────────────────────────┴────────┴────────────┴──────────────────────╯
```

### 4. Flapping Protection (`--retries`)
By default, Canary triggers an alert on the first failure (`--retries 1`). For unstable networks or transient glitches, set `--retries 2` or `--retries 3`:
- **Attempt 1 fails:** `fail_count` becomes 1 and the state becomes
  `PENDING_DOWN`; **no alert is sent**.
- **Attempt 2 fails:** `fail_count` reaches threshold, status changes to `DOWN`, **[ALERT] DOWN notification sent**.
- **Subsequent run succeeds:** `fail_count` resets to 0. Once
  `--recoveryThreshold` consecutive successes have occurred, status changes to
  `UP` and a **[RECOVERY] notification is queued**.

---

## Notifications & Alerts

Canary supports multiple notification endpoints simultaneously. Repeat
`--notify URL` for CLI use, use a TOML `notify` array, or place one URL (multiple
URLs separated by newlines) in `CANARY_NOTIFY`.

Transition notifications use a durable SQLite outbox. State and outbox rows are
committed atomically, and temporary failures are retried on later runs with
bounded exponential backoff. Delivery is at-least-once, so providers may rarely
receive a duplicate around a process crash.

Notification credentials and full webhook paths are never included in result
output or delivery errors. Prefer `CANARY_NOTIFY` and `CANARY_HEADERS` over
command-line secrets, and keep credentials out of checked-in TOML. See the
[configuration guide](docs/configuration.md) for the complete source and
security contract.

---

## Validation and security

Canary validates timeouts, retry thresholds, ports, HTTP status codes and
methods, hostnames, DNS expectations, redirects, header syntax, TLS thresholds,
and ICMP packet counts before opening a network connection. Invalid input exits
with code `2`; a valid check that reaches an unavailable service exits with code
`1`.

ICMP and TLS helper processes receive an executable and an argument array
directly. No target is evaluated by a shell, and the temporary OpenSSL-based TLS
implementation uses two sequential invocations rather than a pipeline. See the
[security contract](docs/security.md) for the complete boundary.

### Supported Notification Protocols:

1. **Slack, Discord & Generic Webhooks (`http://` or `https://`):**
   Generic webhooks receive both `text` and `content`; Slack receives `text`
   and Discord receives `content`. Any HTTP 2xx response counts as success.
   ```bash
   --notify "https://hooks.slack.com/services/XXX/YYY/ZZZ"
   ```

2. **Pushover (`pushover://`):**
   Format: `pushover://USER_KEY@API_TOKEN`
   ```bash
   --notify "pushover://uQiRzpo4DXghDmr9QnoxfConfiguration@azGDORePK8gMaC0QOYAMyRIuzDM5x9"
   ```

3. **Combined Multi-channel Notifications:**
   ```bash
   --notify "pushover://USER@TOKEN" \
   --notify "https://hooks.slack.com/services/..."
   ```

Prefer loading these URLs from `CANARY_NOTIFY` or a protected, untracked TOML
file so credentials do not appear in process arguments. Verify a configured
provider independently of check state with:

```bash
CANARY_NOTIFY='https://hooks.slack.com/services/...' \
  canary notify test slack
```

---

## Integration with Metronome/Metronome-Web

[Metronome](https://github.com/titanomachy/Metronome)/[Metronome-Web](https://github.com/titanomachy/Metronome-Web) serves as the scheduler and dashboard UI for Canary. Configure jobs in the Metronome-Web interface.:

| Job Name in Metronome-Web | Recommended Schedule | Example Command |
| :--- | :--- | :--- |
| **Health: Production API** | `every 1 minute` or `*/1 * * * *` | `/opt/canary/canary http https://api.example.com/health --search "ok" --retries 2 --notify "https://hooks.slack.com/..."` |
| **SSL Expiry: Web Server** | `every 1 day` or `0 8 * * *` | `/opt/canary/canary ssl api.example.com --minDays 14 --notify "pushover://USER@TOKEN"` |
| **Database Port: Postgres** | `every 2 minutes` or `*/2 * * * *` | `/opt/canary/canary tcp db.internal -p 5432 --timeout 1000 --retries 2` |
| **DNS Resolution: Core API** | `every 5 minutes` or `*/5 * * * *` | `/opt/canary/canary dns api.example.com --expected "93.184.216.34"` |

### Why this combination works:
- **Automatic Response-Time Graphs:** Canary output (for example, `HTTP OK - Response time: 42ms`) and process execution duration are logged to SQLite by Metronome-Web and visualized in Apache ECharts.
- **Exit Code Integration:** Exit code `0` displays a green success status; exit code `1` marks the run as failed and highlights the error message in the history log.

---

## Development and testing

All automated tests use local fixtures and require no internet access:

```bash
nimble test             # unit, integration, and CLI suites
nimble testCli          # CLI contract only
nimble testIntegration  # local network and SQLite integration tests
nimble checkAll         # checks, debug/release builds, and all tests
```

See the [testing guide](docs/testing.md) for the coverage matrix and fixture
design. Public command behavior is specified in the
[CLI compatibility contract](docs/cli-contract.md).

---

## License

MIT License. Free for use and modification in your own infrastructure.
