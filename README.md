# canary

A lightweight, stateless-by-default service health and uptime monitoring CLI in Nim. Designed to integrate seamlessly with schedulers like [Metronome-Web](https://github.com/titanomachy/Metronome-Web) as a self-hosted replacement for services like Uptime Robot.

---

## Philosophy & Architecture

Many monitoring solutions are heavy background daemons bundling their own schedulers, web servers, and persistent services. **Canary** adheres to the Unix philosophy: *do one thing and do it well*.

1. **Stateless & Fast:** Without `--db`, `CANARY_DB`, or `--notify`, Canary executes one targeted health check without writing state and exits immediately.
2. **Orchestrated by Metronome-Web:** [Metronome-Web](https://github.com/titanomachy/Metronome-Web) manages the cron/interval schedule, asynchronous job execution, run history, and Apache ECharts latency visualisations.
3. **Smart State Tracking & Alerting:** Powered by [nim-sqlite](https://github.com/titanomachy/nim-sqlite), Canary records endpoint status and failure counts in an embedded SQLite database (`~/.config/canary/state.db`). Notifications (Pushover, Slack, Discord, Webhooks) are dispatched **only on state transitions** (`UP -> DOWN` and `DOWN -> UP`), eliminating alert fatigue and false positives.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                             Metronome-Web                              │
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

# Structured JSON output & Retries (alert only after 2 consecutive failures)
./canary http https://myapp.com --retries 2 --json --notify "https://hooks.slack.com/services/..."
```

**Options:**
| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | `string` | *required* | Target URL to test (*positional argument*) |
| `-t=, --timeout=` | `int` | `5000` | Timeout in milliseconds |
| `-s=, --status=` | `int` | `200` | Expected HTTP status code |
| `--search=` | `string` | `""` | Substring that must be present in response body |
| `--headers=` | `string` | `""` | Request headers separated by commas or newlines |
| `-m=, --methodStr=` | `string` | `"GET"` | HTTP method (`GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`) |
| `-b=, --body=` | `string` | `""` | Payload body for POST/PUT requests |
| `--maxRedirects=` | `int` | `5` | Maximum number of redirects to follow |
| `-r=, --retries=` | `int` | `1` | Consecutive failure count required before DOWN alert |
| `--recoveryThreshold=` | `int` | `1` | Consecutive successes required before recovery alert |
| `--id=` | `string` | `""` | Stable explicit state identity (recommended when a target has multiple assertions) |
| `-n=, --notify=` | `string` | `""` | Notification URL(s) separated by commas |
| `-d=, --db=` | `string` | `""` | Path to SQLite database (optional, see State Tracking) |
| `-j, --json` | `bool` | `false` | Output result as structured JSON object |

#### Terminal Output Examples:
```text
$ ./canary http https://example.com --search "Example Domain"
HTTP OK - https://example.com - Status: 200 OK - Latency: 42ms

$ ./canary http https://example.com/not-found
HTTP ERROR - https://example.com/not-found - Status: 404 Not Found (Expected: 200) - Latency: 18ms
[exit code: 1]

$ ./canary http https://example.com --methodStr HEAD --json
{"check":"http","target":"https://example.com","status":"UP","latency_ms":35,"message":"HTTP OK - https://example.com - Status: 200 OK - Latency: 35ms","details":"Status: 200 OK"}
```

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
| `-n=, --notify=` | `string` | `""` | Notification URL(s) |
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
```

#### Terminal Output Examples:
```text
$ ./canary tcp example.com -p 443
TCP OK - example.com:443 - Latency: 10ms

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
Verify domain name resolution and optionally validate the resolved IP.

```bash
# Basic DNS resolution
./canary dns example.com

# Verify domain resolves to expected IP
./canary dns example.com --expected "93.184.216.34"
```

#### Terminal Output Examples:
```text
$ ./canary dns example.com
DNS OK - example.com resolved to 93.184.216.34 - Latency: 7ms
```

---

### 6. UDP Checks (`canary udp`)
Check UDP service reachability (e.g. DNS or NTP). Canary reports `UP` only after
receiving a response before the timeout. Use `--expected` to require a substring
in that response.

```bash
./canary udp 127.0.0.1 -p 9000 --payload "ping" --expected "pong"
```

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

Canary supports multiple notification endpoints simultaneously via a
comma-separated list in `--notify` or `CANARY_NOTIFY`.

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
   Sends a JSON payload: `{"text": "[ALERT] Canary: ... is DOWN!", "content": "..."}`
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
   --notify "pushover://USER@TOKEN,https://hooks.slack.com/services/..."
   ```

---

## Integration with Metronome-Web

[Metronome-Web](https://github.com/titanomachy/Metronome-Web) serves as the scheduler and dashboard UI for Canary. Configure jobs in the Metronome-Web interface:

| Job Name in Metronome-Web | Recommended Schedule | Example Command |
| :--- | :--- | :--- |
| **Health: Production API** | `every 1 minute` or `*/1 * * * *` | `/opt/canary/canary http https://api.example.com/health --search "ok" --retries 2 --notify "https://hooks.slack.com/..."` |
| **SSL Expiry: Web Server** | `every 1 day` or `0 8 * * *` | `/opt/canary/canary ssl api.example.com --minDays 14 --notify "pushover://USER@TOKEN"` |
| **Database Port: Postgres** | `every 2 minutes` or `*/2 * * * *` | `/opt/canary/canary tcp db.internal -p 5432 --timeout 1000 --retries 2` |
| **DNS Resolution: Core API** | `every 5 minutes` or `*/5 * * * *` | `/opt/canary/canary dns api.example.com --expected "93.184.216.34"` |

### Why this combination works:
- **Automatic Latency Graphs:** Canary output (e.g. `HTTP OK - Latency: 42ms`) and process execution duration are logged to SQLite by Metronome-Web and visualized in Apache ECharts.
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
