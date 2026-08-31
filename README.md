# Canary

Canary is a lightweight Linux health-check CLI written in Nim. A scheduler
starts one process, Canary performs one HTTP, TLS, TCP, UDP, DNS, ICMP, or local
command check, prints a result, and exits. It is stateless by default; SQLite
state, failure/recovery thresholds, and durable notifications are opt-in.

Canary is designed to pair with schedulers such as
[Metronome](https://github.com/titanomachy/Metronome),
[Metronome-Web](https://github.com/titanomachy/Metronome-Web), cron, and systemd
timers instead of running its own daemon or scheduler.

## Five-minute quickstart

Canary 0.1.x supports Linux and requires Nim 2.0 or newer, a C compiler,
SQLite development libraries, the PCRE runtime, OpenSSL command-line tools,
and `ping`. The optional HTTP timing mode also requires the libcurl shared
library.

```bash
git clone https://github.com/titanomachy/canary.git
cd canary
nimble install -d
nimble build -y

# Stateless checks: no database is created.
./build/canary http https://example.com --statusRange 2xx
./build/canary tcp example.com --port 443
./build/canary dns example.com --type A

# Machine-readable output and a stable state identity.
./build/canary http https://example.com --json \
  --id example-home --db ./build/canary-state.db --retries 2
```

A completed healthy check exits `0`, an unhealthy check exits `1`, invalid
configuration exits `2`, and an unexpected internal error exits `3`. State or
notification failures are reported on stderr without changing the completed
check result.

Run `./build/canary --help` or `./build/canary <command> --help` for the exact
CLI. See [Installation](#installation) for distro packages.

## Checks

| Command | Purpose | Typical assertions |
| --- | --- | --- |
| `http` | HTTP/HTTPS response | status/range, response time, header, text, regex, JSON field |
| `ssl` | TLS certificate expiry | minimum remaining days |
| `tcp` | TCP service | connect, optional request and response/banner substring |
| `udp` | UDP service | response required, optional substring |
| `dns` | DNS records | A, AAAA, CNAME, MX, or TXT values; optional resolver |
| `icmp` | Host reachability | bounded packet count and process timeout |
| `command` | Local executable | exit code and optional combined-output substring |

Two quick examples for each command:

**HTTP/HTTPS**

```bash
canary http https://example.com
canary http https://api.example.test/health --statusRange 2xx --search healthy
```

**TLS certificate**

```bash
canary ssl example.com
canary ssl example.com --port 443 --minDays 30
```

**TCP**

```bash
canary tcp example.com --port 443
canary tcp mail.example.test --port 25 --expected '220 '
```

**UDP**

```bash
canary udp 127.0.0.1 --port 9000
canary udp 127.0.0.1 --port 9000 --payload ping --expected pong
```

**DNS**

```bash
canary dns example.com --type A
canary dns example.com --type MX --resolver 1.1.1.1
```

**ICMP**

```bash
canary icmp example.com
canary icmp 192.0.2.10 --count 3 --timeout 3000
```

**Local command**

```bash
canary command /usr/bin/true
canary command /usr/bin/printf --arg ready --outputMatch ready
```

Every network check supports IPv6. Use bracket notation in URLs and in DNS
resolver values that include a port. The complete option and assertion
reference is in [docs/checks.md](docs/checks.md).

## State and notifications

Without `--db`, `CANARY_DB`, `--notify`, or an explicit `--silenceUntil`
change, Canary never creates or updates state. When enabled, SQLite tracks
`UNKNOWN`, `UP`, `PENDING_DOWN`, and `DOWN`, while a durable outbox provides
at-least-once notification delivery.

```bash
export CANARY_DB=/var/lib/canary/state.db
export CANARY_NOTIFY='https://hooks.example.test/private-token'

canary http https://api.example.test/health --id production-api \
  --retries 2 --recoveryThreshold 2 \
  --cooldown 900 --repeatInterval 3600
```

Repeat `--notify URL` for multiple targets, or separate URLs with newlines in
`CANARY_NOTIFY`. Slack, Discord, Pushover, and generic HTTP(S) webhooks are
supported. Test a provider independently with `canary notify test <provider>`.
See [notifications](docs/notifications.md) and the
[state machine](docs/state-machine.md) for delivery, retry, cooldown, reminder,
and maintenance-silence semantics.

## Configuration

Defaults resolve in this order:

```text
built-in defaults < TOML < CANARY_* environment < CLI options
```

Pass `--config PATH`, or use `$XDG_CONFIG_HOME/canary/config.toml` (falling
back to `~/.config/canary/config.toml`). A missing default file is ignored; a
missing explicit file is an error. Targets remain positional and are never
loaded from configuration. Start with the credential-free
[example configuration](examples/canary.toml) and read the
[configuration guide](docs/configuration.md).

## Installation

Install these platform dependencies first. Package names vary by distribution:

- Nim 2.0 or newer and Nimble;
- GCC or Clang;
- SQLite headers and shared library (`libsqlite3-dev` or `sqlite-devel`);
- the PCRE runtime (`libpcre3` or `pcre`) for regular-expression assertions;
- OpenSSL command-line tools;
- `ping` (usually `iputils-ping`);
- the libcurl shared library for `http --verbose`/`--timing` only.

Then build from source:

```bash
nimble install -d
nimble build -y
install -Dm755 build/canary /usr/local/bin/canary
```

Dependencies are constrained in [canary.nimble](canary.nimble). Only Linux is
officially supported in the 0.1.x series.

## Documentation

<pre>
<a href="docs/checks.md">Checks</a> — check types, assertions, timing, and IPv6
<a href="docs/configuration.md">Configuration</a> — TOML, environment variables, precedence, and secrets
<a href="docs/notifications.md">Notifications</a> — providers, payloads, testing, and durable delivery
<a href="docs/state-machine.md">State machine</a> — thresholds, cooldowns, reminders, and silences
<a href="docs/architecture.md">Architecture</a> — module and process boundaries
<a href="docs/security.md">Security</a> — validation, redaction, and helper processes
<a href="docs/development.md">Development</a> and <a href="docs/testing.md">testing</a> — local workflow, fixtures, and quality checks
<a href="examples/README.md">Examples</a> — local demo plus Metronome-Web, cron, and systemd recipes
<a href="CHANGELOG.md">Changelog</a> · <a href="CONTRIBUTING.md">Contributing</a> · <a href="docs/baseline-contract.md">Baseline contract</a>
</pre>

## Limitations and security

- Canary 0.1.x is Linux-only. TLS certificate inspection temporarily uses the
  OpenSSL executable; ICMP uses `ping`.
- Canary is a single-run probe, not a scheduler, dashboard, or heartbeat
  receiver. Heartbeat/dead-man monitoring belongs in the orchestrator.
- Notification delivery is at-least-once. A provider can receive a duplicate
  if the process exits after sending but before marking an outbox row sent.
- HTTP `--maxLatency` covers the complete Canary HTTP operation. Optional
  libcurl phase timings are diagnostic and can sum to slightly less.
- Put webhook URLs, bearer tokens, and authorization headers in protected
  environment/service files or an untracked TOML file. CLI arguments and
  environment variables remain observable to sufficiently privileged users.
- Generated IDs intentionally remove URL credentials, queries, fragments,
  command arguments, and assertions. Use a stable explicit `--id` when checks
  against the same target need independent state.

Canary invokes helpers and local commands with argument arrays, never through a
shell, and redacts credentials from output and state identities. Read the
[security contract](docs/security.md) before using checks with secrets.

## Development

```bash
nimble test       # unit, integration, CLI, documentation, and example smoke tests
nimble checkAll   # style/static checks, debug/release builds, and all tests
```

All automated network fixtures bind to local loopback addresses and use random
ports; the suite does not contact public services. See
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

## License

[MIT](LICENSE)
