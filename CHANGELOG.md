# Changelog

All notable changes to Canary are documented in this file.

## [Unreleased]

### Added

- Focused check, notification, state-machine, and development manuals plus a
  contributor guide and a documentation index from the shortened README.
- Credential-free Metronome-Web, cron, and systemd timer examples, and an
  executable local HTTP/TCP/UDP/mock-webhook demo.
- A `nimble testDocs` task that validates local Markdown links and documentation
  structure, then smoke-tests the local demo; it is also part of `nimble test`
  and `nimble checkAll`.
- A least-privilege Linux GitHub Actions workflow on Nim 2.2.10 that runs the
  complete `nimble checkAll` contract, including documentation and examples.

- A shellless `command` check for local executables, with repeatable literal
  argv values, one total timeout, an expected exit code, and an optional
  combined stdout/stderr substring assertion.
- Typed TOML/environment/CLI configuration plus unit and black-box coverage for
  command success, expected nonzero exits, output mismatch, timeout, validation,
  missing executables, and sensitive-output containment.

- Per-check notification cooldowns through `--cooldown`, with transactional
  catch-up alerts for outages that remain DOWN after the cooldown.
- Periodic DOWN reminders through `--repeatInterval`; concurrent processes use
  the state transaction to enqueue at most one due reminder.
- Durable maintenance silences through `--silenceUntil UTC_TIMESTAMP`, plus
  `clear` for early termination. Checks and thresholds continue during silence,
  pending delivery is deferred, and an active outage alerts after the window.
- Unit and CLI coverage for notifier interval validation, UTC parsing,
  configuration precedence, reminder/cooldown timing, silence persistence,
  deferred outbox work, stale alert cancellation, and concurrent reminder
  deduplication.

- Typed TOML configuration through `--config PATH` and the optional
  `$XDG_CONFIG_HOME/canary/config.toml` default path.
- `CANARY_*` environment inputs for shared and command-specific defaults,
  including notification URLs and authorization headers.
- Black-box coverage for configuration precedence, missing and malformed TOML,
  type conversion, validation, help, version, and parser exit codes.
- A credential-free example configuration and a complete configuration guide.
- A typed `CanaryConfig` model with shared and command-specific configuration
  for every existing check.
- A parser-independent `app.run(config)` orchestration boundary and direct
  `executeCheck(config)` API for tests and reuse.
- An explicit `--id` option that keeps state independent for multiple checks
  against the same target.
- Architecture documentation for the CLI, configuration, application, check,
  state, and exit-code boundaries.
- Unit coverage for parsing, validation, result formatting, check IDs, and all
  persisted state transitions.
- Deterministic local HTTP, TLS, UDP, and webhook fixtures on random ports.
- A multiprocess SQLite concurrency regression test with isolated temporary
  databases.
- `nimble testIntegration` and `nimble checkAll` tasks, plus a testing guide.
- Central validation for hostnames, DNS expectations, HTTP headers and methods,
  numeric ranges, single positional targets, and ICMP packet counts.
- Security regression coverage for direct process arguments, process timeouts,
  URL and notification-error redaction, invalid methods, and command-fragment
  hostnames.
- DNS queries for `A`, `AAAA`, `CNAME`, `MX`, and `TXT`, with repeatable
  expected answers, explicit resolver selection, a total timeout, UDP-to-TCP
  fallback for truncated replies, and deterministic local coverage.
- Optional TCP request transmission and expected response or server-banner
  matching, bounded by one total deadline and deterministic local fixtures.
- IPv6 support across HTTP(S), TCP, UDP, DNS resolver transport, TLS, and ICMP,
  with dual-stack address resolution, canonical bracketed endpoints, and local
  IPv6 loopback coverage.
- An explicit `response_time_ms` field for HTTP JSON results, alongside the
  retained `latency_ms` compatibility field.
- Optional HTTP `--verbose`/`-v` timing mode (with `--timing` alias), reporting
  separate DNS, TCP-connect, TLS-handshake, TTFB, transfer, and total phases.
- A structured `timings_ms` JSON object for timed HTTP successes and failures,
  plus deterministic local HTTP and HTTPS phase-timing coverage.

### Changed

- Reduced the README to project positioning, a five-minute quickstart, check
  overview, installation, documentation links, and explicit limitations and
  security notes; detailed contracts now live under `docs/`.

- Generated command state identities contain only the executable; argv and
  assertion text stay out of persistence and public diagnostics. Operators can
  use `--id` to separate multiple probes of the same executable.

- State rows now record notification timing, current-incident alert ownership,
  and the persisted silence end; existing 0.1 databases migrate in place
  without re-alerting already-DOWN legacy incidents.
- Notification messages identify `ALERT`, `REMINDER`, or `RECOVERY` in addition
  to the health transition.

- Replaced `cligen` with a thin `nim-confutils` adapter; all execution still
  crosses the parser-independent `app.run(config)` boundary.
- Configuration now resolves as built-in defaults, TOML, environment variables,
  then CLI options, with later sources taking precedence.
- Bounded `confutils` to the compatible `0.1.x` line and
  `toml_serialization` to `0.2.x`; CLI black-box tests guard upgrades.
- State transitions now run in an immediate SQLite transaction so concurrent
  processes cannot lose failure-count updates.
- A first failure below `--retries` is stored as `PENDING_DOWN`; it reaches
  `DOWN` and emits an alert only at the configured threshold.
- UDP checks now require a response before the timeout and enforce `--expected`.
- TCP checks retain connect-only behavior by default, while `--request` and
  `--expected` enable application-level probes without logging probe contents.
- TCP now tries resolved IPv4 and IPv6 endpoints within one deadline, while UDP
  probes every resolved address family and accepts the first response.
- Webhook delivery now treats non-2xx responses and timeouts as failures without
  changing the health-check exit code.
- ICMP now has a bounded `--timeout` and invokes `ping` directly with an argv
  array.
- TLS certificate inspection now invokes OpenSSL twice with explicit arguments
  and stdin, without a shell, redirection, or pipeline.
- Invalid configuration consistently exits with code `2`; network and assertion
  failures remain completed `DOWN` checks with code `1`.
- All check durations now use the monotonic `getMonoTime()` clock, preventing
  system wall-clock corrections from distorting elapsed measurements. SSL
  duration now covers certificate inspection and parsing as well as handshake.
- Human-readable HTTP output and documentation now call the full-operation
  measurement response time; `--maxLatency` applies to that total response time.
- Timed HTTP requests use libcurl in process so all phase values belong to the
  measured HTTP operation and existing response assertions still use its body
  and headers. Libcurl is loaded only for timing mode; private CA paths honor
  `CURL_CA_BUNDLE` and `SSL_CERT_FILE`.

### Security

- Local commands use direct executable-plus-argv process creation without a
  shell. Arguments, captured stdout/stderr, and configured output matches are
  not copied into results or notification messages.

- Notification URLs and authorization headers can be supplied through
  `CANARY_NOTIFY` and `CANARY_HEADERS`, avoiding shared command-line arguments;
  the checked-in TOML example contains no secrets.
- Removed URL userinfo, query parameters, fragments, notification credentials,
  and raw client errors from public output, state IDs, and diagnostics.
- HTTP, TCP, UDP, and DNS checks now contain unexpected client/socket failures
  and return stable diagnostics without leaking exception text or stack traces.
