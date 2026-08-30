# Changelog

All notable changes to Canary are documented in this file.

## [Unreleased]

### Added

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

### Changed

- Replaced `cligen` with a thin `nim-confutils` adapter; all execution still
  crosses the parser-independent `app.run(config)` boundary.
- Configuration now resolves as built-in defaults, TOML, environment variables,
  then CLI options, with later sources taking precedence.
- Bounded `confutils` to the compatible `0.1.x` line and
  `toml_serialization` to `0.2.x`; CLI black-box tests guard upgrades.
- State transitions now run in an immediate SQLite transaction so concurrent
  processes cannot lose failure-count updates.
- A first failure below `--retries` is stored as `UNKNOWN`; it reaches `DOWN`
  and emits an alert only at the configured threshold.
- UDP checks now require a response before the timeout and enforce `--expected`.
- TCP checks retain connect-only behavior by default, while `--request` and
  `--expected` enable application-level probes without logging probe contents.
- Webhook delivery now treats non-2xx responses and timeouts as failures without
  changing the health-check exit code.
- ICMP now has a bounded `--timeout` and invokes `ping` directly with an argv
  array.
- TLS certificate inspection now invokes OpenSSL twice with explicit arguments
  and stdin, without a shell, redirection, or pipeline.
- Invalid configuration consistently exits with code `2`; network and assertion
  failures remain completed `DOWN` checks with code `1`.

### Security

- Notification URLs and authorization headers can be supplied through
  `CANARY_NOTIFY` and `CANARY_HEADERS`, avoiding shared command-line arguments;
  the checked-in TOML example contains no secrets.
- Removed URL userinfo, query parameters, fragments, notification credentials,
  and raw client errors from public output, state IDs, and diagnostics.
- HTTP, TCP, UDP, and DNS checks now contain unexpected client/socket failures
  and return stable diagnostics without leaking exception text or stack traces.
