# Baseline contract

This document defines Canary's public baseline as of version `0.1.0`. Changes to
these contracts require tests and a changelog entry.

## Execution and state

Canary executes one check and then exits. A default invocation is stateless: it
does not create or update a database.

State tracking is enabled explicitly by any of these inputs:

- `--db PATH`;
- a non-empty `CANARY_DB` environment variable;
- a non-empty TOML `db` setting;
- `--notify URL`, `CANARY_NOTIFY`, or a TOML `notify` setting, because
  transition-based notifications require persisted state.

If notification is enabled without an explicit database path, Canary stores
state in `~/.config/canary/state.db`. Supplying a database without notification
records state but does not send notifications.

## Supported platform

Linux is the only supported platform for the `0.1.x` series. The baseline is
Nim 2.0 or newer, a C compiler, SQLite development libraries, and the system
tools used by individual checks. The current baseline was verified on Linux
amd64 with Nim 2.2.10.

macOS and Windows may compile in part, but they are not supported until their
complete check suites run in CI. In particular, the current TLS and ICMP checks
depend on platform-specific command-line tools.

## Exit codes and output

The detailed parser-independent compatibility matrix is defined in the
[CLI compatibility contract](cli-contract.md).

| Exit code | Meaning | Output channel |
| ---: | --- | --- |
| `0` | The requested check is `UP`. | Result on stdout. |
| `1` | The requested check completed and is `DOWN`. | Result on stdout. |
| `2` | CLI usage or configuration is invalid. | Diagnostic on stderr. |
| `3` | Canary could not complete the check because of an unexpected internal error. | Diagnostic on stderr. |

Help and version requests exit with `0`. A remote timeout, refused connection,
unexpected response, or failed assertion is a completed `DOWN` check, not an
internal error.

Invalid timeouts, retry thresholds, ports, methods, hostnames, status codes,
DNS expectations, header syntax, TLS thresholds, redirect counts, and ICMP
packet counts are configuration errors. They are rejected before network or
helper-process execution and exit with `2`.

## Sensitive targets and helper processes

HTTP targets may contain userinfo and query parameters for request execution,
but Canary removes userinfo, the complete query, and fragments from stdout,
JSON, state IDs, notification labels, and diagnostics. Notification diagnostics
identify at most the scheme and host; they never include credentials, paths, or
query values.

On supported Linux systems, ICMP invokes `ping` and TLS invokes `openssl`
directly with argument arrays. No target is interpreted by a shell. The TLS
implementation uses separate `s_client` and `x509` invocations, passing the leaf
certificate over stdin rather than through a shell pipeline.

## Notification and state failures

The health-check result is authoritative. A notification delivery or state-store
failure never changes `UP` to `DOWN`, changes `DOWN` to `UP`, or alters the check
exit code. Such failures are reported on stderr.

Notification transitions are stored atomically with state in a durable SQLite
outbox. A failed delivery is retained and retried by later Canary runs with
bounded exponential backoff and deterministic jitter. Delivery remains
at-least-once: a process that exits after a provider accepts a message but
before SQLite records it as sent may cause a duplicate after the delivery lease
expires.

## Version source

`src/canary_contract.nim` is the single source of truth for the package and CLI
version. Both the Nimble manifest and `canary --version` consume
`CanaryVersion` from that file.
