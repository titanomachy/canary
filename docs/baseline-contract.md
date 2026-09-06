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
- `--silenceUntil`, `CANARY_SILENCEUNTIL`, or a TOML `silenceUntil` setting,
  because maintenance windows are durable per check ID.

If notification is enabled without an explicit database path, Canary stores
state in `~/.config/canary/state.db`. Supplying a database without notification
records state but does not send notifications.

## Supported platform

Linux and 64-bit Windows are supported for the `0.1.x` series. The baseline is
Nim 2.0 or newer, a C compiler, SQLite development libraries, and the system
tools used by individual checks. CI builds both platforms with Nim 2.2.10.

Optional HTTP phase timing uses the system libcurl shared library in process.
The `curl` executable is not required. Ordinary HTTP checks continue to use
Nim's HTTP client and do not require libcurl to perform a request.

On Windows, timing mode probes common libcurl DLL names both beside
`canary.exe` and through the normal DLL search path. When no compatible DLL can
be loaded, the check result explains where to install it and notes that the DLL
and its dependencies must match Canary's architecture.

macOS may compile in part but is not supported until its compatibility suite
runs in CI. TLS requires the OpenSSL executable on both supported platforms.
ICMP uses the platform's `ping` executable with Linux- or Windows-specific
arguments. The supported 64-bit Windows build targets the OpenSSL 3 x64 DLL
ABI used by current MSYS2 packages.

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

## Elapsed-time contract

All seven check types measure elapsed duration with the monotonic
`getMonoTime()` clock rather than the epoch-based wall clock. The timer covers
the complete check function through result classification. HTTP response time
specifically covers the interval from starting the HTTP check through receiving
and processing the complete response, including configured response
assertions. Failed requests and timeouts are measured until the failure is
classified.

Human-readable HTTP output labels the value `Response time`. Structured HTTP
output exposes it as `response_time_ms` and retains the equal-valued generic
`latency_ms` field for compatibility. The established `--maxLatency` option
compares this total HTTP response time, despite its legacy name.

`--verbose` (alias `--timing`) additionally exposes libcurl transport phases in
floating-point milliseconds under `timings_ms`: DNS, TCP connect, TLS
handshake, TTFB, transfer, and transport total. These phase values do not
replace the complete monotonic `response_time_ms` measurement. An inapplicable
or incomplete phase is zero; timing fields are omitted when timing mode is off.

Absolute certificate expiration still requires the system wall clock; only the
elapsed SSL check duration is monotonic. On some systems the monotonic clock
does not advance during system suspend. It remains the appropriate clock for
normal uptime checks while the system is active because wall-clock corrections
cannot distort elapsed measurements.

Invalid timeouts, retry thresholds, ports, methods, hostnames, status codes,
DNS expectations, header syntax, TLS thresholds, redirect counts, and ICMP
packet counts are configuration errors. Command executable/argv limits and
expected exit codes are validated the same way. They are rejected before
network or helper-process execution and exit with `2`.

## Sensitive targets and helper processes

HTTP targets may contain userinfo and query parameters for request execution,
but Canary removes userinfo, the complete query, and fragments from stdout,
JSON, state IDs, notification labels, and diagnostics. Notification diagnostics
identify at most the scheme and host; they never include credentials, paths, or
query values.

On Linux and Windows, ICMP invokes `ping` and TLS invokes `openssl` directly
with argument arrays. No target is interpreted by a shell. The TLS
implementation uses separate `s_client` and `x509` invocations, passing the leaf
certificate over stdin rather than through a shell pipeline.

The `command` check likewise invokes the selected executable directly with one
argv element per `--arg`. Its configured timeout bounds the complete process;
the default expected exit code is `0`, and an optional literal output match is
applied to combined stdout and stderr. Arguments, captured output, and match
text are not included in public results.

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

Optional cooldowns, repeat intervals, and maintenance silences are also
evaluated transactionally per check ID. They affect notification scheduling
only: checks still run, state thresholds still advance, and the health-check
exit code remains authoritative. Silence prevents another process from
claiming that check's pending outbox rows until the stored UTC end time.

## Version source

The package version is a string literal in `canary.nimble`, as required by
Nimble metadata readers. The CLI version is `CanaryVersion` in
`src/canary_contract.nim`; the documentation test requires both values to stay
in sync.
