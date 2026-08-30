# Testing

Canary's automated tests are deterministic and fully local. They do not depend
on public websites, DNS records, or notification services.

## Commands

| Command | Coverage |
| --- | --- |
| `nimble test` | Unit, integration, and CLI suites. |
| `nimble testCli` | Public stdout, stderr, JSON, and exit-code contract. |
| `nimble testIntegration` | Local HTTP, TCP, UDP, DNS, TLS, webhook, and SQLite scenarios. |
| `nimble checkAll` | Style/static checks, debug and release builds, then every suite. |

## Unit coverage

`tests/unit/test_unit.nim` covers header and Pushover parsing, HTTP-method
mapping, input ranges, URL validation, human and JSON result formatting, typed
configuration for all seven check kinds, parser-independent check execution,
stable and explicit check IDs, layered TOML/environment/CLI precedence,
environment-based secret inputs, and state transitions.
Notifier state coverage also fixes the clock to verify cooldown catch-up,
DOWN reminders, persisted maintenance windows, deferred delivery, stale-alert
cancellation on recovery, and in-place schema migration.

Timing coverage verifies that the shared elapsed-time helper accepts a
monotonic `MonoTime`, HTTP output uses `Response time` and
`response_time_ms`, and the legacy `latency_ms` JSON field remains equal for
compatibility. It also verifies the six structured `timings_ms` fields and the
`--verbose`/`--timing` configuration mapping. Local delayed fixtures exercise
DNS/TCP/TTFB/transfer phase output, the total HTTP response-time
threshold and the bounded monotonic deadlines used by UDP, TCP, and DNS.

The unit suite also verifies that shell metacharacters remain a literal process
argument, helper-process timeouts are enforced, local command/ICMP/OpenSSL
checks receive exact argv arrays, command exit/output/timeout assertions are
classified correctly, invalid input never reaches a runner, and sensitive
command values and URL secrets are absent from formatted output and state IDs.

Each state test creates its own temporary SQLite database. The state table
exercises these paths:

```text
no row + success ────────────────> UP
no row + failure below threshold > UNKNOWN
UNKNOWN + failure at threshold ──> DOWN + alert
UP + failure below threshold ────> UP (pending failure)
pending failure + success ───────> UP (counter reset)
DOWN + failure ──────────────────> DOWN (no duplicate alert)
DOWN + success ──────────────────> UP + recovery
DOWN + repeat interval elapsed ──> DOWN + reminder
silenced DOWN + silence elapsed ─> DOWN + catch-up alert
```

## Integration fixtures

`tests/fixtures/local_server.nim` binds to `127.0.0.1` by default or `::1` with
`--ipv6`, always on a kernel-assigned port. It serves one local protocol
scenario and exits. Its modes provide:

- successful, mismatching, delayed, and redirecting HTTP responses with phase
  timing;
- matching and mismatching UDP replies;
- server-first TCP banners, request/response probes, and silent TCP timeouts;
- local DNS answers for every supported record type;
- successful, delayed, and HTTP 503 webhook responses;
- HTTP targets containing userinfo, query values, and fragments to verify output
  redaction.
- a generated, short-lived self-signed certificate served over loopback to
  exercise both real OpenSSL invocations and an HTTPS libcurl handshake timing.
- IPv6 HTTP, TCP, UDP, DNS-resolver, and TLS exchanges; ICMP IPv6 argument
  selection is covered with an exact process-runner contract.

The timeout scenarios use short, bounded local waits. The concurrency test
starts eight `state_worker` processes against one state row and verifies that
the transactionally updated failure count contains every write. A second
eight-process scenario fixes the notifier clock and verifies that only one due
DOWN reminder is enqueued.

The CLI suite verifies help, version, parser and application exit codes, missing
and invalid TOML, the optional default path, typed validation, precedence,
independent explicit state IDs, and an IPv6 TCP result through the public JSON
contract. It checks timing mode through the public nested JSON contract and
also forces a webhook connection failure with userinfo, a secret path, and a
query token, then verifies that stderr contains only the public notification
host. Local command cases cover successful literal output matching, expected
nonzero exits, assertion failures, timeouts, and missing executables.
