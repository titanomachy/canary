# Check reference

Canary performs exactly one check per invocation. Every check returns a human
message or one JSON object and exits with the shared contract documented in
[`baseline-contract.md`](baseline-contract.md). Command help is the source of
truth for accepted flags:

```bash
canary <http|ssl|tcp|udp|dns|icmp|command> --help
```

## Shared behavior

All checks accept these options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--timeout` | `5000` ms | Check-specific total timeout. |
| `--id` | generated | Stable state identity, maximum 128 characters. |
| `--retries` | `1` | Consecutive failures required for `DOWN`. |
| `--recoveryThreshold` | `1` | Consecutive successes required to recover from `DOWN`. |
| `--cooldown` | `0` | Minimum seconds between DOWN-class notifications. |
| `--repeatInterval` | `0` | DOWN reminder interval; zero disables reminders. |
| `--silenceUntil` | unset | UTC maintenance end, or `clear`. |
| `--notify` | none | Notification URL; repeat for multiple endpoints. |
| `--db` | none | SQLite path; enables state. |
| `--json` | false | Emit one structured JSON object. |

The target is always one required positional argument. Configuration errors
are detected before a check starts and exit `2`; a reachable service that fails
an assertion is a completed `DOWN` check and exits `1`.

Every elapsed time uses a monotonic clock. For socket checks, `--timeout` is one
deadline for resolution, connection, transmission, and response rather than a
fresh timeout for each phase.

## HTTP and HTTPS

```bash
canary http https://api.example.test/health \
  --statusRange '2xx,304' \
  --responseHeader 'Content-Type: application/json' \
  --jsonField 'service.status=ready' \
  --maxLatency 500
```

| Option | Default | Assertion or behavior |
| --- | --- | --- |
| `--status` | `200` | One exact expected status. |
| `--statusRange` | empty | Comma-separated codes, inclusive ranges, or classes; replaces `--status`. |
| `--maxLatency` | `0` | Maximum complete response time in ms; zero disables it. |
| `--search` | empty | Literal body substring. |
| `--regex` | empty | Regular expression matched against the body. |
| `--responseHeader` | empty | `Name` for presence or `Name: substring` for a value assertion. |
| `--jsonField` | empty | JSON scalar assertion as `dotted.path=value`; numeric path components index arrays. |
| `--headers` | empty | Request headers separated by commas or newlines. |
| `--methodStr` | `GET` | `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `PATCH`, or `OPTIONS`. |
| `--body` | empty | Request body. |
| `--maxRedirects` | `5` | Maximum followed redirects. |
| `--verbose`, `--timing` | false | Include libcurl transport phase timings. |

All configured assertions must pass. `statusRange` accepts values such as
`204`, `200-299`, `2xx`, or `2xx,304`. JSON values are compared as exact plain
scalar text; for example `replicas.0.healthy=true`.

HTTP response time covers client setup, redirects, the complete response body,
and local assertions. One timeout is shared by TCP connection, TLS negotiation,
redirects, and response transfer in both transports. Ordinary requests use Nim's asynchronous
HTTP client under that deadline; libcurl remains optional for phase timings.
JSON includes both `response_time_ms` and the equal
`latency_ms` compatibility field. Timing mode additionally returns
`timings_ms.dns`, `tcp_connect`, `tls_handshake`, `ttfb`, `transfer`, and
`total`. These transport phases are diagnostic; `--maxLatency` applies to the
complete Canary response time.

## TLS certificate expiry

```bash
canary ssl example.test --port 443 --minDays 21
canary ssl 'https://[2001:db8::30]/' --minDays 14
```

`--minDays` defaults to `14` and must be non-negative. `--port` defaults to
`443`. Canary extracts the leaf certificate, parses its expiration time, and
fails if fewer than the configured whole days remain. In the 0.1.x series it
invokes the OpenSSL executable directly with argument arrays. See the
[known security boundary](security.md#helper-process-boundary).

## TCP

```bash
# Connect only.
canary tcp db.internal --port 5432

# Match a server-first banner.
canary tcp mail.internal --port 25 --expected '220 '

# Send one request, then match the response.
canary tcp 127.0.0.1 --port 9000 --request PING --expected PONG
```

`--port` is required. Without `--request` or `--expected`, a successful
connection is enough. A non-empty `--expected` reads until it finds the literal
substring or the deadline expires; it can therefore inspect a server-first
banner. Matching succeeds as soon as the bytes arrive, including text split
across multiple reads; the server can keep the connection open. A request is
sent verbatim before reading. Requests, expectations, and
buffered responses are limited to 65,536 bytes and are not logged.

## UDP

```bash
canary udp 127.0.0.1 --port 9000 --payload ping --expected pong
```

`--port` is required and `--payload` defaults to `ping`. Sending alone never
counts as success: Canary must receive a datagram before the deadline. A
non-empty `--expected` requires a literal substring in that response.

## DNS

```bash
canary dns example.test --type A \
  --expected 192.0.2.10 --expected 192.0.2.11
canary dns example.test --type MX --expected '10 mail.example.test' \
  --resolver 192.0.2.53:5353
```

`--type` accepts `A`, `AAAA`, `CNAME`, `MX`, or `TXT` and defaults to `A`.
Repeat `--expected` for every required answer; additional answers are allowed.
CNAME and MX names compare case-insensitively without a trailing dot, IPv6
addresses are canonicalized, and TXT values compare exactly.

An empty `--resolver` uses the first nameserver in `/etc/resolv.conf`. An
explicit resolver must be an IP literal with an optional port. Truncated UDP
responses retry over TCP within the same deadline.

## ICMP

```bash
canary icmp 192.0.2.10 --count 3 --timeout 3000
```

`--count` defaults to `1` and accepts 1 through 100. Canary invokes the Linux
or Windows `ping` executable directly, using the native arguments on each
platform, and bounds the complete helper process with `--timeout`. An IPv6
literal explicitly selects `ping -6`.

## Local command

```bash
canary command /usr/bin/systemctl \
  --arg is-active --arg postgresql \
  --exitCode 0 --outputMatch active --timeout 3000
```

Each repeatable `--arg` becomes one unchanged argv element; no shell parses the
executable or arguments. `--exitCode` defaults to `0` and accepts 0 through
255. `--outputMatch` is a case-sensitive literal substring in combined stdout
and stderr. A timeout always fails, regardless of termination status. A command
must finish and close its inherited output pipes within the timeout.
Output is collected while the command runs, so a large response does not block
the child on a full pipe. Output collection shares the command deadline.
Canary terminates its process tree on timeout, including children left behind
by an exited parent. Linux uses an isolated process group and Windows uses a
Job Object. Programs must not deliberately detach from the managed group.

A missing or unstartable executable is a configuration error.

Arguments, captured output, and match text stay out of results, state IDs, and
notifications. Generated identities contain only the executable, so use
`--id` for different probes of the same program.

## IPv6

All network checks support IPv6 literals. URLs require brackets:

```bash
canary http 'http://[2001:db8::10]:8080/health'
canary tcp 2001:db8::20 --port 443
canary udp '[2001:db8::53]' --port 9000
canary dns example.test --type AAAA --resolver '[2001:db8::53]:5353'
```

TCP tries resolved IPv4 and IPv6 addresses within one deadline. UDP probes the
resolved address families and accepts the first valid response. Output that
combines an IPv6 address and port always uses `[address]:port`.
