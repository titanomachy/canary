# CLI compatibility contract

This document defines the command-line behavior that must remain stable when
Canary's argument parser is changed. It deliberately describes observable
behavior rather than the parser implementation.

## Supported command shape

```text
canary <command> <target> [options]
```

The supported commands are `http`, `ssl`, `tcp`, `udp`, `dns`, `icmp`, and
`command`.
Options may follow the positional target, as shown throughout the README.
Documented short options and both `--option value` and `--option=value` forms
are part of the interface. Boolean options such as `--json` do not require a
value.

Parser-specific conveniences that are not documented in the README are not
part of this contract. In particular, compatibility is not required for
abbreviated option names, automatic singular/plural matching, `--helpsyntax`,
or valued boolean forms such as `--json=off`.

Every check command accepts `--id NAME`. When state tracking is active, this
value is the persisted state identity. Two invocations with the same target and
different explicit IDs must not share retry counters or transitions. IDs are
case-sensitive, have at most 128 characters, and cannot contain control
characters or surrounding whitespace.

Every command also accepts `--config PATH`. Configuration sources resolve as
built-in defaults, TOML, `CANARY_*` environment variables, and finally CLI
options. The default TOML path and supported keys are defined in
[`configuration.md`](configuration.md). A target remains a required positional
argument and cannot be supplied by TOML or the environment.

Every check command accepts the common notifier controls `--cooldown SECONDS`,
`--repeatInterval SECONDS`, and `--silenceUntil UTC_TIMESTAMP|clear`.
Intervals are non-negative integers and default to `0` (disabled). The UTC
timestamp format is exactly `yyyy-MM-ddTHH:mm:ssZ`. Silence is persisted by
check ID; omitting the option leaves the stored window unchanged, while
`clear` ends it. These options do not change the check result or exit code.

The DNS command accepts `--type A|AAAA|CNAME|MX|TXT`, repeatable
`--expected VALUE`, `--resolver IP[:PORT]`, and `--timeout MILLISECONDS`.
Resolver IPv6 literals with a port use bracket notation. Every expected answer
must be returned; extra answers are permitted.

The TCP command accepts `--request VALUE` and `--expected VALUE`. A request is
sent verbatim after connecting. An expectation requires a matching response
substring; without a request it matches server-first banners. `--timeout`
bounds the complete connect, send, and receive sequence. Omitting both values
retains the established connect-only behavior.

The local command shape is:

```text
canary command <executable> [--arg VALUE]... [--timeout MILLISECONDS]
  [--exitCode CODE] [--outputMatch TEXT]
```

Each repeatable `--arg` becomes exactly one argv element; Canary never invokes
a shell. Exit code `0` is expected by default, and `--exitCode` accepts `0`
through `255`. A non-empty `--outputMatch` requires a case-sensitive literal
substring in combined stdout and stderr. Timeout bounds the complete process
run and takes precedence over exit/output assertions. A timeout or assertion
failure is a completed `DOWN` check; failure to start the executable is invalid
configuration. Result output never contains argv values, captured process
output, or the configured match. The generated state ID uses only the
executable; use `--id` for distinct probes of one program.

The HTTP command accepts `-v`/`--verbose`; `--timing` is an equivalent alias.
This opt-in mode adds transport phases to human output and a `timings_ms` object
to JSON. It does not change status, body, header, regex, JSON-field, redirect,
timeout, or maximum-response-time assertions.

All six network checks accept IPv6. HTTP(S) targets use bracketed URL
authorities such as `http://[::1]:8080/health`. TCP, UDP, SSL, and ICMP host
arguments accept bare (`::1`) or bracketed (`[::1]`) literals. A displayed
TCP/UDP endpoint always uses `[address]:port`. DNS resolver literals with a
custom port use `[address]:port`, as described above. TCP tries resolved IPv4
and IPv6 addresses within its one total deadline; UDP probes every resolved
address family and accepts the first response.

Notification delivery can be checked separately with:

```text
canary notify test <slack|discord|pushover|webhook> [--notify URL]...
```

`--notify` is repeatable. When it is omitted, targets are read from a TOML
`notify` array or `CANARY_NOTIFY`; secrets therefore do not need to appear in
the process argument list. A test delivery returns `0` on success, `1` on
delivery failure, and `2` for invalid configuration or a provider mismatch.

## Compatibility matrix

| Invocation category | Exit code | stdout | stderr |
| --- | ---: | --- | --- |
| No arguments | `0` | General help | Empty |
| `--help` | `0` | General help and command list | Empty |
| `<command> --help` | `0` | Help for that command | Empty |
| `--version` | `0` | Canonical version followed by a newline | Empty |
| Unknown command | `2` | Empty | Diagnostic identifying the command |
| Unknown option | `2` | Empty | Diagnostic identifying the option |
| Missing target | `2` | Empty | Configuration diagnostic |
| Missing required option | `2` | Empty | Diagnostic identifying the option |
| Missing explicit config file | `2` | Empty | Configuration diagnostic |
| Invalid TOML or environment type | `2` | Empty | Configuration diagnostic |
| Invalid option type | `2` | Empty | Diagnostic identifying the value or option |
| Invalid option range | `2` | Empty | Configuration diagnostic |
| Completed `UP` check | `0` | Human-readable result | Empty |
| Completed `DOWN` check | `1` | Human-readable result | Empty |
| Completed check with `--json` | `0` or `1` | One valid JSON object | Empty |
| Unexpected internal failure | `3` | Empty | Diagnostic without a stack trace |

Diagnostics do not have to retain parser-specific punctuation, wrapping, or
complete help text. Their channel, exit code, and enough context to identify
the invalid input are stable.

Completed JSON results contain the generic `latency_ms` duration. HTTP results
also contain the equal-valued `response_time_ms` field and label the value
`Response time` in their human-readable message. It is the total monotonic
elapsed time from starting the HTTP check through receiving and processing the
complete response. `--maxLatency` applies to that same total response time.

With HTTP timing mode, `timings_ms` contains floating-point millisecond fields
`dns`, `tcp_connect`, `tls_handshake`, `ttfb`, `transfer`, and `total`. DNS is
measured from transport start through resolution; TCP connect starts after DNS;
TLS handshake starts after TCP; TTFB starts after TCP or TLS setup; transfer
starts at the first response byte. `total` is the summed libcurl transport time
and includes redirects. A field is zero when its phase is not applicable or
did not complete. The object is present on both successful and failed timed
requests and is omitted from ordinary HTTP results. The existing integer
`response_time_ms` remains the broader monotonic Canary check duration and can
therefore be slightly greater than `timings_ms.total`.

## Automated coverage

The black-box suite in `tests/cli/test_cli.nim` launches the compiled Canary
executable as a child process and observes only its arguments, exit status,
stdout, stderr, and explicitly requested state rows. Local TCP sockets provide
deterministic IPv4/IPv6 `UP`, `DOWN`, JSON, and state-identity checks without
internet access.
