# CLI compatibility contract

This document defines the command-line behavior that must remain stable when
Canary's argument parser is changed. It deliberately describes observable
behavior rather than the parser implementation.

## Supported command shape

```text
canary <command> <target> [options]
```

The supported commands are `http`, `ssl`, `tcp`, `udp`, `dns`, and `icmp`.
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

The DNS command accepts `--type A|AAAA|CNAME|MX|TXT`, repeatable
`--expected VALUE`, `--resolver IP[:PORT]`, and `--timeout MILLISECONDS`.
Resolver IPv6 literals with a port use bracket notation. Every expected answer
must be returned; extra answers are permitted.

The TCP command accepts `--request VALUE` and `--expected VALUE`. A request is
sent verbatim after connecting. An expectation requires a matching response
substring; without a request it matches server-first banners. `--timeout`
bounds the complete connect, send, and receive sequence. Omitting both values
retains the established connect-only behavior.

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

## Automated coverage

The black-box suite in `tests/cli/test_cli.nim` launches the compiled Canary
executable as a child process and observes only its arguments, exit status,
stdout, stderr, and explicitly requested state rows. Local TCP sockets provide
deterministic IPv4/IPv6 `UP`, `DOWN`, JSON, and state-identity checks without
internet access.
