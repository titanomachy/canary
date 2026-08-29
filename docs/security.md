# Security contract

This document defines the input, process-execution, and redaction boundaries for
Canary `0.1.x`.

## Input and exit-code classification

Canary validates configuration before it performs network I/O or starts a helper
process. This includes positive timeouts, retry thresholds of at least one,
ports from 1 through 65535, HTTP status codes from 100 through 599, supported
HTTP methods, non-negative redirect and TLS thresholds, syntactically valid
hostnames/IP addresses and headers, valid expected DNS IP addresses, exactly one
target, and ICMP packet counts from 1 through 100.

Invalid configuration writes a concise diagnostic to stderr and exits with `2`.
A valid check that times out, cannot connect, receives an unexpected response,
or fails an assertion produces a normal `DOWN` result on stdout and exits with
`1`. Unexpected internal failures exit with `3` and do not expose exception text
or a stack trace.

## Helper-process boundary

Linux is the only supported platform for `0.1.x`.

- ICMP starts `ping` with a fixed executable name and an argument array.
- TLS starts `openssl s_client`, extracts the first PEM certificate in memory,
  and starts `openssl x509` separately with that certificate on stdin.
- No helper command uses shell evaluation, redirection, command substitution, or
  a pipeline.
- Helper execution is bounded by the configured timeout.

OpenSSL is a temporary runtime dependency for the TLS expiry check. Replacing it
with a TLS-library implementation remains a future architectural improvement,
not a prerequisite for the safe `0.1.x` process boundary.

## Redaction boundary

The original HTTP URL is used only for the outgoing request. Before a target is
formatted, persisted, or included in a notification label, Canary removes:

- URL usernames and passwords;
- the complete query string, including names and values;
- URL fragments.

This intentionally means that two HTTP checks differing only by query values
share a generated state ID in `0.1.x`. Use `--id` or `CANARY_ID` to give such
checks independent state identities.

Notification delivery errors include at most a public scheme and hostname. Raw
HTTP, socket, resolver, OpenSSL, and notification exception messages are not
shown because upstream libraries can embed full URLs or credentials in those
messages.

Notification URLs and authorization headers can be loaded from
`CANARY_NOTIFY` and `CANARY_HEADERS`. Prefer those environment inputs or a
separately protected, untracked TOML file over shared command-line arguments,
and never commit real credentials. See [`configuration.md`](configuration.md).
