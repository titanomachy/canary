# Configuration

Canary loads typed defaults through `nim-confutils` and converts the selected
command to the parser-independent `CanaryConfig` model. Targets remain
positional command arguments: this first configuration phase does not define
named or scheduled checks.

## Sources and precedence

Values are resolved from lowest to highest priority:

```text
built-in defaults < TOML < CANARY_* environment variables < CLI options
```

For example, `CANARY_TIMEOUT=2000` overrides `timeout = 3000` in TOML, and
`--timeout 1000` overrides both. Both `--option value` and `--option=value`
remain supported.

Use an explicit file with `--config PATH`. Without that option Canary looks at:

```text
$XDG_CONFIG_HOME/canary/config.toml
```

When `XDG_CONFIG_HOME` is empty or unset, the path is
`~/.config/canary/config.toml`. A missing default file is silently ignored and
is never created. A missing explicitly requested file, an unreadable file,
invalid TOML, or a wrong value type is a configuration error with exit code 2.

## TOML structure

Shared defaults live at the top level. Command-specific defaults use a table
named after the command. The repository's
[`examples/canary.toml`](../examples/canary.toml) is safe to copy because it
contains no credentials.

```toml
retries = 2
recoveryThreshold = 2
json = false
db = "/var/lib/canary/state.db"

[http]
timeout = 3000
status = 200
maxRedirects = 3

[ssl]
timeout = 5000
minDays = 21
port = 443
```

The common keys are `id`, `notify`, `db`, `retries`, `recoveryThreshold`, and
`json`. `retries` is the failure threshold retained for CLI compatibility;
`recoveryThreshold` is the number of consecutive successful checks required to
leave `DOWN`. Available command keys are:

| Table | Keys |
| --- | --- |
| `[http]` | `timeout`, `status`, `search`, `headers`, `methodStr`, `body`, `maxRedirects` |
| `[ssl]` | `minDays`, `port`, `timeout` |
| `[tcp]` | `port`, `timeout` |
| `[udp]` | `port`, `payload`, `expected`, `timeout` |
| `[dns]` | `expected` |
| `[icmp]` | `count`, `timeout` |

Targets (`url` or `host`) are intentionally not loaded from TOML or the
environment. Supply exactly one target after the command.

## Environment variables and secrets

Environment names use the `CANARY_` prefix and the uppercased option name:
`CANARY_RETRIES`, `CANARY_RECOVERYTHRESHOLD`, `CANARY_DB`, `CANARY_TIMEOUT`,
`CANARY_STATUS`, `CANARY_NOTIFY`, and `CANARY_HEADERS`, for example. Camel-case
option names do not gain an extra underscore: use `CANARY_MINDAYS` and
`CANARY_MAXREDIRECTS`.

Prefer the environment for notification URLs, bearer tokens, and authorization
headers so they are absent from shared process listings and checked-in TOML:

```bash
export CANARY_NOTIFY='https://hooks.example.invalid/private-token'
export CANARY_HEADERS='Authorization: Bearer private-token'
canary http https://api.example.test/health
```

Environment variables are still visible to the process and may be observable
to sufficiently privileged local users. Protect service-manager environment
files with restrictive permissions and do not commit real secrets.

## Validation and command behavior

All sources use the same type conversion and parser-independent validation.
Invalid ports, timeouts, retry counts, methods, status codes, hostnames, header
syntax, and other check settings therefore exit with code 2 before network
access. `--help`, command help, `--version`, result output, and exit codes remain
part of the black-box CLI contract in [`cli-contract.md`](cli-contract.md).
