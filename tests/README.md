# Tests

Run the complete suite with:

```bash
nimble test
```

Run only the command-line black-box suite with:

```bash
nimble testCli
```

Run the local integration suite with:

```bash
nimble testIntegration
```

Check local documentation links and run the HTTP/TCP/UDP/webhook example with:

```bash
nimble testDocs
```

Run static checks, debug and release builds, and every test suite with:

```bash
nimble checkAll
```

The test layers are:

- `unit/test_unit.nim`: typed application configuration, parser-independent
  execution, layered TOML/environment/CLI configuration, parsing, validation,
  result formatting, redaction, direct
  helper-process arguments/timeouts, local command assertions, check IDs, and
  the complete SQLite
  state-transition table. Deterministic notifier clocks cover cooldowns,
  reminders, and maintenance silences. Every state test owns a temporary
  database.
- `integration/test_integration.nim`: local HTTP, TCP, UDP, DNS, TLS, and
  webhook servers on random ports, HTTP phase timing (including a real local
  TLS handshake), IPv6 loopback coverage for every socket
  transport, plus multiprocess SQLite state and reminder concurrency tests.
- `cli/test_cli.nim`: black-box coverage of the public behavior in
  `docs/cli-contract.md`, including config paths, precedence, typed errors, and
  explicit state identity, silence behavior, and shellless local command
  execution, using local IPv4 and IPv6 TCP sockets.
- `docs/test_docs.nim`: local Markdown-link resolution, README scope, required
  manual/example inventory, and safe example-configuration assertions.
- `fixtures/`: small Nim executables used by integration tests. They accept one
  request or datagram and exit, which keeps tests deterministic.

The documentation task also executes `examples/run-local-demo.sh` against the
one-shot local fixtures. No suite contacts a public website or external
notification provider. See
[`docs/testing.md`](../docs/testing.md) for the scenarios and fixture contract.
