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

Run static checks, debug and release builds, and every test suite with:

```bash
nimble checkAll
```

The test layers are:

- `unit/test_unit.nim`: typed application configuration, parser-independent
  execution, layered TOML/environment/CLI configuration, parsing, validation,
  result formatting, redaction, direct
  helper-process arguments/timeouts, check IDs, and the complete SQLite
  state-transition table. Every state test owns a temporary database.
- `integration/test_integration.nim`: local HTTP, UDP, TLS, and webhook servers
  on random ports plus a multiprocess SQLite concurrency test.
- `cli/test_cli.nim`: black-box coverage of the public behavior in
  `docs/cli-contract.md`, including config paths, precedence, typed errors, and
  explicit state identity, using local TCP sockets.
- `fixtures/`: small Nim executables used by integration tests. They accept one
  request or datagram and exit, which keeps tests deterministic.

No suite contacts a public website or external notification provider. See
[`docs/testing.md`](../docs/testing.md) for the scenarios and fixture contract.
