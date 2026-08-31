# Development

Canary targets Linux in the 0.1.x series and builds with Nim 2.0 or newer. The
repository currently tests with Nim 2.2. Development requires a C compiler,
SQLite headers/library, the PCRE runtime, OpenSSL, `ping`, and libcurl for HTTP
timing tests.

## Set up

```bash
git clone https://github.com/titanomachy/canary.git
cd canary
nimble install -d
nimble build -y
```

Nimble writes generated binaries and caches under `build/`, which is ignored.
Do not edit vendored content under `nimbledeps/`.

## Repository layout

```text
src/canary.nim          minimal process entrypoint
src/canary/             CLI/configuration and application orchestration
src/checks/             parser-independent check implementations
src/notifier.nim        SQLite state machine and notification outbox
tests/unit/             pure and state-contract tests
tests/integration/      loopback network and multiprocess tests
tests/cli/              public black-box CLI contract
tests/docs/             documentation link/structure tests
tests/fixtures/         one-shot local protocol servers and workers
docs/                   user and maintainer contracts
examples/               safe configuration and scheduler recipes
```

Read [`architecture.md`](architecture.md) before moving boundaries and
[`baseline-contract.md`](baseline-contract.md) before changing output or exit
semantics.

## Test commands

| Command | Purpose |
| --- | --- |
| `nimble test` | Unit, integration, CLI, documentation, and executable example smoke tests. |
| `nimble testCli` | Public stdout, stderr, JSON, help, and exit codes. |
| `nimble testIntegration` | Local protocol fixtures and SQLite concurrency. |
| `nimble testDocs` | Local Markdown links and local-demo execution. |
| `nimble checkAll` | Style/static checks, debug/release builds, then all suites. |

The suite must not contact public websites, DNS resolvers, or notification
providers. Network tests bind `127.0.0.1` or `::1` on kernel-assigned ports.
See [`testing.md`](testing.md) for coverage and fixture behavior.
The Linux GitHub Actions workflow runs the same `nimble checkAll` command with
Nim 2.2.10, so documentation and executable examples cannot bypass CI.

## Change workflow

1. Add or update a test that expresses the contract.
2. Keep checks independent of the CLI parser: accept typed values and return a
   `CheckResult` instead of printing or terminating the process.
3. Validate configuration before network or process execution.
4. Update user docs, examples, README links, and `CHANGELOG.md` when behavior is
   visible externally.
5. Run `nimble checkAll` and `git diff --check`.

Use comments for contracts, invariants, redaction boundaries, deadlines, and
the reason behind non-obvious transaction decisions. Avoid narrating obvious
control flow. Public output is a compatibility surface; add fields rather than
silently renaming existing JSON fields.

## Security review checklist

- Does untrusted input ever reach a shell or command string?
- Can credentials appear in stdout, stderr, state IDs, notification messages,
  exception text, or child-process arguments?
- Is a timeout one bounded deadline rather than multiplied per attempt?
- Are state and outbox changes atomic under concurrent processes?
- Does a new network fixture stay local and deterministic?
- Are new dependencies constrained and documented?

Report vulnerabilities privately to the maintainer rather than opening a
public issue with credentials or exploit details.

## Documentation and examples

Keep README focused on orientation and the first successful run. Put detailed
semantics in `docs/` and link to them. Examples must use reserved domains or
loopback addresses, contain no real credentials, and be exercised by
`nimble testDocs` when executable.

When adding a local Markdown link, the documentation test resolves it relative
to the containing file. Keep filenames case-correct so links also work on Linux
and GitHub.
