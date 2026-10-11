# Development

Canary targets Linux and 64-bit Windows in the 0.1.x series and builds with Nim
2.0 or newer. The repository currently tests with Nim 2.2. Development requires a C compiler,
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
The Windows job runs `nimble testWindows`, which performs static/debug/release
builds and native smoke tests for HTTP and timing, regex assertions, TCP, UDP,
DNS, ICMP, TLS, command execution and timeout handling, SQLite state, and the
documentation contract. The executable local demo remains a POSIX shell test
in the Linux job.

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

## Release workflow

1. Update the literal version in `canary.nimble` and `CanaryVersion` in
   `src/canary_contract.nim` together.
2. Move unreleased changes into a dated version section in `CHANGELOG.md`,
   keeping an empty `Unreleased` section for subsequent work.
3. Run `nimble checkAll` and `git diff --check`, commit the release changes,
   and push them to `master`.
4. Wait for both Linux and Windows GitHub Actions jobs to pass for that commit.
5. Create an annotated `vVERSION` tag on the tested commit and push it. Publish
   a GitHub release using that tag and the corresponding changelog section.

Releases currently distribute source through GitHub's generated archives.
Users build with Nimble and install the platform dependencies documented in
the [README](../README.md#installation).

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
