# Contributing to Canary

Thanks for improving Canary. Changes should preserve its small single-run CLI
model, stateless default, deterministic local tests, and explicit security
boundaries.

## Before opening a change

1. Discuss large product or architecture changes before implementation.
2. Install the prerequisites and dependencies described in
   [`docs/development.md`](docs/development.md).
3. Add focused coverage in the appropriate unit, integration, CLI, or
   documentation suite.
4. Update `CHANGELOG.md` under `Unreleased` for user-visible behavior.
5. Run:

   ```bash
   nimble checkAll
   git diff --check
   ```

## Expectations

- Keep commits and pull requests focused; do not include generated `build/`
  files or local databases.
- Preserve CLI exit codes and existing JSON fields unless a documented breaking
  release explicitly changes them.
- Use local fixtures on random ports. Tests must not depend on public networks,
  provider accounts, wall-clock timing races, or real secrets.
- Invoke helpers and commands with executable-plus-argv APIs, never a shell.
- Redact URL userinfo, query values, fragments, webhook paths, credentials,
  command arguments, and raw command output from public diagnostics.
- Add comments where they explain a contract or non-obvious reason, especially
  around transactions, deadlines, and redaction; skip comments that restate the
  code.
- Keep new dependencies minimal, constrained, and justified.

## Pull-request description

Explain the user-visible outcome, tests run, compatibility impact, and any
security or migration considerations. Mention remaining limitations explicitly.
If the change affects state, describe concurrent-process and existing-database
behavior.

Bug reports should include the Canary version, command shape with secrets
redacted, exit code, output, Linux distribution, and relevant tool versions.
Do not post notification URLs, authorization headers, tokens, or private target
details.
