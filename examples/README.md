# Examples

Every example uses loopback or reserved `.example`/`.test` names and contains
no real credentials. The local demo is executed by `nimble testDocs`.

## Local HTTP, TCP, UDP, and webhook demo

From the repository root:

```bash
./examples/run-local-demo.sh
```

The script builds Canary and the one-shot test fixture when needed, starts each
service on a kernel-assigned loopback port, and checks:

- an HTTP body assertion;
- a TCP request/response assertion;
- a UDP response assertion;
- a generic mock-webhook delivery test.

It writes temporary port and diagnostic files below a private temporary
directory and removes them on exit. It never contacts the public network. Set
`CANARY_BIN` or `FIXTURE_BIN` to test alternate prebuilt binaries.

## Configuration

[`canary.toml`](canary.toml) contains safe typed defaults for every command.
Copy it to `$XDG_CONFIG_HOME/canary/config.toml` and keep secrets in a protected
environment file:

```bash
install -Dm600 examples/canary.toml ~/.config/canary/config.toml
export CANARY_NOTIFY='https://hooks.example.invalid/private-token'
canary http https://api.example.test/health --id production-api
```

The reserved URL intentionally cannot deliver. Replace it only in your local,
untracked configuration. See the [configuration guide](../docs/configuration.md).

## Schedulers

- [`metronome-web.md`](metronome-web.md) lists job names, schedules, and argv
  suitable for entering in Metronome-Web without embedding notification
  credentials.
- [`canary.cron`](canary.cron) demonstrates cron with a protected environment
  file and stable check identities.
- [`systemd/canary-api.service`](systemd/canary-api.service) and
  [`systemd/canary-api.timer`](systemd/canary-api.timer) form a hardened
  oneshot/timer pair. [`systemd/canary.env.example`](systemd/canary.env.example)
  documents the environment file without a usable secret.

Schedulers should invoke Canary more frequently than cooldown/reminder
precision requires. Keep `--id`, database path, thresholds, and notification
targets consistent across runs that own the same history.
