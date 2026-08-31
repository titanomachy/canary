# Metronome-Web jobs

Create one Metronome-Web job per check. The exact UI and job-storage format
belong to the installed Metronome-Web version; the stable part is the executable
and argv shown here.

| Job | Schedule | Executable and arguments |
| --- | --- | --- |
| Production API | Every minute | `/usr/local/bin/canary http https://api.example.test/health --id production-api --statusRange 2xx --jsonField service.status=ready --retries 2 --recoveryThreshold 2 --json` |
| Public certificate | Daily at 08:00 UTC | `/usr/local/bin/canary ssl api.example.test --id production-api-tls --minDays 21 --json` |
| PostgreSQL socket | Every two minutes | `/usr/local/bin/canary tcp db.internal --port 5432 --id production-db --timeout 1000 --retries 2 --json` |
| Authoritative DNS | Every five minutes | `/usr/local/bin/canary dns api.example.test --type A --expected 192.0.2.10 --id production-dns --json` |

Set `CANARY_DB=/var/lib/canary/state.db` and `CANARY_NOTIFY=...` in the protected
environment inherited by the Metronome-Web worker. Do not paste a real webhook
URL into the job command: process arguments and job history may expose it.

Canary's `0` and `1` exits map naturally to successful and failed job runs.
Configuration errors (`2`) should be treated as an operator problem rather than
service downtime. JSON output provides `status`, `latency_ms`, and, for HTTP,
`response_time_ms` for dashboards or history processing.
