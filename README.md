# SecurityLens

SecurityLens is a unified security-operations platform: it ingests multi-source
security logs (CloudTrail, SSH, nginx, application), runs a layered detection
engine over them, and turns the anomalies it finds into deduplicated,
correlated, LLM-triaged alerts that a SOC analyst works from a live dashboard.
It combines five capabilities — log anomaly detection, sensitive-data-exposure
classification, identity/access anomaly detection, an LLM threat-hunting
assistant, and production-style alerting — into one coherent pipeline rather
than five disconnected scripts. The large language model is used only where
judgement helps (triage, investigation, English→Go rule generation) and never
on the per-log hot path, so detection stays fast and cheap while the
analyst-facing reasoning stays rich.

The headline result, measured against labelled synthetic ground truth: **100%
recall and 100% operational precision with zero false positives on benign
activity**, holding across datasets from 8k to 500k logs and multiple seeds
(details and caveats below). Every number in this README traces to a command in
[Measured results](#measured-results) that was actually run.

---

## Threat model

SecurityLens is built to catch the account- and access-centric attacks that
dominate real cloud breaches, where the adversary is using valid or
brute-forced credentials rather than dropping malware:

| Threat | What the attacker does | How SecurityLens catches it |
| --- | --- | --- |
| **Credential stuffing / brute force** | Sprays many failed logins against many accounts from one source | Rule detector: failed-auth count per source IP over a short window |
| **Privilege escalation** | Grants themselves admin, an IAM self-grant after a foothold | Rule detector: self-granted elevated permission changes |
| **Sensitive-data exposure** | Leaks PII/secrets into logs | Classifier: PII/secret patterns with example-vs-real discrimination |
| **Identity anomaly** | Logs in successfully from a never-before-seen location/IP | Statistical: per-user baseline of source IPs; new **successful** origin |
| **Lateral movement** | Uses one identity to reach many hosts in a burst | Rule detector: distinct-host SSH fan-out per user over a window |
| **Off-hours access** | Operates at a user's local deep-night, evading daytime norms | Statistical: per-user local-hour baseline, successful access only |
| **Data exfiltration** | Moves a large volume of bytes outbound | Rule detector: outbound byte volume over threshold |

**Trust boundaries.** Logs are treated as untrusted, attacker-influenced input;
detectors read only operational fields and never the ground-truth labels (see
the label firewall below). The LLM is treated as an untrusted code generator:
any Go it produces is checked against an import allowlist and compiled in an
isolated throwaway module before a human ever sees it, and it is never executed.
Secrets (the Anthropic API key) come from the environment and are never logged;
the secrets classifier even redacts the secrets it finds before they reach an
alert.

**Non-goals.** This is not a network IDS, an EDR, or a malware sandbox. It
reasons over structured security logs, not packet captures or binaries.

---

## Architecture

```
  CloudTrail      SSH       nginx        app          sources
      |            |          |           |
      +------------+----+-----+-----------+
                        v
              normalize -> LogEvent               internal/model
                        |
                        v
        +-------------------------------------------+
        |        DETECTION ENGINE (per window)      |  internal/detect
        |                                           |  internal/pipeline
        |  L1  rule detectors        (Go, no LLM)   |
        |  L2  statistical baselines (per-user, Redis)
        |  L3  LLM triage            (cached, off hot path)
        +---------------------+---------------------+
                              v
          dedup (event-time key) -> correlate (entity)    internal/pipeline
                    |                        |
                    v                        v
                 alerts                  incidents
                    |
   +--------+-------+--------+-------------+-------------+
   v        v       v        v             v             v
dashboard on-call runbooks investigation rule-gen    metrics
(SSE live) JSON  (per type) (LLM+context) (LLM->Go,   (FP rate,
                                          compiled)   latency, vol)
   |
   +-- React + TanStack Query + Recharts front end        web/

 Storage:  PostgreSQL + TimescaleDB (logs hypertable, alerts, incidents,
           llm_usage, eval_runs)  ·  Redis (baselines, LLM cache, pub/sub)
```

Detectors are pure functions over a batch of `LogEvent`s, which makes each one
directly unit-testable against labelled fixtures. The engine sweeps event-time
windows out of Postgres, fans each window out to every detector, and dedups the
resulting candidates by event-time key so overlapping windows merge rather than
duplicate.

### Label firewall

The synthetic dataset carries ground-truth labels (`logs.attack_id`,
`logs.attack_type`, and an `attacks` manifest) **only** so the evaluator and
tests can score detections. Detector code is forbidden from reading them; the
invariant "no `attack_` reference anywhere under `internal/detect/`" is enforced
by `make check-label-firewall`. This guarantees the reported accuracy reflects
detection on operational fields, not label leakage.

---

## Quickstart

### Option A — Docker Compose (one command)

```bash
cp .env.example .env        # optional: add ANTHROPIC_API_KEY for live LLM
docker compose up --build
```

This starts Postgres/TimescaleDB, Redis, the Go backend, and the nginx-served
front end. On first boot the backend seeds a synthetic dataset (200k logs / 21
days by default, configurable in `.env`) and begins detecting. Then open:

- **Dashboard:** http://localhost:3000
- **API:** http://localhost:8080/api/health

To populate the accuracy panel with a scored run against ground truth:

```bash
docker compose run --rm backend /app/eval
```

> **Build status in this environment.** The Compose stack, Dockerfiles, and
> nginx config are authored and internally verified — the nginx config passes a
> real `nginx -t`, and Server-Sent Events were confirmed to stream through nginx
> unbuffered in real time (an alert delivered mid-stream, not on connection
> close). The two Dockerfile `go build` steps and the `npm run build` step were
> run natively and succeed. The images themselves were **not** built here
> because this sandbox has no container runtime and none is installable without
> root (rootless Docker needs setuid `newuidmap` and `slirp4netns`). Everything
> else in this README was verified for real natively — see below.

### Option B — Native (no Docker)

Requires Go 1.22+, Postgres (with the TimescaleDB extension if you want the
hypertable; it degrades gracefully to a plain table otherwise), and Redis.

```bash
# point these at your services if they differ from the defaults
export DATABASE_URL="postgres://lens:lens@127.0.0.1:5432/securitylens?sslmode=disable"
export REDIS_ADDR="127.0.0.1:6379"

make seed        # generate the synthetic dataset (SEED_LOGS/SEED_DAYS/SEED_SEED)
make eval        # score every detector against ground truth, print the table
make run         # start the API + dashboard backend on :8080

# front end
cd web && npm install && npm run dev    # dev server on :3000, proxies to :8080
```

Useful targets: `make test` (unit), `make test-integration` (DB-backed
end-to-end detection test), `make check-label-firewall`, `make vet`, `make web`
(production front-end build). Run `make help` for the full list.

---

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | `postgres://lens:lens@…/securitylens` | Postgres DSN |
| `REDIS_ADDR` | `127.0.0.1:6379` | Redis address |
| `PORT` | `8080` | API / dashboard port |
| `ANTHROPIC_API_KEY` | *(empty)* | Anthropic key; empty selects the mock LLM |
| `LLM_MODE` | `auto` | `auto` = live if a key is present else mock; force with `mock` / `live` |
| `LLM_MODEL` | `claude-opus-4-8` | Model used for live calls |
| `SEED_ON_START` | `false` (`true` in compose) | Seed the dataset on boot if the logs table is empty |
| `SEED_LOGS` / `SEED_DAYS` / `SEED_SEED` | `200000` / `21` / `1` | Synthetic dataset size, span, and RNG seed |
| `SEED_ANCHOR_NOW` | `false` | End the dataset near "now" (fresh live feed); the evaluator omits this for reproducibility |
| `SWEEP_INTERVAL` / `DETECT_LAG` / `SWEEP_STEP` | `15s` / `5s` / `10m` | Live sweep cadence, settle lag, and window step |

### LLM: live and mock behind one interface

The triage, investigation, and rule-generation features call the Anthropic
Messages API through a hand-rolled client (no SDK dependency), using adaptive
thinking and retrying 429/5xx with backoff. When no API key is present, an
interface-compatible **mock** returns deterministic, labelled output of the same
JSON shape, parsed through the same code path, so the full pipeline and every
dashboard view are exercisable offline. Setting `ANTHROPIC_API_KEY` switches to
live calls with no code change. Every LLM result is tagged `mock: true|false` in
the API and UI so you always know which path produced it. Triage results are
cached in Redis and are never invoked on the per-log hot path.

---

## Example alert

```json
{
  "id": "6783079e-9de3-40a0-861e-9241003ecc03",
  "alert_type": "credential_stuffing",
  "severity": "high",
  "src_ip": "122.134.127.213",
  "title": "Credential stuffing: 32 failed logins from 122.134.127.213",
  "status": "open",
  "count": 1,
  "window_start": "2026-06-28T09:16:24Z",
  "window_end": "2026-06-28T09:20:00Z",
  "evidence": {
    "counts": { "failed_logins": 32, "distinct_users": 27 },
    "notes": ["27 distinct accounts targeted from a single source in under 4 minutes"],
    "samples": [ { "ts": "…", "event_type": "console_login", "status": "failure", "src_ip": "122.134.127.213" } ]
  }
}
```

`GET /api/alerts/{id}` returns the alert plus its runbook; a
`POST …/triage` attaches the LLM verdict/confidence/next-steps; a
`POST …/investigate` returns an attack hypothesis, benign explanations, and
pivot queries computed over the surrounding activity.

---

## Measured results

All numbers below come from `cmd/eval`, which drains the detection pipeline over
a labelled dataset and scores every alert against the `attacks` manifest. They
are reproducible with `make seed && make eval` — the generator uses a fixed time
anchor by default, so a given seed produces byte-identical results run-to-run
(verified: two full sweeps of the table below produced identical numbers).

| Dataset | Recall | Operational precision | Type-exact precision | Benign false positives | Backfill drain |
| --- | --- | --- | --- | --- | --- |
| 8k logs / 10d / seed 7 | 100% | 100% | 89% | 0 | ~0.6s |
| 20k logs / 14d / seed 1 | 100% | 100% | 73% | 0 | ~1.6s |
| 200k logs / 21d / seed 1 | 100% | 100% | 76% | 0 | ~5.2s |
| 200k logs / 21d / seed 3 | 100% | 100% | 76% | 0 | ~5.0s |
| 500k logs / 30d / seed 42 | 100% | 100% | 88% | 0 | ~9.6s |

All seven attack types are detected in every run. Synthetic-log **load**
throughput is roughly **130k logs/sec** (Postgres `COPY`); detection **backfill**
throughput is roughly **50k logs/sec** single-node (500k logs drained and scored
in ~9.6s). In live mode, detection latency is bounded by
`SWEEP_INTERVAL + DETECT_LAG` (~20s with the defaults); the per-window detection
work itself is sub-second. The live pipeline was confirmed to reproduce the same
17 alerts / 0 benign false positives on the 200k/seed-1 dataset as the batch
evaluator.

### Why two precision numbers

- **Operational precision** counts an alert as correct if it overlaps a real
  attack on the same entity, regardless of which detector fired. This mirrors how
  a multi-detector SOC with alert correlation actually triages: an alert pointing
  at genuine attack activity is useful even if a different detector "owned" that
  technique. Operational precision is **100%** — SecurityLens raises zero alerts
  on benign activity in every run above.
- **Type-exact precision** additionally requires the detector's label to match
  the ground-truth label. It sits at 73–89% because the *same* malicious activity
  legitimately trips more than one detector — e.g. a credential-stuffing
  breakthrough that succeeds also looks like an identity anomaly and an off-hours
  event (the attacker logs in from a new IP at the victim's odd local hour), and
  correlation merges them into one incident. These are overlapping true
  detections, not false alarms, which is why they cost type-exact but not
  operational precision.

Getting to zero benign false positives was the core detection-engineering work.
The dominant false-positive source was credential-stuffing spillover: a brute
-force burst lands *failed* logins on dozens of victims at one instant, which for
users in negative-offset timezones is their local deep-night, so naive off-hours
and identity detectors flagged every victim. The fix was to make behavioural
detectors ignore failed/denied events entirely (off-hours counts only successful
access; identity requires a successful auth from the new origin) and to overlap
sweep windows so bursts straddling a boundary are never split below threshold.
See [`NOTES.md`](NOTES.md) for the full tuning history.

---

## The five capabilities, mapped to code

1. **Log anomaly detection + LLM triage** — `internal/detect/rules.go`
   (credential stuffing, privilege escalation, lateral movement, exfiltration)
   feeding `internal/llm/service.go` for cached verdicts.
2. **Sensitive-data-exposure detection** — `internal/detect/secrets.go`, a
   PII/secret classifier that discriminates real secrets from
   examples/placeholders (Luhn + test-card + placeholder filtering) so the LLM
   isn't burned on obvious non-findings, and redacts what it does find.
3. **Identity/access anomaly** — `internal/detect/stats.go` with per-user
   baselines in Redis (`internal/detect/baseline.go`) for source IPs and local
   activity hours (new-location logins, off-hours access).
4. **Threat-hunting assistant** — `internal/llm/service.go` for the
   investigation endpoint and English→Go rule generation, with generated code
   checked against an import allowlist and compiled in isolation by
   `internal/rulegen/validate.go`.
5. **Production alerting** — `internal/pipeline/pipeline.go` (dedup by event-time
   key, entity correlation into incidents), `internal/runbook/runbook.go` (a
   runbook per alert type), on-call JSON, and the metrics endpoint reporting FP
   rate, latency, and volume.

---

## Testing

- `make test` — unit tests for every detector against labelled fixtures, the
  secrets classifier's FP/TP table, baseline construction (successes learned,
  failures never), generator realism invariants, dedup/eval scoring, the mock
  LLM's shape/determinism, and the rule-generation compile/reject/never-execute
  path.
- `make test-integration` — seeds a real Postgres+Redis, drains the pipeline,
  and asserts 100% per-type recall with zero benign alerts, that every alert is
  correlated into an incident, and that a second drain is dedup-stable.
- `make check-label-firewall` — proves detector code never references the
  ground-truth labels.

All of the above pass in this environment; see the final summary for the run
output.

---

## Limitations and honest caveats

- **Synthetic data.** Detection is validated against a synthetic generator with
  labelled attacks, not production traffic. The generator is deliberately
  realistic (per-user timezones including half-hour offsets, home/office-IP
  logins, per-user host sets, benign shoulder-hour activity, documentation-style
  secret confusers) so the detectors face plausible confusers, but real
  environments will need threshold tuning. Recall/precision are reported on this
  synthetic ground truth.
- **Mock LLM without a key.** Absent `ANTHROPIC_API_KEY`, triage / investigation
  / rule-gen use a deterministic mock behind the same interface. It exercises
  every code path and UI state but does not reflect live model quality; results
  are labelled `mock: true`. The live Anthropic path is implemented and selected
  automatically when a key is present, but was not exercised here because no key
  was provided to this build.
- **Docker not built in this environment.** The Compose stack, Dockerfiles, and
  nginx config are authored and self-consistent; the nginx config passes
  `nginx -t` and the SSE-through-nginx behaviour was verified against the running
  backend. No container runtime is installable without root in this sandbox, so
  the images were not built here — everything else was verified natively (Go
  build/vet, full unit + integration tests, the evaluator, a live server smoke
  test with every endpoint curl'd, a headless-browser pass over the dashboard,
  and the front-end production build).
- **TimescaleDB optional.** The logs table is a TimescaleDB hypertable when the
  extension is available and a plain table otherwise; the migration branches on
  `pg_extension` and all queries are written to work either way. The Compose
  stack uses the TimescaleDB image; native verification here ran on vanilla
  PostgreSQL 16.
- **Single node.** The pipeline runs in-process. Horizontal scale-out (sharding
  the sweep by entity, multiple workers) is a design extension, not implemented.
