# NOTES — build log and lessons

One lesson per entry, newest last. Summary line first, detail after.

## 1. Toolchain in a no-root, no-Docker sandbox
**Stood the whole stack up natively from user-space binaries when no container runtime was installable.**
This environment has no Go, Node, Docker, Postgres, or Redis, no passwordless sudo, and none of the rootless-Docker prerequisites (`newuidmap`/`newgidmap`/`slirp4netns` are missing, and the extracted `newuidmap` can't be setuid-root without root, so multi-UID user namespaces — which the official Postgres/Redis images need — are impossible). Solution: install everything into `~/.local` without root — Go and Node from their official tarballs, PostgreSQL 16 from Zonky's portable embedded-postgres binaries, Redis built from source (`make MALLOC=libc`), and the `psql` client extracted from the `postgresql-client-18` .deb. Postgres runs with a user-owned data dir on 127.0.0.1; Redis daemonized with `--save ''`. This is what makes every "measured" claim in the README real rather than authored.

## 2. TimescaleDB is used when present, with a verified plain-Postgres fallback
**Migration creates the hypertable only if the extension exists; everything else is identical.**
`docker-compose.yml` ships the `timescale/timescaledb` image so users get a real hypertable. This build environment can't install the extension, so local verification runs on vanilla Postgres 16 through the same migration, which branches on `pg_extension`, logs a NOTICE, and keeps `logs` a plain table. All queries are extension-agnostic. Documented in the README so nobody is surprised.

## 3. Ground-truth labels live next to the logs but are firewalled from detection
**`logs.attack_id` / `logs.attack_type` and the `attacks` manifest exist only for evaluation.**
Detector SQL never selects these columns; only `cmd/eval`, `internal/eval`, and tests read them. This is what makes the README metrics honest instead of decorative. A grep-able invariant enforced by `make check-label-firewall`: the string `attack_` must not appear under `internal/detect/`.

## Detection tuning lessons (from eval-driven iteration)

- **Credential-stuffing pollution was the dominant false-positive source.** A
  single credential-stuffing burst lands *failed* logins on 20–50 victims at one
  fixed UTC instant. For victims in negative-offset timezones that instant is
  their local deep-night, so the off-hours detector counted those failures as
  "off-hours access", and the identity detector counted the new attacker IP as a
  new-location login. Fix: behavioural detectors must ignore failed/denied
  events (off-hours counts only successful *access*; identity requires a
  *successful* auth from the new IP). This single insight took operational
  precision from ~50% to 100% at every scale. The first eval run after wiring the
  detectors showed 27 benign FPs; this fix plus the two below drove it to 0.

- **Window-boundary splitting hurts recall for count-threshold detectors.** A
  burst that straddles a sweep-window boundary can split below threshold on both
  sides and be missed. Fix: overlap successive sweep windows by one `SweepStep`
  (each window is `2*step` long, advancing by `step`) so any burst shorter than
  the step is fully contained in at least one window; event-time dedup collapses
  the duplicate firings into one alert. This made recall a robust 100% across
  8k/20k/200k/500k without lowering thresholds.

- **Generator realism removes whole FP classes.** Benign logins from the user's
  home/office IP (always in baseline before attacks begin on day 3), benign SSH
  scoped to a small per-user host set (people reach their own few servers, not
  the fleet), and API calls without a dst-host eliminated identity/lateral benign
  FPs at the source instead of by raising thresholds (which would have cost
  recall). The generator also seeds documentation-style secret confusers
  (`AKIA…EXAMPLE`, `sk_test_…`, masked `****`, test card numbers) so the secrets
  classifier is graded against realistic non-findings.

- **The secrets classifier is about discrimination, not detection.** Regexes that
  match "a secret-shaped string" are trivial; the first eval run turned every
  masked `token=************` benign log line into 26 false positives. The fix was
  a positive/negative gate: reject placeholder markers (`example`, `<redacted>`,
  `xxxx`, `****`, uniform/short values), require live secrets to mix character
  classes, Luhn-check card numbers and drop known test cards, and reject reserved
  SSN ranges. The classifier's FP/TP table is a committed unit test.

- **Off-hours needs a dead-band and a maturity gate, and half-hour timezones
  bite.** Off-hours fires only when an hour and the two hours either side are all
  empty in the user's baseline, and only after the user has ≥40 successful events
  across ≥3 distinct days — otherwise a brand-new user's first evening event
  self-reports as anomalous. A late regression: anchoring the dataset near "now"
  shifted absolute timestamps, and a `+5:30` user's benign morning event landed
  on a fractional-UTC-hour boundary the integer-hour baseline histogram hadn't
  populated, producing one FP. Fix: warm the baseline across
  `workStart-1 … workEnd+2` so shoulder and boundary hours are always covered.

- **Determinism matters for reproducible evals.** The generator originally
  anchored the dataset end to wall-clock "now" (so the live feed has fresh
  events). That made eval results drift run-to-run as timezone boundaries moved.
  Fix: default to a fixed epoch anchor (reproducible; two full sweeps now produce
  identical numbers) and gate the anchor-to-now behaviour behind `AnchorNow`,
  used only by the server's first-boot seed and `SEED_ANCHOR_NOW`.

- **Baselines must learn from successes only, and reset with the dataset.** The
  per-user Redis baseline is updated only from *successful* access — learning
  from failures would let a stuffing burst whitelist the attacker IP before the
  breakthrough. Two operational traps found live: reseeding must flush Redis
  (stale baselines from the previous dataset mass-flag new-origin logins), and a
  fresh sweep watermark must reset the baselines (same reason). Both are handled
  in `cmd/seed` (Redis flush) and the pipeline's fresh-watermark path.

- **Live pipeline == batch evaluator.** A scary-looking 44-alert live run turned
  out to be an operational artifact — a previous server instance was still
  sweeping the DB while I concurrently ran the evaluator and reseeded underneath
  it. Run cleanly (stop, seed, start), the live catch-up reproduces the batch
  evaluator's exact 17 alerts / 0 benign FP on 200k/seed-1. The lesson: don't
  mutate a running pipeline's tables from another process and expect its output
  to mean anything.

- **Two precision numbers are worth reporting.** Type-exact precision penalises
  an alert whose detector label differs from the ground-truth label even when it
  correctly flags real attack activity (a credential-stuffing breakthrough that
  succeeds also reads as an identity anomaly *and* an off-hours event, since the
  attacker logs in from a new IP at the victim's odd local hour); operational
  precision credits any alert that overlaps a real attack on the same entity.
  Operational precision reflects how a multi-detector SOC with correlation
  actually behaves. Measured type-exact lands at 73–89% across scales; the gap is
  entirely these overlapping true detections.

## LLM and rule-generation lessons

- **The LLM is an untrusted code generator — validate in two layers.** Generated
  rules are first parsed for their import set and rejected unless every import is
  on a pure-computation allowlist (`fmt`, `strings`, `strconv`, `time`, `regexp`,
  …); anything touching `os`, `os/exec`, or the network is refused before the
  compiler runs. Whatever passes is then compiled in a throwaway module with
  `GOPROXY=off` and is **never executed**. A unit test proves an `os`-importing
  rule is rejected and that a rule with a side-effecting initializer compiles but
  never runs. The import allowlist was added *because* the test first caught that
  an `os/exec`-importing rule compiled cleanly.

- **The mock must be a real stand-in, not a stub.** The deterministic mock emits
  the same JSON shape as the live model for each feature, derived only from the
  request content, and is parsed through the exact same code path (including the
  brace-balanced JSON extractor that tolerates prose/code-fence wrapping). Unit
  tests assert the mock is parseable, deterministic, and complete for triage,
  investigation, and rule-gen — so the offline demo exercises the same plumbing
  the live path would.

## Front-end lessons

- **Recharts fills don't resolve CSS `var()`.** The dashboard theme uses CSS
  custom properties, but Recharts writes colours into SVG `fill` attributes where
  `var(--series-1)` renders as nothing — the alert-by-type bar chart came up with
  labels and no bars. Fix: charts use resolved hex (the validated dark-mode
  categorical steps) while the surrounding React UI keeps the CSS variables.
  Caught by a headless-browser pass that counted rendered `<path>` bars.

- **nginx + SSE:** the reverse proxy must set `proxy_buffering off` (and the API
  already sends `X-Accel-Buffering: no`) or Server-Sent Events are buffered and
  the live feed stalls. Verified for real: with the committed `nginx.conf`
  fronting the running backend, an alert published mid-stream arrived at the
  client immediately rather than on connection close.
