# Caminus — Build Plan

Resume state for the Caminus build. Current target: **v0.1.0** (Sprint 1).

## Status

- **M1 (done):** GitHub Actions static engine. 5 rules (`CAM-INJ/PPE/RUN/PERM/SUP-001`),
  text + JSON output, severity `--gate`, tests. Builds/vets/tests clean.

## Sprint 1 → v0.1.0 (in progress)

Goal: **multi-platform (GitHub + GitLab CI), pipeline-native (SARIF), token-free,
CI-ready, tagged v0.1.0.**

Vinculum/Ariadne export are **deferred** (post-v0.1 — they need the M2 graph and
add no new detection value now).

### Tasks

- [x] **1. GitLab CI parser** — `internal/gitlabci`: line model with
  `ExecContext(i)` (`script`/`before_script`/`after_script`), `Sources()`
  (`rules:`/`workflow:`/`only:` → push, merge_request_event, …), `Includes()`,
  debug-trace + dind + tags detection.
- [x] **2. GitLab rule set** — parity with the GitHub five:
  - `CAM-GL-INJ-001` (Critical, confirmable) — untrusted `$CI_*`
    (MR title/desc, branch name, commit message/author) in a `script:` block.
  - `CAM-GL-PPE-001` (Medium) — MR-event pipeline secret/`CI_JOB_TOKEN` exposure.
    *Framed honestly: GitLab protects variables by default, so this is narrower
    than GitHub's pwn-request.*
  - `CAM-GL-DBG-001` (High) — `CI_DEBUG_TRACE`/`CI_DEBUG_SERVICES` → secrets in logs.
  - `CAM-GL-RUN-001` (High/Med) — `docker:dind`/privileged build, or self-managed
    `tags:` on an MR-triggered job.
  - `CAM-GL-SUP-001` (Low) — `include: remote:` URL or `include: project:` on a
    mutable branch ref.
- [x] **3. Platform dispatch** — per-file detection (path: `.gitlab-ci.yml` /
  `.gitlab/**` → gitlab; `.github/workflows/**` → github) + `--platform` override;
  `scan` discovery picks up both; route to the right parser+ruleset.
- [x] **4. SARIF reporter** — `--format sarif` (SARIF 2.1.0), code-scanning ready.
- [x] **5. Fixtures + tests** — GitLab vuln/safe fixtures, platform-detection
  tests, SARIF golden test. Keep precision discipline (no FP on protected-var /
  env-routed best practice).
- [~] **6. Release eng** (goreleaser + CI + CHANGELOG done; git init pending user) — `.goreleaser.yml`, CI workflow that **self-scans**
  Caminus's own pipeline (dogfood), `CHANGELOG.md`, README polish, version
  ldflags. `git init` + first commit — **gated on user go-ahead; never push.**

### Scope cuts (deferred, not forgotten)
- Structural YAML parse (`-tags yaml`) — stay zero-dep line model for v0.1.
- Indirect-PPE (local script invoked under a privileged trigger) — stretch only.
- Vinculum parser + Ariadne attack-path export — post-v0.1 (M1.5/M2).

### Acceptance
`go vet`/`go test` green · GitLab vuln → criticals, safe → 0 · `--format sarif`
validates · self-scan passes in CI · `caminus version` reports the tag.

## Sprint 2 → M2: enum + trust graph + OIDC blast-radius

The moat. From a token, build the trust graph and synthesize ranked attack
paths from attacker-controllable triggers to secrets, self-hosted runners, and
**OIDC-federated cloud roles + resources**.

Decisions (locked): **GitHub-first** (GitLab enum → M2.5). Cloud data is **read
live from cloud APIs** (AWS first) — see *Dependency note*.

### Tasks
- [x] **1. GitHub enum client** — `internal/platform/github`, stdlib http,
  `CAMINUS_TOKEN`. Enumerates workflows (→ static rules → mark entry points),
  self-hosted runners (org+repo), secret *names* (repo+org), repo/org OIDC
  subject-claim config, branch protection on the default branch. Pagination
  (Link header), graceful 403/404. Record/replay transport (`internal/vcr`)
  with a fixture cassette + tests; `enum` command emits `graph.json`. **Zero-dep.**
  *Deferred to M2.x: environments enumeration, runner groups, full
  multi-page runner/secret listing, rate-limit backoff.*
- [x] **2. Trust-graph builder + `graph` command** — `internal/graph`
  reachability model (containment walked child→parent, capabilities forward),
  BFS from entry points (entrypoint=true / privileged triggers) to sinks
  (self-hosted runner / org+repo secret / OIDC / cloud-role), ranked by
  `entry-weight × sink-value ÷ path-len`, MITRE-tagged steps; `graph` cmd loads
  graph.json, optional `--scan` to mark entry points, text + json, severity
  filter. Tests + end-to-end (enum→graph) verified. **Zero-dep.**
- [ ] **3. OIDC modeling + `CAM-OIDC-001`** — over-broad federation (wildcard
  `sub`, missing `aud`, branch-unconstrained trust). GitHub side. **Zero-dep.**
- [ ] **4. AWS cloud read** — `internal/cloud/aws` (AWS SDK v2: iam + sts).
  Enumerate IAM roles trusting `token.actions.githubusercontent.com`, parse the
  `sub`/`aud` trust conditions, resolve which pipeline subjects can assume which
  roles → CloudRole/Resource nodes + can-assume/reaches edges + blast-radius.
  **Behind `-tags cloud`** so the core binary stays dependency-free.
- [ ] **5. Record/replay test harness** — fixture API/cloud responses (à la
  Vercelsior `--record`/`--replay`) so CI needs no live token/creds.

### Dependency note
Direct cloud reads add the AWS SDK, changing the project's "zero dependencies"
claim. Containment: core `scan`/`enum`/`graph` stay stdlib-only; cloud is
isolated in `internal/cloud/*`, AWS-first (GCP/Azure → M2.5/M3), gated behind
`-tags cloud`. Update README/DESIGN wording when Task 4 lands
("dependency-free core; cloud enumeration uses the official cloud SDKs").

### Scope cuts
GitLab enum → M2.5 · GCP/Azure cloud read → M2.5/M3 · full IAM permission
simulation (use role policy summaries, don't reimplement the evaluator) ·
Ariadne export → stretch.

### Acceptance
`caminus enum --org X --token …` → graph.json · `caminus graph -i graph.json
[--scan scan.json] --format text` → ranked paths · AWS OIDC trust resolved on a
fixture · `CAM-OIDC-001` fires on wildcard `sub` · record/replay tests green.

## Later milestones
- **M2.5:** GitLab enum + GCP/Azure cloud read; indirect-PPE; structural YAML;
  Vinculum parser + Ariadne export.
- **M3:** `exploit` — authorization-gated dynamic confirmation.
