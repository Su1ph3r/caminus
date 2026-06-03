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
- [x] **3. OIDC modeling + `CAM-OIDC-001`** — `internal/platform/github/oidc.go`
  computes the effective subject pattern from the repo's claim customization and
  flags repo-wide subjects (no ref/environment scoping) as over-broad. Emits
  `CAM-OIDC-001` (Medium, honest framing — actionable once cloud trust is
  matched in Task 4) into `Graph.Findings`; annotates the OIDC node
  (`subject_pattern`, `over_broad`) and bumps its sink value so OIDC→cloud paths
  rank higher. `enum` surfaces enum findings; tests + end-to-end verified.
  **Zero-dep.**
- [x] **4. AWS cloud read** — `internal/cloud`: dependency-free trust-policy
  parser + subject matcher + `Enrich` (graph mutation, `CAM-OIDC-002`) in
  always-compiled files with full unit tests; AWS SDK `Fetch` (iam:ListRoles)
  isolated in `aws.go` behind `-tags cloud`, stub otherwise. `cloud` command
  adds CloudRole nodes + can-assume edges and the CI→OIDC→cloud attack path.
  Containment verified: default build links **0** AWS pkgs, `-tags cloud` links
  57; default `cloud` degrades to a rebuild hint. *Deferred: AWS record/replay
  fixtures (Task 5), resource-level blast radius, GCP/Azure (M2.5).*
- [x] **5. Record/replay test harness** — `internal/vcr` extended with request
  body discriminator matching (AWS IAM is query-protocol: POST / with the action
  in the body). `cloud` gained `--replay`/`--record`; the AWS SDK honours an
  injected transport + anonymous creds. Hand-built IAM ListRoles cassette +
  cloud-tagged replay test drive the real SDK XML deserializer with no AWS
  account. CI now runs `go test -tags cloud ./...` and `go build -tags cloud`.
  Full enum→cloud→graph pipeline verified end-to-end via replay.

### M2 finalization (completing the milestone)
- Paginated runner/secret enumeration (Link header), not just the first page.
- Environments + protection-rule enumeration recorded on the repo node.
- Rate-limit-aware error (403 + `X-RateLimit-Remaining: 0`).
- Removed the stale `graph --cloud` placeholder flag (`cloud` is its own command).
- Docs (README/DESIGN) updated: M2 marked delivered, cloud flow + `-tags cloud`
  build documented. **M2 COMPLETE.**

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

## M2.5 → v0.3.0 (done)

Multi-platform enum + multi-cloud blast radius.
- [x] **GitLab enum** — `internal/platform/gitlab`: zero-dep REST (v4) client +
  enumerator (group/project, `.gitlab-ci.yml` entry-point detection via the
  GitLab rule set, runners, CI/CD variables, `id_tokens:` OIDC). `enum
  --platform gitlab`; self-managed via `--base-url`. Replay cassette + tests.
- [x] **GCP cloud read** — `internal/cloud/gcp.go` (`-tags cloud`): Workload
  Identity Federation (pools/providers + SA IAM bindings) → GitHub trusts. Pure
  member parser (`gcp_member.go`) always-compiled + unit-tested. Replay test.
- [x] **Azure cloud read** — `internal/cloud/azure.go` (`-tags cloud`): app-
  registration federated identity credentials via Microsoft Graph. Replay test.
- [x] **`cloud --provider aws|gcp|azure`** (+`--project` for GCP); provider-
  neutral `GitHubTrust` + per-cloud CAM-OIDC-002 wording. Default build links 0
  cloud SDKs; GCP/Azure isolated behind `-tags cloud`.

## M3 → v0.4.0–v0.5.0 (done)

`exploit` — dynamic confirmation for confirmable findings.
- [x] **Generate (v0.4.0):** `internal/exploit` + `exploit` command. Confirmable
  findings (graph `-i` and/or `scan --format json --scan`) → artifact (attack
  input / pipeline payload with a benign canary) + reversible
  Deliver/Evidence/Cleanup plan. Generators for injection (CAM-INJ-001/
  CAM-GL-INJ-001), pwn-request (CAM-PPE-001, secret presence not value), runner
  (CAM-RUN-001/CAM-GL-RUN-001), OIDC→cloud (CAM-OIDC-002; AWS/GCP/Azure ×
  GitHub/GitLab). Deterministic canary; read-only by design.
- [x] **Live arming (v0.5.0):** `--arm --i-own-target` delivers a workflow PoC to
  a branch on an owned target, triggers it, confirms the canary in run logs, and
  deletes the branch (cleanup deferred on every path; `--keep` opts out). Token
  host-gated; non-armable PoCs fall back to the playbook. Scripted-transport
  tests.
- [x] **GitLab→cloud (v0.5.0):** `cloud` resolves OIDC→cloud for GitLab graphs —
  issuer-aware trust model, grammar-agnostic subject classify, platform-gated
  matching; CAM-OIDC-002 fires for GitLab projects.

## M3.5 → v0.6.0 (done)

Deeper detection, no token required.
- [x] **Indirect-PPE** — `CAM-PPE-002` (GitHub) + `CAM-GL-INJ-002` (GitLab):
  untrusted input that is env-routed (GitHub) or auto-exported (`$CI_*`, GitLab)
  but then used unsafely (unquoted / `eval` / `$(…)` / backtick) **inside a local
  file the pipeline executes** — shell script, `Makefile` recipe, or
  `package.json` script. Resolves the repo root from the pipeline path, reads the
  referenced file from disk, and emits nothing when the file is absent (no
  speculative FPs). Both confirmable; reuse the injection PoC generator. Zero-dep.
- [x] **Structural YAML (`-tags yaml`)** — opt-in `gopkg.in/yaml.v3` engine,
  isolated behind the build tag like the cloud SDKs; resolves anchors/aliases and
  flow forms for the indirect rules (catches alias-supplied untrusted env the
  line model cannot connect). Stub under the default build; identical detection
  otherwise. Build-tagged tests pin line-model-misses vs structural-catches.

### Acceptance
`scan` flags an unquoted untrusted var in an executed script (and stays silent on
the quoted-safe form); default build links **0** YAML packages, `-tags yaml`
links yaml.v3; `go test` / `-tags yaml` / `-tags cloud` all green; dogfood
self-scan still clean.

## M4 → distribution (in progress)

Getting Caminus into others' hands.
- [x] **Packaging** — GoReleaser publishes a Homebrew **cask** (`Su1ph3r/homebrew-tap`)
  and a Scoop manifest (`Su1ph3r/scoop-bucket`) alongside the cross-platform
  archives, gated by `SKIP_PKG_PUBLISH` so releases work before the tap/bucket +
  `TAP_GITHUB_TOKEN` exist (`RELEASING.md`). Pre-hook changed `go mod tidy` →
  `go mod download` so the build-tag-only deps are not pruned. **Migrated the
  deprecated `brews:` formula block to `homebrew_casks:`** (GoReleaser deprecated
  formula generation; cask drops `install:`/`test:`, adds a Gatekeeper-quarantine
  postflight hook for the unsigned binary). **Verified 2026-06-03:** `goreleaser
  check` is clean, and `goreleaser release --snapshot --clean` builds all 6
  os/arch binaries, archives, `checksums.txt`, a well-formed cask
  (`dist/homebrew/Casks/caminus.rb`, sha256s matching checksums), and the Scoop
  manifest; the built binary reports its ldflags version.
- [x] **GitHub Action** — Docker action (`action.yml` + `Dockerfile` +
  `entrypoint.sh`) runs `caminus scan` in CI with path/platform/format/
  min-severity/gate/output inputs and propagates the gate exit code; the
  Dockerfile is also a general-purpose Caminus image.
- **Dropped (indefinitely):** Vinculum + Ariadne export. Re-open if the toolsuite
  integration becomes a priority.

### Acceptance
- [x] `goreleaser check` passes (clean, no deprecations — 2026-06-03).
- [x] Snapshot release builds archives + `checksums.txt` + cask + scoop manifest
  (proven via `goreleaser release --snapshot --clean`, 2026-06-03).
- [x] Docker action scans a repo and fails the step on a high/critical finding
  (verified via the built image, 2026-06-03): vuln fixture → 6 findings, gate
  `high` → **exit 1** (step fails); safe fixture → exit 0; `gate: none` reports
  but does not fail; hyphenated inputs (`INPUT_MIN-SEVERITY`) and SARIF-to-file
  (`INPUT_OUTPUT`) both work; the default entrypoint runs as a general CLI image.
- [ ] A real tagged release publishes the archives/checksums to GitHub, and the
  brew/scoop taps once `TAP_GITHUB_TOKEN` + the tap/bucket repos exist — **pending
  external setup** (see `RELEASING.md`).
