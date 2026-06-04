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

## M5 → reusable workflows & composite actions (depth — in progress)

Follow the indirect-PPE dataflow across GitHub-native code-reuse boundaries — a
known blind spot for many scanners — propagating the *caller's* trigger context.
Same precision discipline as CAM-PPE-002 (absent target → silence; present-but-
unreadable → UNASSESSED; symlink-confined read).

- [x] **Local reusable-workflow injection** (`CAM-PPE-003`). Untrusted expression
  passed via `with:` into `jobs.<id>.uses: ./.github/workflows/wf.yml`, then
  interpolated as `${{ inputs.<name> }}` into a called `run:`. Block + flow `with:`
  forms; trigger-gated; remote `org/repo@ref` out of scope; absent → silent;
  unreadable → UNASSESSED. 8 unit tests + on-disk fixture
  (`testdata/reusable-vuln/`) scanned end-to-end via the CLI. Dogfood clean.
- [x] **Local composite-action injection** (`CAM-PPE-004`). `steps[].uses: ./dir`
  → `dir/action.yml`|`.yaml` with `runs.using: composite`; map the step's `with:`
  untrusted values to `inputs.<name>`; flag `${{ inputs.<name> }}` in the
  composite's `run:` steps. Dash-aware step-boundary parsing (keyColumn
  normalization) so the matching `with:` is scoped to the one step item
  regardless of which key carries the `- `; `.yml` targets routed to CAM-PPE-003,
  remote `@ref` out of scope. 8 unit tests (dash-on-uses, dash-on-name, sibling-
  step isolation, .yaml manifest, absent→silent) + on-disk fixture
  (`testdata/composite-vuln/`) scanned E2E. Dogfood clean.
- [x] **Unpinned/mutable remote reusable workflow** (`CAM-SUP-002`). Remote
  `jobs.<id>.uses: owner/repo/.github/workflows/wf.yml@<mutable>` — contents
  unreadable (CAM-PPE-003 stays silent), so this surfaces the supply-chain
  exposure: Medium for a mutable ref, **High** when the job passes `secrets:
  inherit` (poisoned upstream also gets all caller secrets). CAM-SUP-001 now
  routes `.yml`/`.yaml` refs here (no double-report); step actions stay in
  CAM-SUP-001. 5 unit tests incl. the no-double-report and pinned-is-safe cases.
- [x] **Callee-side env-routing** (second hop). `env: X: ${{ inputs.<tainted> }}`
  then `$X` used unquoted / eval / `$(…)` inside the called workflow or composite
  manifest — extends CAM-PPE-003/004 beyond the direct `${{ inputs.X }}` sink,
  reusing the CAM-INJ-002 quote analyzer. Quoted `"$X"` stays safe. Shared run-
  segment grouping factored out of InlineEnvInjection (no regression).

### Acceptance — met 2026-06-03
`scan` flags a tainted input that reaches a `run:` across a reusable-workflow /
composite-action boundary (direct AND env-routed), stays silent on the safe-
input / static-value / quoted forms, never resolves a remote ref as a local
file, and reports a remote mutable-ref reusable workflow as CAM-SUP-002 without
double-reporting it as CAM-SUP-001; `go test` / `-tags yaml` / `-tags cloud` /
`go vet` all green; dogfood self-scan still clean.

**Remaining M5 (optional polish):** GitLab `include:` / `trigger:` child-pipeline
dataflow parity; nested composite→composite hop. Deferred — the GitHub reuse
surface (the headline blind spot) is covered.

## M6 → benchmark & precision (credibility — in progress)

The artifact that lets Caminus *claim* de-facto status rather than assert it.
- [x] **Labeled corpus + scorer** (`benchmark/`). 21 cases (12 covered-vuln, 6
  safe/near-miss, 3 known-gap), ground truth in `manifest.jsonl`, regenerated by
  `gen_corpus.sh`. `benchmark_test.go` builds the real binary, scans each case,
  scores **per rule class** (`expect`/`forbid`), and is wired into `go test ./...`
  as a CI regression gate. Baseline: precision 100%, recall 100% over covered
  classes, 0 FP on the 6 near-miss cases; 3 honest gaps documented + tested.
- [x] **Cross-tool comparison** (`COMPARISON.md`). Two tools measured 2026-06-03:
  - **poutine** (Linux/WSL): 4/12 covered classes, 0 FP, catches 1 gap
    (`gap-github-script`).
  - **octoscan** (Synacktiv, Go, GitHub-only): 4/10 covered GitHub classes (GitLab
    N/A), **1 FP** (precision 80%), catches all 3 gaps via a coarse input-side
    heuristic — the same coarseness that causes the FP on `safe-composite-
    safeinput`. A measured precision/recall tradeoff: Caminus traces dataflow to
    the sink (0 FP, misses the 3 unmodeled-sink gaps); octoscan flags input-side
    (catches the gaps, 1 FP).
  - Harnesses (`compare_poutine.sh`, `compare_octoscan.sh`, `score_comparison.py`)
    + raw results (`results-{poutine,octoscan}.jsonl`) committed. `raven` (Neo4j/
    Redis) and `gato-x` (online/token) not suited to an offline tree — documented,
    not estimated. Corpus is Caminus-class-shaped (stated up front) — a coverage
    comparison, not a ranking. **Actionable: the 3 gaps are candidates for an
    UNASSESSED-style "untrusted input crosses into an unresolvable action sink"
    rule that keeps precision while closing the recall gap.**

### Acceptance — met 2026-06-03
`go test ./benchmark/` prints the scorecard and fails on any FN / near-miss FP /
newly-covered gap; `COMPARISON.md` carries real measured columns for poutine and
octoscan, and an honest "not run here" for raven/gato-x.

## M7 → adoption (publish) — done 2026-06-03

- [x] **Released v0.7.0** (GoReleaser: 6 os/arch archives + `checksums.txt`,
  "Latest"); **v0.7.1** adds the gap-closing rules + the GHCR image.
- [x] **`v0` floating major tag** → the release commit (has `action.yml`, so
  `Su1ph3r/caminus@v0` resolves). Release trigger restricted to `v[0-9]+.…` so
  moving `v0`/`v1` does not re-trigger GoReleaser.
- [x] **SARIF→code-scanning demo** = the README "Use in CI" section
  (`github/codeql-action/upload-sarif`).
- [x] **Container image** to `ghcr.io/su1ph3r/caminus` (multi-arch, SHA-pinned
  Docker actions) — the tap-free universal install (v0.7.1).
- [ ] **Marketplace publish** — a one-time repo-owner UI checkbox on the release +
  Developer Agreement; not API-toggleable. Steps in `RELEASING.md`. (User to do.)

## M7.5 → close the benchmark frontier — done 2026-06-03 (v0.7.1)

- [x] **`CAM-INJ-003`** — actions/github-script `script:` injection (confident).
- [x] **`CAM-PPE-005`** — untrusted input into an action whose sink Caminus can't
  resolve (non-composite JS/Docker, or a forwarding composite) → Info/UNASSESSED;
  silent on the resolvable-safe composite (0 FP). Closes the 3 M6 gaps; Caminus
  now 15/15 covered at 100% precision. New honest gap: `$GITHUB_ENV` cross-step
  laundering (missed by all three tools).

## Post-1.0 backlog
- 3rd CI platform (CircleCI / Azure Pipelines / Jenkinsfile / Bitbucket).
- `$GITHUB_ENV` / `$GITHUB_OUTPUT` / `${{ steps.*.outputs.* }}` cross-step taint.
- Nested-composite/reusable N-hop resolution; raven/gato-x comparison harness.
