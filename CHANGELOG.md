# Changelog

All notable changes to Caminus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — M6: precision/recall benchmark
- **`benchmark/` — a labeled corpus + reproducible scorer.** 21 self-contained
  mini-repo cases (`gen_corpus.sh` regenerates them) with ground truth in
  `manifest.jsonl`: 12 covered-vuln, 6 safe/near-miss, 3 known-gap. The scorer
  (`benchmark_test.go`, run by `go test ./...`) builds the real binary, scans
  each case, and scores **per rule class** (a privileged-trigger `CAM-PPE-001` on
  a safe file is a true positive, not noise, so scoring is class-scoped via
  `expect`/`forbid`). It fails the build on any false negative, any false positive
  on a near-miss, or a `known_gap` that becomes detected. Baseline 2026-06-03:
  precision 100%, recall 100% over covered classes, 0 FP on the 6 near-miss
  cases. The 3 honest coverage gaps (github-script `script:` injection, nested
  composite actions, local JS actions) are documented and tested as the frontier.
  Now a CI regression gate. **Cross-tool comparison: `poutine` measured** on the
  same corpus (Linux/WSL — its analyzer needs a real git repo and does not load
  under Windows go-git): poutine detects 4/12 covered classes with 0 FP and
  catches one of Caminus's three documented gaps (`gap-github-script`), confirming
  the corpus is not rigged. Caminus's edge is dataflow depth (env-routed /
  indirect / reusable-workflow / composite-action injection, GitLab injection,
  plain unpinned tags); the tools are complementary. Harness
  (`compare_poutine.sh`, `score_comparison.py`) + raw results
  (`results-poutine.jsonl`) committed; `raven`/`gato-x`/`octoscan` status recorded
  honestly in `COMPARISON.md`. The corpus is Caminus-class-shaped (stated up
  front) — a coverage comparison, not an unbiased ranking.

### Added — M5 tail: callee env-routing + remote reusable-ref supply-chain
- **Callee-side env-routing for `CAM-PPE-003` / `CAM-PPE-004`.** The reusable-
  workflow and composite-action injection rules now also catch the second hop: a
  tainted input the called code routes through an `env:` variable
  (`env: T: ${{ inputs.title }}`) and then uses unquoted / via `eval` /
  command-substitution in a `run:` — not just the direct `${{ inputs.X }}`
  interpolation. Quoted `"$T"` stays safe (recommended form). Reuses the
  CAM-INJ-002 shell-quote analyzer; the run-segment grouping is factored out of
  `InlineEnvInjection` and shared.
- **`CAM-SUP-002` — unpinned/mutable remote reusable workflow.** A remote
  `jobs.<id>.uses: owner/repo/.github/workflows/wf.yml@<mutable-ref>` runs as a
  whole job with the caller's permissions and is often called with `secrets:
  inherit`; an upstream owner (or tag/branch repointer) can poison the pipeline
  and exfiltrate secrets. Medium for a mutable ref, **High** with `secrets:
  inherit`. `CAM-SUP-001` now routes `.yml`/`.yaml` refs to this rule (no
  double-report); step actions remain `CAM-SUP-001`. Caminus cannot read the
  remote workflow, so this surfaces the exposure the dataflow rule can't.

### Added — composite-action injection (M5, `CAM-PPE-004`)
- **Cross-call-boundary expression injection through local composite actions.**
  The step-level sibling of `CAM-PPE-003`: a workflow step on an attacker-
  influenced trigger invokes a local composite action by directory
  (`steps[].uses: ./.github/actions/foo`) and passes it an untrusted expression
  via `with:`, where the action manifest (`foo/action.yml`, `runs.using:
  composite`) interpolates `${{ inputs.<name> }}` into one of its own `run:`
  steps. Uses dash-aware step-boundary parsing (a `keyColumn` normalization that
  aligns `- name:` / `uses:` / `with:` regardless of which key carries the list
  dash) so the matching `with:` is scoped to exactly the one step item — verified
  against dash-on-uses, dash-on-name, and adjacent-sibling-step layouts. Tries
  `action.yml` then `action.yaml`; `.yml` targets are routed to the reusable-
  workflow rule; remote `owner/repo@ref` actions are out of scope. Same
  absent→silent / unreadable→UNASSESSED discipline. Confirmable.

### Added — reusable-workflow injection (M5, `CAM-PPE-003`)
- **Cross-call-boundary expression injection through local reusable workflows.**
  A caller on an attacker-influenced trigger that passes an untrusted expression
  (`with: title: ${{ github.event.pull_request.title }}`) into a local reusable
  workflow (`jobs.<id>.uses: ./.github/workflows/wf.yml`), where the called
  workflow then interpolates `${{ inputs.<name> }}` directly into a `run:` shell.
  The sink lives in a *different file* the caller hands execution to — invisible
  to a scan of either file alone. Extends the CAM-PPE-002 file-hop model across
  the call boundary, reusing the repo-root resolution, symlink-confined read, and
  precision discipline: a remote `org/repo@ref` is out of scope (another repo,
  unreadable — supply-chain's concern); an absent callee is silent (no
  speculative FP); a present-but-unreadable callee is surfaced as UNASSESSED
  (Info, below the default gate). Parses both block and flow-mapping `with:`
  forms; gated on an attacker-influenced trigger so a static `with:` value never
  flags. Confirmable; maps to the injection PoC generator. First increment of M5
  (reusable workflows & composite actions) — composite actions and callee-side
  env-routing follow.

### Fixed — packaging
- **Migrated the deprecated GoReleaser `brews:` formula block to
  `homebrew_casks:`.** GoReleaser deprecated formula generation in favor of
  casks; `goreleaser check` failed with a deprecation error. The cask drops the
  formula-only `install:`/`test:` stanzas (a binary cask installs the artifact
  directly) and adds a `postflight` hook that strips the macOS quarantine xattr
  so Gatekeeper does not block the unsigned binary. Tap repo, `TAP_GITHUB_TOKEN`,
  and `SKIP_PKG_PUBLISH` gating are unchanged. Verified with `goreleaser check`
  (clean) and `goreleaser release --snapshot --clean` (archives + `checksums.txt`
  + cask + scoop manifest all generated, sha256s consistent).

## [0.6.0] — 2026-06-03

Milestones **M3.5 and M4 complete**: indirect Poisoned Pipeline Execution
detection, an opt-in structural-YAML engine, the inline env-routed injection
rule, and distribution (packaging + a GitHub Action).

### Added — distribution (M4, packaging + GitHub Action)
- **Homebrew + Scoop** via GoReleaser (`brews:` / `scoops:`), publishing to
  `Su1ph3r/homebrew-tap` and `Su1ph3r/scoop-bucket`. Gated by `SKIP_PKG_PUBLISH`
  so binary releases succeed before the tap/bucket and `TAP_GITHUB_TOKEN` secret
  are set up (see `RELEASING.md`).
- **GitHub Action** (`action.yml` + `Dockerfile` + `entrypoint.sh`): a Docker
  action that runs `caminus scan` in CI with inputs for path/platform/format/
  min-severity/gate/output, builds the image from source at the pinned ref, and
  propagates the gate exit code. The `Dockerfile` doubles as a general-purpose
  Caminus container image.
- **GoReleaser hardening:** replaced the `go mod tidy` pre-hook with
  `go mod download` — `tidy` runs with default build tags and would prune the
  build-tag-only dependencies (`yaml.v3`, cloud SDKs) from `go.mod`.

### Added — env-routed inline injection (`CAM-INJ-002`)
- The same-step completion of the injection family: an attacker-controllable
  value routed through an `env:` variable (the form `CAM-INJ-001` treats as safe)
  but then used **unquoted** — or via `eval`/command-substitution — directly in a
  `run:` shell. `CAM-INJ-001` fires only on the literal `${{ github.event.* }}`
  form and the indirect rules only on referenced files, so this env-routed-but-
  unquoted inline case previously fell between them. Reuses the trigger gate,
  untrusted-env source collection, and shell-quote analyzer (so `"$VAR"` stays
  safe); confirmable, mapped to the injection PoC generator. The two injection
  rules are disjoint — `CAM-INJ-002` never double-reports the literal form.

### Added — indirect-PPE detection (default build, zero new deps)
- `CAM-PPE-002` (GitHub Actions) and `CAM-GL-INJ-002` (GitLab CI): an attacker-
  controllable value that is routed through an `env:` variable (GitHub) or
  auto-exported as `$CI_*` (GitLab) — the form the direct-injection rules treat
  as safe — but then reaches a shell **inside a local file the pipeline
  executes** (a shell script, a `Makefile` recipe, or a `package.json` script),
  used unquoted or via `eval`/command-substitution. This closes the dataflow gap
  `CAM-INJ-001` documented as a later milestone, one file-hop out.
- `internal/rules/indirect.go`: follows `run:`/`script:` invocations to on-disk
  files (interpreter + path, `./script`, `make` → `Makefile`, `npm/yarn/pnpm` →
  `package.json`), resolves the repo root from the pipeline path, and runs a
  precise shell-quote analyzer (unquoted / `eval` / `$(…)` / backtick = unsafe;
  `"$VAR"` and `'$VAR'` = safe). A referenced file that is absent on disk yields
  **no finding** — no speculative false positives. Both rules are `confirmable`
  and reuse the injection PoC generator.

### Added — structural YAML engine (`-tags yaml`, optional)
- `internal/rules/structural.go` (+ `structural_stub.go` for the default build):
  an opt-in parser using `gopkg.in/yaml.v3`, isolated behind the `yaml` build tag
  exactly like the cloud SDKs, so the default binary stays dependency-free. It
  resolves YAML anchors/aliases and flow forms for the indirect rules — e.g. an
  `env:` value supplied through an alias whose anchored source is the untrusted
  expression, which the line model cannot connect. Behavior is otherwise
  identical; build-tagged tests pin both the line-model limitation and the
  structural recall win.
- CI builds/tests both configurations (`go test -tags yaml ./...`).

### Hardened — finalize review (security / quality / silent-failure / breaking-change)
- **Symlink escape (blocker):** following a referenced script could read a file
  outside the scanned repo (a malicious pipeline symlinking a "script" to
  `/etc/passwd`). The referenced-file read now resolves the real path
  (`EvalSymlinks`) and re-confines it within the symlink-resolved repo root, and
  ignores non-regular files — so the scanner never reads outside the tree.
- **No silent "clean" on unanalyzable files:** a referenced, pipeline-executed
  file that is *present but unreadable or unparseable* (permissions, encoding,
  malformed `package.json`) is now surfaced as an **Info "UNASSESSED" finding**
  rather than scored clean. Info ranks below the default `--gate high`, so it
  never breaks an existing CI gate, and is non-confirmable so it never reaches
  the exploit stage. An *absent* file still yields nothing (no speculation).
- **Precision (false-positive fixes):** `make`/`npm` analysis is now scoped to
  the invoked target — `make build` no longer flags an unsafe recipe in an
  unrelated `release:` target, and `npm ci` analyzes only install-lifecycle
  scripts, not an unused `deploy` script. The shell-quote analyzer handles
  backslash escaping (`echo "\"$X\""` is no longer mis-flagged), folds backslash
  line-continuations, and skips heredoc bodies (data, not command positions).
  `bash -c '<inline>'` is no longer mistaken for a file reference; single-line
  flow-form `env: { … }` is parsed by the line model.
- **Resource bound:** referenced (attacker-named) files are read with a 5 MiB cap.

## [0.5.0] — 2026-06-01

Milestone **M3 complete**: dynamic confirmation end to end — live, reversible
arming for the generated PoCs, and GitLab→cloud OIDC blast-radius so the
confirmation works for GitLab graphs too.

### Added — live arming (`exploit --arm --i-own-target`)
- `internal/exploit/arm.go` + `arm_platforms.go`: a self-contained, write-capable
  GitHub/GitLab client that delivers a workflow-file PoC to a fresh branch on a
  target you own, lets the pushed branch trigger the pipeline, polls the run to
  completion, fetches the job logs, and confirms the **benign canary** — then
  deletes the branch.
- **Reversible by construction:** cleanup is deferred and runs on every exit path
  (success, failure, or canary-absent); `--keep` opts out for debugging; a
  non-cleaned branch is reported with a warning. The token is attached only to
  the configured host. Only the workflow-delivering PoCs (OIDC, runner) are
  auto-armed; injection/pwn-request fall back to the printed manual playbook.
- New flags: `--token` (or `CAMINUS_TOKEN`), `--arm-base-url`, `--keep`. The
  orchestration is exercised by scripted-transport tests (built blind; not run
  against a live target by the suite).

### Hardened — finalize review + multi-agent bug hunt
Pre-release review of the M3 changes (a security/quality finalize pass and a
full-codebase multi-agent bug hunt) fixed:
- **Token leak (blocker):** the live-arming write client followed redirects with
  no guard; it now strips both `Authorization` and `PRIVATE-TOKEN` on any host
  change while still following the redirect (GitHub job-logs 302 to credential-
  less blob storage). Go strips neither across subdomains, and never strips
  `PRIVATE-TOKEN`.
- **Inverted confirmation signal:** unreadable run logs were reported as a clean
  "not proved"; a run that did not succeed was reported as a clean negative.
  Both are now surfaced as errors / INCONCLUSIVE, and a left-behind PoC branch is
  promoted to a returned error and a non-zero exit.
- **Detection accuracy:** CAM-INJ-001 now detects untrusted expressions inside the
  common `- run: |` list-item block scalar (previously missed); CAM-GL-INJ-001 no
  longer false-positives on `script:` appearing inside a quoted value.
- **Robustness:** a JSON-null node in a hand-edited `graph.json` no longer panics
  the graph/cloud/exploit stages; finding evidence truncates on a UTF-8 rune
  boundary; a corrupt default `graph.json` is fatal rather than silently skipped;
  a failed `--record` cassette save now exits non-zero; `scan` warns on UNASSESSED
  files (opt-in `--fail-on-incomplete`, default exit unchanged).
- **Hardening:** cloud/graph-derived values are collapsed to one line before
  interpolation into generated PoC YAML (no step injection under `--arm`); GitHub
  API path segments are URL-escaped (parity with GitLab/arm); artifact output dirs
  assert containment under the output root.

### Added — GitLab→cloud OIDC matching
- The cloud trust model now carries the CI **issuer**; the AWS trust-policy parser
  recognizes GitLab-issuer federations (dynamic `<issuer>:sub` keys) alongside
  GitHub, and GCP/Azure readers accept GitLab providers/credentials too.
- Subject classification is grammar-agnostic (`repo:` and GitLab `project_path:`),
  and `cloud` enrichment summarizes GitLab projects + builds GitLab candidate
  subjects, so `CAM-OIDC-002` now fires for GitLab graphs. Trust↔repo matching is
  gated by source platform (a GitHub federation can't match a GitLab project, and
  vice versa — important for no-subject-condition trusts).

## [0.4.0] — 2026-06-01

Milestone **M3 (generate stage)**: the `exploit` command turns confirmable
findings into concrete, non-destructive proof-of-concept artifacts — the property
that separates Caminus from static-only scanners.

### Added — `caminus exploit`
- New `internal/exploit` package + wired `exploit` command. For each *confirmable*
  finding (from a trust graph `-i` and/or a `scan --format json` report `--scan`)
  it generates the concrete attack artifact carrying a benign canary, plus a
  reversible **Deliver / Evidence / Cleanup** plan (written as `PLAN.md` beside
  the artifact files, or to stdout with `-o -`).
- Generators for four confirmable families:
  - **Injection** (`CAM-INJ-001`, `CAM-GL-INJ-001`) — the attacker-controlled
    input (`$(echo <canary>)`) the vulnerable pipeline runs as a shell command.
  - **Pwn-request** (`CAM-PPE-001`) — a fork-PR step that proves a secret is *in
    scope* by reporting its presence and length only, never its value.
  - **Self-hosted runner** (`CAM-RUN-001`, `CAM-GL-RUN-001`) — a job that prints
    the runner host's identity, proving code execution on the self-hosted host.
  - **OIDC→cloud** (`CAM-OIDC-002`) — a provider-aware (AWS / GCP / Azure),
    platform-aware (GitHub / GitLab) pipeline that mints the OIDC token, assumes
    the cloud identity, and makes a single **read-only** identity call
    (`sts get-caller-identity` / `gcloud auth list` / `az account show`).
- **Escalation-restraint by design:** generation-only — it performs no live
  mutation. Canaries are benign, cloud proofs are read-only, secret *values* are
  never exfiltrated, and every plan ships teardown steps. `--arm` is gated on
  `--i-own-target` and prints the reversible operator playbook rather than
  executing it. Live API-driven delivery is a later increment behind this seam.
- Canaries are derived deterministically (rule + target) so artifacts are stable
  and diffable.

### Not yet (tracked for M3 continuation)
- Live API-driven arming (create branch → run → capture canary → auto-cleanup).
- GitLab→cloud OIDC subject matching in `cloud` (currently GitHub subjects only).

## [0.3.0] — 2026-06-01

Milestone **M2.5**: multi-platform enumeration and multi-cloud blast radius. The
trust graph now crosses GitLab as well as GitHub, and the OIDC→cloud resolver
covers AWS, GCP, and Azure.

### Added — GitLab enumeration (`enum --platform gitlab`)
- New `internal/platform/gitlab`: a zero-dependency, read-only GitLab REST (v4)
  client and enumerator that mirrors the GitHub one. It walks a group (or a
  single project) into the trust graph — projects, the `.gitlab-ci.yml` pipeline
  (parsed and run through the existing GitLab rule set to mark **entry points**),
  instance/group/project **runners**, project + group **CI/CD variables**, and
  **`id_tokens:` OIDC** usage with the instance issuer and representative subject.
- Same defenses as the GitHub client: the token (PRIVATE-TOKEN) is attached only
  to the configured host, RFC 5988 pagination is followed, off-host next/redirect
  URLs are refused, and transport failures mark nodes `enum_incomplete`.
- Self-managed GitLab is supported via `--base-url` (host root or `…/api/v4`).
- The `graph` stage synthesizes ranked attack paths over GitLab graphs unchanged
  (pipeline → project → runner / variable / OIDC), MITRE-tagged.

### Added — GCP & Azure cloud read (`cloud --provider gcp|azure`)
- `--provider` selects the cloud to resolve (default `aws`); `--project` supplies
  the GCP project id.
- **GCP** (`internal/cloud/gcp.go`, `-tags cloud`): reads Workload Identity
  Federation via the IAM API — finds pools whose provider trusts the GitHub
  issuer, then maps each service account's `workloadIdentityUser` /
  `serviceAccountTokenCreator` bindings (`attribute.repository`,
  `attribute.repository_owner`, `subject`, whole-pool) to the GitHub subjects
  they admit. The member parser (`gcp_member.go`) is pure, always-compiled, and
  unit-tested; unmappable custom attributes are logged and skipped (no guessing).
- **Azure** (`internal/cloud/azure.go`, `-tags cloud`): reads Entra app-
  registration federated identity credentials via Microsoft Graph (azcore +
  azidentity), keeping those whose issuer is the GitHub Actions issuer and mapping
  the FIC subject directly.
- The trust model is now provider-neutral (`GitHubTrust.Provider`); CAM-OIDC-002
  text adapts per cloud (AWS role / GCP service account / Azure app registration,
  with the right credential-exchange call).
- Record/replay cassettes drive the **real** GCP and Azure SDKs in CI with no
  cloud account, matching the existing AWS harness.

### Dependency containment
- The default build still links **zero** cloud SDKs (`scan`/`enum`/`graph` and
  the GitLab client are stdlib-only). GCP and Azure SDKs are isolated behind
  `-tags cloud` alongside AWS; the un-tagged `cloud` command degrades to a
  rebuild hint.

## [0.2.0] — 2026-06-01

First tagged release. Adds the full M2 capability set on top of the M1 static
scanner: GitLab CI rules, authenticated GitHub enumeration, ranked attack-path
synthesis, and the AWS OIDC→cloud blast radius. Hardened by a finalize review
and two multi-agent bug-hunt passes.

### Fixed — full-codebase bug hunt
False-negatives and a credential-leak vector found by a `--full` multi-agent hunt
over the v0.1 scan engine (which earlier diff-scoped reviews had not covered):
- **Detection blind spots (HIGH):** a quoted top-level `"on":` key, and a leading
  UTF-8 BOM, each made the workflow trigger parser return nothing — silently
  disabling pwn-request, self-hosted-runner-escalation, and entry-point detection
  on common YAML idioms. Both parsers now tolerate quoted keys and strip a BOM.
- **Token exfiltration / SSRF (HIGH):** the GitHub client followed `Link:
  rel="next"` URLs verbatim and attached the PAT to any host. The token is now
  sent only to the configured API host, off-host pagination is refused, and the
  HTTP client rejects cross-host redirects.
- **Silent incompleteness (HIGH):** `scan` swallowed directory-walk errors
  (unreadable dir → "clean") — now warned; `enum` collapsed transport failures
  into "resource absent" — now marks the node `enum_incomplete` and warns.
- **False positives / robustness (MED):** `run:` inside a quoted value no longer
  triggers a CRITICAL injection finding; a GitLab `project:` include's `ref:` is
  read regardless of key order (and `file:` is no longer counted as a separate
  include); `vcr` record fails loudly on a truncated body instead of persisting it.
- Added the previously-missing `workflow`, `gitlabci`, `vcr`, and `client` test
  files covering all of the above.

### Fixed — bug-hunt review
- **Crash fix:** `caminus graph` panicked (nil-pointer deref in `stepFor`) when a
  `graph.json` contained an edge to a node absent from `nodes` (a dangling
  intermediate hop, e.g. a hand-edited or truncated file). The nil guard now
  precedes the dereference.
- `nextLink` parses the Link header's angle-bracketed URLs instead of splitting
  on raw commas, so a paginated `next` URL containing a literal comma in its
  query is no longer truncated.
- `vcr` replay reads the cassette under the same mutex as record, making the
  transport honestly safe under the concurrent-RoundTrip contract.

### Fixed — finalize review
- **`graph` now surfaces enumeration findings.** It previously synthesized
  attack paths but silently dropped `CAM-OIDC-001/002` from both text and JSON
  output — the stage documented as the consolidated attacker view hid the
  highest-value OIDC→cloud findings. JSON output is now `{ "paths": …,
  "findings": … }`; both honor `--min-severity`.
- **Cloud trust matching probes enumerated environments**, not just a hardcoded
  `production`, so a role scoped to e.g. `:environment:staging` is no longer a
  silent false negative.
- **Unreadable workflow content is marked UNASSESSED, not benign.** When the
  token cannot fetch a workflow's YAML, the pipeline node now records
  `content_unavailable` and `enum` warns with a count, instead of silently
  treating it as having no risky triggers. The base64 decode failure path is
  now logged.
- **Malformed IAM trust conditions fail loudly.** A present-but-unparsable
  `:sub`/`:aud` now errors (and the role is skipped with a logged reason in the
  cloud build) instead of being misclassified as "no subject condition" — the
  most permissive class.
- Compiled glob regexes are cached (was recompiling per subject in the
  trusts×repos×patterns×subjects hot loop).
- `graph.json` and recorded cassettes are written `0o600` (recon artifacts).
- `graph --cloud` retained as a deprecated, ignored flag (no CLI break).

### Changed — M2 finalization
- `enum` now paginates runner and secret listings (Link header) instead of
  reading only the first page, and enumerates deployment **environments** with
  their protection rules (recorded on the repo node).
- Rate limiting is reported clearly (403 with `X-RateLimit-Remaining: 0`).
- Removed the stale `graph --cloud` placeholder flag; cloud enrichment is the
  `cloud` subcommand.

### Added — M2 Task 5
- **Record/replay for the cloud path.** `internal/vcr` now matches on a request
  body discriminator (AWS IAM is query-protocol — every call is `POST /` with
  the action in the body). `caminus cloud` gained `--record`/`--replay`, and the
  AWS SDK accepts an injected transport with anonymous credentials. A recorded
  IAM `ListRoles` fixture drives the real SDK deserializer in a cloud-tagged
  test, so the OIDC→cloud logic is CI-tested without an AWS account. CI runs the
  `-tags cloud` build and tests.

### Added — M2 Task 4
- **`cloud` — OIDC→cloud blast radius (AWS).** `internal/cloud` parses IAM role
  trust policies that federate to GitHub Actions OIDC, classifies their
  permissiveness (scoped / ref-wildcard / repo-wildcard / no-subject), and
  matches their `sub` conditions against enumerated CI subjects to add
  CloudRole nodes + can-assume edges — completing the CI → OIDC → cloud-role
  attack path. Where an attacker-controllable pipeline can assume a permissive
  role it emits **`CAM-OIDC-002`** (High, Critical for repo-wildcard trust).
- The trust-policy parser and subject matcher are dependency-free and unit
  tested; the AWS SDK (iam:ListRoles) is isolated behind the **`cloud` build
  tag**. The default binary links no third-party packages; `caminus cloud`
  without the tag degrades to a rebuild hint.

### Added — M2 Task 3
- **OIDC subject modeling + `CAM-OIDC-001`.** `enum` computes each repo's
  effective OIDC subject from its claim customization and flags repo-wide
  subjects (no ref/environment scoping) as over-broad federation — a token any
  workflow run, including a fork-influenced one, can present. Recorded on the
  OIDC node and emitted as a graph finding; over-broad OIDC nodes rank higher in
  attack-path synthesis.

### Added — M2 Task 2
- **`graph` — ranked attack-path synthesis.** `internal/graph` walks the trust
  graph from attacker-controllable entry points (poisonable pipelines) to
  high-value sinks (self-hosted runners, secrets, OIDC federation), ranks the
  paths, and tags each step with a MITRE ATT&CK technique. `graph` loads a
  `graph.json` from `enum`, optionally merges a `scan` report to mark entry
  points, and emits text or JSON.

### Added — M2 Task 1
- **`enum` — read-only GitHub enumeration into the trust graph.** Stdlib HTTP
  client (`internal/platform/github`) enumerates repos, workflows (run through
  the static rules to mark *entry points*), self-hosted runners, secret names
  (repo + org), OIDC subject claims, and default-branch protection, emitting a
  `graph.json`.
- **Record/replay transport** (`internal/vcr`) with `--record`/`--replay` so
  enumeration is testable without a live token (à la Vercelsior).

### Added — v0.1.0 (Sprint 1)
- **GitLab CI support.** New `internal/gitlabci` parser and five rules at taxonomy
  parity with the GitHub set:
  - `CAM-GL-INJ-001` (Critical) — untrusted `$CI_*` variable interpolated into a
    `script:` block.
  - `CAM-GL-PPE-001` (Medium) — merge-request pipeline secret/`CI_JOB_TOKEN`
    exposure (framed honestly for GitLab's protect-by-default model).
  - `CAM-GL-DBG-001` (High) — `CI_DEBUG_TRACE`/`CI_DEBUG_SERVICES` leaking secrets
    to job logs.
  - `CAM-GL-RUN-001` (High/Med) — privileged Docker-in-Docker build.
  - `CAM-GL-SUP-001` (Low) — `include: remote:` / unpinned cross-project include.
- **Per-file platform detection** with `--platform auto|github|gitlab` override;
  `scan` discovery now finds both `.github/workflows/**` and `.gitlab-ci.yml`.
- **SARIF 2.1.0 output** (`--format sarif`) for code scanning and CI gating.
- Self-scanning CI workflow (dogfood) and GoReleaser release pipeline.

## [0.1.0-dev] — M1

### Added
- GitHub Actions static engine with five rules (`CAM-INJ/PPE/RUN/PERM/SUP-001`).
- `scan` subcommand: text + JSON output, `--min-severity`, `--gate`.
- Scaffolded `enum` / `graph` / `exploit` stages with stable interfaces.
- Zero-dependency, single-binary build (Linux/macOS/Windows).
