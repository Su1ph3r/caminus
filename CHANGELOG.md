# Changelog

All notable changes to Caminus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

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
