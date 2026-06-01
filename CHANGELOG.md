# Changelog

All notable changes to Caminus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
