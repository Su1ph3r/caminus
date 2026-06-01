# Changelog

All notable changes to Caminus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
