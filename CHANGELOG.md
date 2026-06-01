# Changelog

All notable changes to Caminus are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
