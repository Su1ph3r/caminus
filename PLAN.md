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

## Next milestones (post-v0.1)
- **M1.5:** indirect-PPE, structural YAML, Vinculum parser + Ariadne export.
- **M2:** authenticated `enum` + trust-graph + OIDC→cloud blast-radius (Nubicustos).
- **M3:** `exploit` — authorization-gated dynamic confirmation.
