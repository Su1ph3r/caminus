# Caminus

**Multi-platform CI/CD pipeline attack framework.**

Caminus maps a pipeline compromise as a trust graph — from an attacker-controllable
trigger to its blast radius (secrets, self-hosted runners, and, via OIDC, cloud
roles and the resources behind them) — and is built to dynamically confirm the
primitives it finds, not just flag YAML patterns.

*Caminus* (Latin: forge, hearth, furnace) — the forge is where source is turned
into shipped artifacts, and where the supply chain breaks.

Single binary, dependency-free core. Linux, macOS, Windows. (Cloud
enumeration — `caminus cloud` — uses the official AWS SDK and is built only
with `-tags cloud`; the default build links no third-party packages.)

> **Status:** v0.1.0 (Sprint 1) — the static `scan` engine covers **GitHub
> Actions and GitLab CI**, with text / JSON / SARIF output. `enum` / `graph` /
> `exploit` are scaffolded with stable interfaces; see [`DESIGN.md`](./DESIGN.md)
> §Roadmap and [`PLAN.md`](./PLAN.md).

---

## Why Caminus

The CI/CD attack-tool landscape splits into static scanners (poutine, Raven)
that only flag patterns, and GitHub-only exploitation tools (gato-x). None
unifies **multi-platform** coverage, an **OIDC → cloud blast-radius** graph, and
**dynamic confirmation** in one tool. Caminus fills that middle and slots into the
existing pipeline (Reticustos → **Caminus** → Vinculum → Ariadne / Nubicustos).

Findings map to the OWASP Top 10 CI/CD Security Risks and the Poisoned Pipeline
Execution (PPE) classes.

## Install

```bash
go build -o caminus ./cmd/caminus
# or
go install github.com/Su1ph3r/caminus/cmd/caminus@latest
```

## Usage

```bash
# Scan the repo (defaults to "."): finds GitHub Actions AND GitLab CI files
caminus scan

# Scan specific paths/files (platform auto-detected from path)
caminus scan .github/workflows/
caminus scan .gitlab-ci.yml
caminus scan release.yml --platform github

# Output formats: text (default), json, sarif (code scanning)
caminus scan . --format sarif

# Only show high+ findings; control the CI gate threshold
caminus scan . --min-severity high
caminus scan . --gate critical      # exit 1 only on critical
caminus scan . --gate none          # never fail the build
```

Exit codes: `0` clean · `1` finding at/above the gate (default `high`) ·
`2` usage/error · `3` capability not yet implemented.

## Example

```
$ caminus scan testdata/vuln-pwn-request.yml

[CRIT] Pwn request: privileged trigger checks out untrusted PR head  [confirmable]
  CAM-PPE-001  testdata/vuln-pwn-request.yml:16  (pwn-request)
  > ref: ${{ github.event.pull_request.head.sha }}
  fix: Do not check out and execute untrusted PR code in a privileged-trigger workflow...

[CRIT] Untrusted input "github.event.comment.body" interpolated into a run: shell command  [confirmable]
  CAM-INJ-001  testdata/vuln-pwn-request.yml:21  (expression-injection)
  > echo "comment: ${{ github.event.comment.body }}"
  ...

6 finding(s): 3 critical, 1 high, 1 medium, 1 low, 0 info
```

The `[confirmable]` tag marks findings the (planned) `exploit` stage can prove
against a target you own.

## Rules

**GitHub Actions**

| ID | Severity | What it catches |
|----|----------|-----------------|
| `CAM-INJ-001`  | Critical | Untrusted `${{ github.event.* }}` interpolated into a `run:` shell |
| `CAM-PPE-001`  | Crit/High/Med | Pwn request: privileged trigger (± untrusted checkout) |
| `CAM-RUN-001`  | High/Med | Self-hosted runner reachable by pipeline execution |
| `CAM-PERM-001` | Medium | `GITHUB_TOKEN` granted `write-all` |
| `CAM-SUP-001`  | Low | Third-party action not pinned to a commit SHA |

**GitLab CI**

| ID | Severity | What it catches |
|----|----------|-----------------|
| `CAM-GL-INJ-001` | Critical | Untrusted `$CI_*` (MR/commit/branch field) interpolated into `script:` |
| `CAM-GL-PPE-001` | Medium | Merge-request pipeline secret / `CI_JOB_TOKEN` exposure |
| `CAM-GL-DBG-001` | High | `CI_DEBUG_TRACE`/`CI_DEBUG_SERVICES` leaking secrets to job logs |
| `CAM-GL-RUN-001` | High/Med | Privileged Docker-in-Docker build |
| `CAM-GL-SUP-001` | Low | `include: remote:` / unpinned cross-project include |

**Enumeration (`enum` / `cloud`)** — findings that require API access, not just YAML

| ID | Severity | What it catches |
|----|----------|-----------------|
| `CAM-OIDC-001` | Medium | Over-broad OIDC subject — repo-wide federation token (no ref/environment scoping) |
| `CAM-OIDC-002` | High/Crit | Attacker-controllable pipeline can assume a permissively-trusted cloud role (CI → OIDC → cloud) |

Caminus deliberately does **not** flag untrusted input routed through an
intermediate `env:` variable (GitHub) or a quoted environment read (GitLab) —
that is the recommended remediation, and false-positiving on best practice
erodes trust.

## Development

```bash
go vet ./...
go test ./...
go build -o caminus ./cmd/caminus
```

See [`DESIGN.md`](./DESIGN.md) for architecture, the attack taxonomy, and the
M1.5 → M4 roadmap (GitLab CI, SARIF/Ariadne export, authenticated enumeration,
OIDC graph, dynamic confirmation).

## License

MIT.
