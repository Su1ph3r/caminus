# Caminus

**Multi-platform CI/CD pipeline attack framework.**

Caminus maps a pipeline compromise as a trust graph — from an attacker-controllable
trigger to its blast radius (secrets, self-hosted runners, and, via OIDC, cloud
roles and the resources behind them) — and is built to dynamically confirm the
primitives it finds, not just flag YAML patterns.

*Caminus* (Latin: forge, hearth, furnace) — the forge is where source is turned
into shipped artifacts, and where the supply chain breaks.

Single binary, dependency-free core. Linux, macOS, Windows. (Cloud
enumeration — `caminus cloud` — uses the official AWS / GCP / Azure SDKs and is
built only with `-tags cloud`; the default build links no third-party packages.)

> **Status:** the full pipeline works — `scan` (GitHub Actions + GitLab CI),
> `enum` (GitHub **and** GitLab), `graph`, `cloud` (AWS, GCP, Azure OIDC
> blast-radius, for GitHub **and** GitLab graphs), and `exploit` (PoC generation
> **plus** live, reversible arming). See [`DESIGN.md`](./DESIGN.md) §Roadmap and
> [`PLAN.md`](./PLAN.md).

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

# With cloud blast-radius support (AWS / GCP / Azure SDKs):
go build -tags cloud -o caminus ./cmd/caminus
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

### Trust graph & attack paths (token required)

```bash
# 1. Enumerate into a trust graph (or --replay a cassette). Pick a platform:
caminus enum --platform github --org acme --token $CAMINUS_TOKEN -o graph.json
caminus enum --platform gitlab --org acme --token $CAMINUS_TOKEN -o graph.json
#   self-managed GitLab / GitHub Enterprise: add --base-url
#   single project/repo: --repo acme/widgets

# 2. Resolve the OIDC→cloud blast radius (needs a -tags cloud build + cloud creds)
caminus cloud -i graph.json --provider aws                     # enriches in place
caminus cloud -i graph.json --provider gcp --project my-proj
caminus cloud -i graph.json --provider azure

# 3. Synthesize ranked, MITRE-tagged attack paths
caminus graph -i graph.json --min-severity high
```

This surfaces chains like *poisoned pipeline → OIDC federation → assumable cloud
identity* (`CAM-OIDC-002`: an AWS role, GCP service account, or Azure app), plus
paths to self-hosted runners and CI secrets — for both GitHub and GitLab graphs.

### Confirm a finding (PoC generation)

`exploit` turns a **confirmable** finding into a concrete, non-destructive PoC —
the attack input / pipeline payload with a benign canary — plus a reversible
Deliver / Evidence / Cleanup plan.

```bash
# Generate a PoC for the OIDC→cloud assumption (writes poc/<rule>-<target>/)
caminus exploit -i graph.json --finding CAM-OIDC-002

# Injection/runner PoCs from a scan report; target you own
caminus scan . --format json > scan.json
caminus exploit --scan scan.json --finding CAM-INJ-001 --repo me/mine -o -

# Live, reversible confirmation against a target you own (gated)
caminus exploit -i graph.json --finding CAM-OIDC-002 --repo me/mine \
    --arm --i-own-target --token $CAMINUS_TOKEN
```

The generated PoCs are non-destructive: canaries are benign, the cloud proof is a
single read-only identity call, and secret *values* are never exfiltrated.
`--arm` (gated on `--i-own-target`) performs the live confirmation for the
workflow-delivering PoCs (OIDC, runner): it creates a branch, delivers the PoC,
lets the run trigger, confirms the canary in the logs, then **deletes the
branch** — cleanup runs on every exit path. Injection/pwn-request PoCs are not
auto-armed; `--arm` prints their manual playbook instead.

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
| `CAM-PPE-002`  | Critical | Indirect PPE: untrusted input reaches a shell **inside a local file the pipeline runs** (script/Makefile/`package.json`), unquoted or via `eval` |
| `CAM-PPE-001`  | Crit/High/Med | Pwn request: privileged trigger (± untrusted checkout) |
| `CAM-RUN-001`  | High/Med | Self-hosted runner reachable by pipeline execution |
| `CAM-PERM-001` | Medium | `GITHUB_TOKEN` granted `write-all` |
| `CAM-SUP-001`  | Low | Third-party action not pinned to a commit SHA |

**GitLab CI**

| ID | Severity | What it catches |
|----|----------|-----------------|
| `CAM-GL-INJ-001` | Critical | Untrusted `$CI_*` (MR/commit/branch field) interpolated into `script:` |
| `CAM-GL-INJ-002` | Critical | Indirect injection: untrusted `$CI_*` reaches a shell **inside a local file the pipeline runs**, unquoted or via `eval` |
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
erodes trust. The indirect rules (`CAM-PPE-002` / `CAM-GL-INJ-002`) close the
flip side: routing is only safe if the value is then *used* safely, so when the
pipeline hands execution to a local repo file that uses the value **unquoted**
or via `eval`/command-substitution, that is flagged. The referenced file is read
from disk relative to the repo root; if it is not present (e.g. a single-file
scan) nothing is reported — no speculative findings.

**Structural YAML (`-tags yaml`, optional).** The default engine is a
zero-dependency line model. Building with `-tags yaml` links `gopkg.in/yaml.v3`
(isolated behind the tag, exactly like the cloud SDKs) and lets the indirect
rules resolve YAML anchors/aliases and flow forms — e.g. an `env:` value supplied
through an alias whose anchored source is the untrusted expression, which the
line model cannot connect. Detection is otherwise identical.

## Development

```bash
go vet ./...
go test ./...
go build -o caminus ./cmd/caminus

# Optional structural-YAML engine (anchor/alias/flow resolution):
go test -tags yaml ./...
go build -tags yaml -o caminus ./cmd/caminus
```

See [`DESIGN.md`](./DESIGN.md) for architecture, the attack taxonomy, and the
M1.5 → M4 roadmap (GitLab CI, SARIF/Ariadne export, authenticated enumeration,
OIDC graph, dynamic confirmation).

## License

MIT.
