# Caminus — Design & Strategy

*Caminus* (Latin: forge, hearth, furnace) — the forge is where raw source is
turned into shipped artifacts, and where the software supply chain is most often
broken. It keeps the Latin-noun naming of the suite (Vinculum, Indago, Vallum).

Caminus is a **multi-platform CI/CD pipeline attack framework**: it maps a
pipeline compromise as a trust graph from an attacker-controllable trigger to
its blast radius — secrets, self-hosted runners, and (via OIDC) cloud roles and
the resources behind them — and is built to **dynamically confirm** the
primitives it finds.

---

## Why this tool (the gap)

CI/CD is one of the highest-leverage, least-tooled attack surfaces. The existing
tools split into two camps, and neither closes the loop:

| Tool | Scope | Approach | Limits |
|------|-------|----------|--------|
| **poutine** (BoostSecurity) | GitHub, GitLab, others | Static config patterns | Read-only; pattern flags, no exploit confirmation, no cross-asset reachability |
| **Raven** (Cycode) | GitHub | Download → Neo4j → rego | Static; GitHub-only; infra-heavy |
| **gato / gato-x** (Praetorian) | GitHub only | Token enum + some exploitation | GitHub-only, Python; no GitLab/Jenkins; no unified graph |
| **legitify** | GitHub/GitLab orgs | Posture/policy | Compliance posture, not attack paths |
| TruffleHog / gitleaks | any repo | Secret regex | Secrets only |

**The unfilled middle:** a single tool that (1) covers **more than GitHub**,
(2) unifies static findings + authenticated enumeration into **one trust
graph**, (3) resolves the **OIDC → cloud blast radius**, and (4) turns a flagged
primitive into a **confirmed** one. That is Caminus.

### The four wedges

1. **Multi-platform attack model.** GitHub Actions first, then **GitLab CI**
   (the largest unserved attack surface — poutine scans it statically, no tool
   *attacks* it well), then Jenkins / Azure Pipelines / CircleCI. One graph,
   cross-provider paths.
2. **OIDC trust-chain resolution.** The high-value, fully-unautomated step:
   "this poisoned pipeline can assume *this* cloud role and reach *these*
   resources." This is where Caminus hands off to **Nubicustos** for cloud
   blast-radius.
3. **Static → dynamic confirmation.** Static scanners drown operators in
   maybe-exploitable flags. Caminus marks findings `confirmable` and the
   `exploit` stage proves them against a target you own (malicious-PR diff /
   workflow payload with a benign canary) — aligned with the project's
   runtime-PoC discipline.
4. **Pipeline-native output.** The JSON report is a clean, Vinculum-shaped
   tool-output document so Caminus can slot into the suite (correlation →
   Ariadne synthesis → Nubicustos cloud edges) as the missing CI/CD node. A
   dedicated Vinculum/Ariadne exporter is not built (deferred indefinitely);
   today the integration seam is the JSON/SARIF report.

---

## Attack taxonomy

Findings map to the OWASP Top 10 CI/CD Security Risks and the Poisoned Pipeline
Execution (PPE) classes:

- **Expression injection** (CICD-SEC-4) — untrusted `${{ github.event.* }}` in a
  `run:` shell. *Confirmable.*
- **Pwn request / Public-PPE** — privileged trigger
  (`pull_request_target`, `workflow_run`, `issue_comment`) + untrusted checkout.
  *Confirmable.*
- **Direct-PPE** — attacker controls the pipeline definition (write access /
  branch without protection).
- **Indirect-PPE** — injection into a pipeline-referenced file (shell script,
  Makefile recipe, npm/package.json script) executed by the pipeline, reached by
  an env-routed (GitHub) or auto-exported (`$CI_*`, GitLab) untrusted value used
  unquoted or via `eval`/command-substitution. *Confirmable.*
- **Runner exposure** (CICD-SEC-7) — non-ephemeral self-hosted runners reachable
  by untrusted code.
- **Excessive permissions** (CICD-SEC-5) — over-broad `GITHUB_TOKEN` / job
  scopes.
- **Unpinned dependency** (CICD-SEC-3) — third-party actions on a mutable tag/
  branch instead of a digest.
- **OIDC trust** (CICD-SEC-6) — over-permissive cloud federation
  (`sub` claim wildcards, missing audience/branch conditions).
- **Secret exposure** (CICD-SEC-6) — credentials surfaced to untrusted code.

---

## Architecture

```
                         ┌──────────────────────────────────────┐
  pipeline YAML ───────► │ scan   static rules → Finding[]       │ (no token)
                         └──────────────┬───────────────────────┘
                                        │ seeds
  token ─────────────►  ┌───────────────▼───────────────────────┐
                        │ enum   provider client → trust graph   │ [M2]
                        │   github / gitlab (platform.Platform)  │
                        └───────────────┬───────────────────────┘
  Nubicustos cloud ───► ┌───────────────▼───────────────────────┐
  export                │ graph  walk edges → AttackPath[]       │ [M2]
                        │   trigger→pipeline→runner/secret→OIDC  │
                        │   →cloud-role→resource                 │
                        └───────────────┬───────────────────────┘
                                        │ confirmable findings
                        ┌───────────────▼───────────────────────┐
                        │ exploit  build PoC artifact, observe   │ [M3]
                        │   (authorization-gated)                │
                        └───────────────┬───────────────────────┘
                                        ▼
        reporter → text · json (Vinculum-shaped) · SARIF
```

Package layout (zero external Go dependencies, single binary — matches Vallum /
Vercelsior house style):

```
cmd/caminus/            CLI: main, cli (router), scan, enum, graph, exploit
internal/model/        Finding + trust-graph types (Node/Edge/Graph/AttackPath)
internal/workflow/     dependency-free line model of a pipeline file
internal/rules/        static attack rules (CAM-INJ/PPE/RUN/PERM/SUP-*)
internal/platform/     provider abstraction (github/gitlab clients land in M2)
internal/reporter/     text + JSON (Vinculum-shaped) + SARIF
```

### Design choices

- **Line-oriented by default; structural on demand.** The rules reason about
  textual patterns and need exact line numbers + original text for evidence and
  for the exploit stage, so the default engine is a zero-dependency line model.
  A structural parse (`-tags yaml`, `gopkg.in/yaml.v3`) *augments* — never
  replaces — it: the line model still supplies line numbers and evidence, while
  the structural parser resolves anchors/aliases and flow forms the textual scan
  cannot recover. The dependency is isolated behind the build tag, so the default
  binary still links nothing third-party.
- **Precision over recall on injection.** The direct injection rule fires only on
  literal `${{ … }}` `run:` interpolation, *not* on the recommended
  `env:`-indirection remediation — flagging best practice would destroy operator
  trust. The follow-on rules then catch the cases where the routing was not
  actually made safe, all sharing one shell-quote analyzer that requires a
  genuinely unsafe use (unquoted / `eval` / command-substitution) and leaves a
  quoted `"$VAR"` alone: `CAM-INJ-002` for an env-routed value used unsafely
  inline in the same `run:`, and `CAM-PPE-002` / `CAM-GL-INJ-002` for the same
  unsafe use one file-hop out (the executed file is read from disk; an absent
  file produces nothing).
- **`confirmable` is a first-class field.** It is the contract between the
  static stage and the exploit stage and the thing that differentiates Caminus
  from pattern scanners.

---

## Roadmap

**M1 — static engine (this milestone). ✅**
GitHub Actions rules (injection, pwn-request, self-hosted runner, write-all,
unpinned actions), text + JSON output, severity gate, tests. Single binary.

**M1.5 — coverage & output. ✅ (shipped in v0.1.0)**
- GitLab CI (`.gitlab-ci.yml`) static rules: script injection, MR-pipeline
  exposure, debug-trace, privileged dind, unpinned include.
- SARIF reporter (CI gate, code scanning).
- *Deferred:* indirect-PPE, structural YAML (`-tags yaml`), Ariadne export.

**M2 — enumeration & graph. ✅**
- `internal/platform/github` read-only client (stdlib http): repos, workflows
  (→ static rules → entry points), self-hosted runners, secret names,
  environments + protection rules, branch protection, OIDC subject claims;
  paginated, with record/replay for token-free testing.
- Trust-graph build; `graph` walks edges to ranked, MITRE-tagged attack paths.
  `cloud` resolves the OIDC → cloud-role blast radius by reading IAM trust
  policies **directly via the AWS SDK** (the security-critical trust matching is
  dependency-free and unit-tested; the SDK fetch is isolated behind the `cloud`
  build tag so the default binary links nothing third-party).
**M2.5 — multi-platform enum & multi-cloud blast radius. ✅**
- `internal/platform/gitlab` read-only client (stdlib http): groups/projects,
  `.gitlab-ci.yml` (→ GitLab rules → entry points), runners, CI/CD variables,
  `id_tokens:` OIDC; same host-gated token / pagination / `enum_incomplete`
  discipline as GitHub. `enum --platform gitlab`; self-managed via `--base-url`.
- `cloud --provider gcp|azure` (alongside aws). GCP reads Workload Identity
  Federation (pools/providers + SA IAM bindings); Azure reads app-registration
  federated identity credentials via Graph. Provider-neutral trust model; both
  SDKs isolated behind `-tags cloud`, default binary still links nothing
  third-party. Real-SDK record/replay tests, no cloud account needed.

**M3 — dynamic confirmation. ✅**
- `exploit` (`internal/exploit`) generates the concrete artifact (attack input /
  workflow payload with a benign canary) for `confirmable` findings — injection,
  pwn-request, self-hosted runner, and the OIDC→cloud assumption (provider- and
  platform-aware) — with a reversible Deliver/Evidence/Cleanup plan. Reads a
  trust graph and/or a scan report. Generated PoCs are read-only by design:
  benign canary, read-only cloud identity call, secret values never exfiltrated.
- `--arm` (gated on `--i-own-target`) performs **live, reversible** confirmation
  for the workflow-delivering PoCs: a self-contained write client creates a
  branch, delivers the PoC, lets the pushed branch trigger the run, polls it,
  confirms the canary in the logs, and deletes the branch (cleanup deferred on
  every exit path; `--keep` opts out). Injection/pwn fall back to the playbook.
- `cloud` resolves the OIDC→cloud blast radius for **GitLab as well as GitHub**:
  the trust model carries the CI issuer, subject matching is grammar-agnostic
  (`repo:` / `project_path:`), and trust↔repo is gated by source platform.

**M3.5 — deeper detection. ✅**
- **Inline env-routed injection** (`CAM-INJ-002`): an attacker-controllable value
  routed through `env:` (the form `CAM-INJ-001` treats as safe) but then used
  unquoted / via `eval`/command-substitution directly in a `run:` shell — the
  same-step completion of the injection family, disjoint from `CAM-INJ-001`.
- **Indirect-PPE** (`CAM-PPE-002` / `CAM-GL-INJ-002`): untrusted input that is
  env-routed (GitHub) or auto-exported (`$CI_*`, GitLab) but then used unsafely
  inside a **local file the pipeline executes** (shell script, `Makefile` recipe,
  `package.json` script). Follows `run:`/`script:` invocations to on-disk files,
  resolves the repo root from the pipeline path, and applies a shell-quote
  analyzer (unquoted / `eval` / `$(…)` / backtick = unsafe; `"$VAR"` = safe). An
  absent referenced file yields no finding — no speculative FPs. This realizes
  the env-routed dataflow `CAM-INJ-001` deferred, one file-hop out.
- **Structural YAML** (`-tags yaml`): opt-in `gopkg.in/yaml.v3` engine isolated
  behind the build tag (like the cloud SDKs; default binary links nothing
  third-party). It resolves anchors/aliases and flow forms for the indirect
  rules — e.g. an `env:` value supplied via an alias whose anchored source is the
  untrusted expression, which the line model cannot connect. Augments, never
  replaces, the line model (which still supplies line numbers and evidence).

**M4 — distribution. (in progress)**
- GoReleaser (Linux/macOS/Windows × amd64/arm64) with Homebrew tap + Scoop
  bucket, gated so binary releases precede package-publish setup. ✅
- GitHub Action (Docker) wrapping `caminus scan` for CI, with a SARIF/gate flow;
  the `Dockerfile` is also a standalone Caminus image. ✅
- *Dropped (indefinitely):* Vinculum + Ariadne export. Reusable-workflow +
  composite-action expansion remains a future option.

---

## Non-goals

- Not a SAST/secrets scanner (TruffleHog/Semgrep own that; Caminus consumes their
  output via Vinculum instead).
- Not a compliance-posture tool (legitify's lane).
- The `exploit` stage never targets third-party infrastructure without explicit
  ownership/authorization, and prefers reversible, evidence-adding actions.
