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
4. **Pipeline-native output.** Findings export to **Vinculum** (correlation),
   attack paths to **Ariadne** (synthesis), cloud edges to **Nubicustos**.
   Caminus is the missing CI/CD node in that existing toolchain.

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
- **Indirect-PPE** — injection into a pipeline-referenced file (Makefile, npm
  script, test config) executed by the pipeline.
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
        reporter → text · json (Vinculum) · SARIF · Ariadne export
```

Package layout (zero external Go dependencies, single binary — matches Vallum /
Vercelsior house style):

```
cmd/caminus/            CLI: main, cli (router), scan, enum, graph, exploit
internal/model/        Finding + trust-graph types (Node/Edge/Graph/AttackPath)
internal/workflow/     dependency-free line model of a pipeline file
internal/rules/        static attack rules (CAM-INJ/PPE/RUN/PERM/SUP-*)
internal/platform/     provider abstraction (github/gitlab clients land in M2)
internal/reporter/     text + JSON (Vinculum-shaped); SARIF/Ariadne next
```

### Design choices

- **Line-oriented, not YAML-AST (for now).** The rules reason about textual
  patterns and need exact line numbers + original text for evidence and for the
  exploit stage. A structural parse augments this behind a build tag later;
  hand-rolling it now would add a dependency and brittleness for little gain.
- **Precision over recall on injection.** The injection rule fires only on
  direct `run:` interpolation, *not* on the recommended `env:`-indirection
  remediation — flagging best practice would destroy operator trust. Unsafe use
  of env-routed values needs dataflow (a later milestone).
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

**M3 — dynamic confirmation.**
- `exploit` generates the concrete artifact (malicious-PR diff / workflow
  payload with a benign canary) for `confirmable` findings; armed mode observes
  execution against a target you own and captures evidence. Authorization-gated
  (`--i-own-target`), reversible, evidence-adding only.

**M4 — distribution.**
- GoReleaser (Linux/macOS/Windows), Homebrew/Scoop, a GitHub Action wrapper,
  Docker image. Reusable-workflow + composite-action expansion.

---

## Non-goals

- Not a SAST/secrets scanner (TruffleHog/Semgrep own that; Caminus consumes their
  output via Vinculum instead).
- Not a compliance-posture tool (legitify's lane).
- The `exploit` stage never targets third-party infrastructure without explicit
  ownership/authorization, and prefers reversible, evidence-adding actions.
