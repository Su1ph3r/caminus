# Security policy

## Reporting a vulnerability

Please report security issues in Caminus privately, via GitHub's **private
vulnerability reporting** (the **Security** tab → *Report a vulnerability*) on
this repository, rather than opening a public issue. Include a description, the
affected version/commit, and a reproduction if you have one. You'll get an
acknowledgement and a fix or mitigation timeline.

Caminus is itself a security tool: it reads pipeline files, and — only with the
`enum`/`cloud`/`exploit` commands — talks to CI and cloud APIs with credentials
you supply. The static `scan` engine performs **no** network calls and executes
nothing it scans.

## Supported versions

Fixes land on `main` and ship in the next tagged release. The latest `v0.x`
release is the supported line; older tags are not back-patched.

## Stability commitment

Caminus is pre-1.0 (`v0.x`), but the **static analysis surface is treated as
stable** and changes to it follow semver-style care:

**Stable — breaking changes are avoided and called out in `CHANGELOG.md`:**
- the `caminus scan` command, its flags, and its **exit codes**
  (`0` clean · `1` finding at/above the gate · `2` usage/error · `3` not
  implemented);
- the **JSON** and **SARIF** report schemas (field names, structure);
- existing **rule IDs** (`CAM-INJ-*`, `CAM-PPE-*`, `CAM-RUN-*`, `CAM-PERM-*`,
  `CAM-SUP-*`, `CAM-GL-*`, `CAM-OIDC-*`) — an ID is not reused for a different
  meaning, and a rule's severity is only changed deliberately and noted;
- the GitHub Action inputs (`action.yml`).

New rules may be added in a minor release (they can surface new findings on an
unchanged input — that is coverage, not a breaking change).

**Experimental — the surface may change without a major bump:**
- `caminus enum`, `graph`, and `cloud` (authenticated enumeration, the trust
  graph, and the OIDC→cloud blast-radius), and their output graph schema;
- `caminus exploit`, including `--arm` live confirmation;
- the structural-YAML engine (`-tags yaml`).

These are powerful and require a token and/or a target you own; they are
validated by unit/record-replay tests but have not been hardened to the same
"stable" bar as `scan`. Use them deliberately, and only against assets you own
or are authorized to test.

## Platform scope

Caminus supports **GitHub Actions** and **GitLab CI**. Other CI systems
(CircleCI, Azure Pipelines, Jenkins, Bitbucket Pipelines) are out of scope for
the current line and tracked as post-1.0 in [`PLAN.md`](./PLAN.md).
