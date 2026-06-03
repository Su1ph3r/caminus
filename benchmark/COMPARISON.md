# Caminus vs other CI/CD scanners

This compares Caminus against the established open-source GitHub Actions / CI
security scanners on the **same labeled corpus** used by the precision/recall
harness (`benchmark/README.md`).

**Honesty rule:** a row is filled in only for a tool that was actually executed
against the corpus, with its version recorded. No estimated, asserted, or
remembered numbers — an unrun tool stays marked *pending*.

## Tools

| tool       | language | install                                                   |
|------------|----------|-----------------------------------------------------------|
| poutine    | Go       | `go install github.com/boostsecurityio/poutine@latest`    |
| raven      | Python   | `pip install raven-cycode` (Cycode)                       |
| octoscan   | Python   | `pip install octoscan`                                    |
| gato-x     | Python   | `pip install gato-x`                                      |

Several of these are oriented toward *scanning a whole repo / org over the GitHub
API* rather than a single offline file tree, so the harness points each at the
corpus case directory and maps whatever local-analysis findings it emits to the
per-case ground truth (same `expect` / `forbid` labels as `manifest.jsonl`).

## Methodology

For each tool and each corpus case:

1. Run the tool over `corpus/<id>/` (offline, no network) in its machine-readable
   output mode (SARIF / JSON where available).
2. Map the tool's findings to the case's ground-truth class — a tool "detects"
   the case if it reports *any* finding at the intended sink (same file, and the
   same vulnerability class as `expect`).
3. Score TP / FN on `vuln` cases and FP / TN on `safe` cases, exactly as the
   Caminus harness does, so the columns are directly comparable.

The interesting axis is not raw count but the **safe / near-miss** cases: a
scanner that flags `safe-inj-envrouted-quoted` (an env-routed value that *is*
quoted) or `safe-sup-pinned` (an action pinned to a SHA) is trading precision for
recall. Those are the rows that separate a dataflow-aware scanner from a
line-grep one.

## Corpus bias — read this first

This corpus was authored from the **classes Caminus targets** (plus three honest
gaps), so it is *shaped toward Caminus* and naturally favors it on recall. It is a
**coverage comparison over these specific classes**, not an unbiased ranking of
tools — every scanner here detects things the corpus does not yet contain (e.g.
poutine's confused-deputy auto-merge, unpinnable-action, and known-vulnerable-
component rules). A fair two-way benchmark would grow the corpus with each
competitor's strength classes; the single gap poutine wins below (`gap-github-
script`) is the start of that. Numbers are reported per-corpus, with that caveat.

## Results

Reproduce: `POUTINE=<bin> bash benchmark/compare_poutine.sh` (Linux) then
`python3 benchmark/score_comparison.py`. Raw per-case tool output is committed in
`results-poutine.jsonl`.

### poutine v0.15.x — measured 2026-06-03 (Linux/WSL)

poutine's local analyzer does **not** load repositories under Windows go-git
(every rule passes vacuously); it was run from Linux (Kali WSL) against each case
as a committed git repo. Per-corpus result:

```
TP=4  FN=8  FP=0  TN=6   gaps: 2 missed, 1 caught
precision=100%   recall=33%  (over the 12 covered classes of this corpus)
```

| corpus case (class)                         | Caminus | poutine | note |
|---------------------------------------------|:-------:|:-------:|------|
| inj-direct (`CAM-INJ-001`)                  |   ✓     |   ✓     | both: `injection` |
| inj-envrouted (`CAM-INJ-002`)               |   ✓     |   ✗     | env-routed unquoted use — poutine misses |
| ppe-pwnrequest (`CAM-PPE-001`)              |   ✓     |   ✓     | both: `untrusted_checkout_exec` |
| ppe-indirect-script (`CAM-PPE-002`)         |   ✓     |   ✗     | sink in an executed shell file |
| ppe-reusable (`CAM-PPE-003`)                |   ✓     |   ✗     | reusable-workflow boundary |
| ppe-composite (`CAM-PPE-004`)               |   ✓     |   ✗     | composite-action boundary |
| run-selfhosted (`CAM-RUN-001`)              |   ✓     |   ✓     | both: `pr_runs_on_self_hosted` |
| perm-writeall (`CAM-PERM-001`)              |   ✓     |   ✗     | poutine's perms rule is scoped to risky events |
| sup-unpinned (`CAM-SUP-001`)                |   ✓     |   ✗     | poutine does not flag plain mutable tags by default |
| sup-reusable-mutable (`CAM-SUP-002`)        |   ✓     |   ✗     | unpinned remote reusable workflow |
| gl-inj (`CAM-GL-INJ-001`)                   |   ✓     |   ✗     | GitLab `$CI_*` injection |
| gl-debug (`CAM-GL-DBG-001`)                 |   ✓     |   ✓     | both: `debug_enabled` |
| **gap-github-script** (gap)                 |   ✗     |   ✓     | **poutine wins** — `script:` injection Caminus does not model |
| gap-nested-composite (gap)                  |   ✗     |   ✗     | both miss the second composite hop |
| gap-local-js-action (gap)                   |   ✗     |   ✗     | both: JS sink |
| 6 safe / near-miss cases                    | 0 FP    | 0 FP    | neither false-positives on the recommended-safe forms |

**Reading it honestly:** the two tools are largely **complementary**. Caminus's
edge on this corpus is dataflow depth — env-routed injection, indirect-PPE into
executed files, and injection across the reusable-workflow / composite-action
call boundary (`CAM-PPE-002/003/004`), none of which poutine flags — plus GitLab
injection and plain unpinned-tag coverage. poutine's edge is `actions/github-
script` `script:` injection, which Caminus does not yet model (already on
Caminus's known-gap list — this confirms it). Both held 100% precision on the
near-miss set.

### Other tools

| tool     | status (2026-06-03) | reason |
|----------|---------------------|--------|
| octoscan | not yet run         | static Python analyzer — attemptable offline; harness pending |
| raven    | not run             | requires a Redis + Neo4j backend and a repo downloader; not an offline single-tree analyzer |
| gato-x   | not run             | enumeration/attack tool driven by the GitHub API with a token; not suited to scanning an offline corpus |

These are marked honestly rather than estimated. `octoscan` is the next candidate
for a like-for-like offline run.
