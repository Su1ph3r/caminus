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
| octoscan   | Go       | clone `synacktiv/octoscan`, `go build .` (replace directives block `go install`) |
| raven      | Python   | Cycode — needs a Redis + Neo4j backend                    |
| gato-x     | Python   | `pipx install gato-x` (GitHub-API / token driven)         |

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

### octoscan v0.1.x (Synacktiv) — measured 2026-06-03

octoscan is a Go tool built on `actionlint`; it analyzes individual workflow
files (`compare_octoscan.sh` scans each case's `.github/workflows/*.yml`). It is
**GitHub-only**, so the two GitLab cases are scored **N/A**, not missed.

```
TP=4  FN=6  FP=1  TN=5  N/A=2   gaps: 0 missed, 3 caught
precision=80%   recall=40%  (over the 10 covered GitHub classes; GitLab N/A)
```

| corpus case (class)                  | Caminus | octoscan | note |
|--------------------------------------|:-------:|:--------:|------|
| inj-direct (`CAM-INJ-001`)           |   ✓     |    ✓     | `expression-injection` |
| inj-envrouted (`CAM-INJ-002`)        |   ✓     |    ✗     | env-routed unquoted use — octoscan misses |
| ppe-pwnrequest (`CAM-PPE-001`)       |   ✓     |    ✓     | `dangerous-checkout` |
| ppe-indirect-script (`CAM-PPE-002`)  |   ✓     |    ✗     | sink in an executed shell file |
| ppe-reusable (`CAM-PPE-003`)         |   ✓     |    ✗     | only flags `local-action` (informational), not the injection |
| ppe-composite (`CAM-PPE-004`)        |   ✓     |    ✓     | flags untrusted `${{ }}` in the step `with:` |
| run-selfhosted (`CAM-RUN-001`)       |   ✓     |    ✓     | `runner-label` |
| perm-writeall (`CAM-PERM-001`)       |   ✓     |    ✗     | no equivalent rule |
| sup-unpinned (`CAM-SUP-001`)         |   ✓     |    ✗     | no plain-unpinned-tag rule |
| sup-reusable-mutable (`CAM-SUP-002`) |   ✓     |    ✗     | — |
| gl-inj / gl-debug (GitLab)           |   ✓     |   N/A    | octoscan is GitHub-only |
| **gap-github-script** (gap)          |   ✗     |    ✓     | `expression-injection` in `script:` — Caminus does not model it |
| **gap-nested-composite** (gap)       |   ✗     |    ✓     | flags the untrusted `with:` input-side (no hop-tracing needed) |
| **gap-local-js-action** (gap)        |   ✗     |    ✓     | flags the untrusted `with:` input-side |
| **safe-composite-safeinput** (safe)  | clean   | **FP**   | flags the tainted `title` the composite never uses |

**The precision/recall tradeoff, measured.** octoscan's `expression-injection`
fires whenever an untrusted `${{ }}` appears in a `run:`, a step `with:`, or a
`script:` — *without tracing whether the action actually uses it*. That coarser,
input-side heuristic is why octoscan **catches all three of Caminus's gaps**
(github-script, nested composite, local JS) — it does not need to follow the sink
— but it is also why it **false-positives on `safe-composite-safeinput`**, where
the tainted `title` is passed but the composite only consumes the safe `mode`
input. Caminus's dataflow precision is the mirror image: it traces the input to
the actual sink, so it stays silent on the safe case (0 FP) but is silent too
when the sink is in a context it does not yet model (a `script:` block, a second
composite hop, or JavaScript). Neither is strictly better — octoscan trades
precision for recall on the injection-into-action surface; Caminus trades that
recall for precision and adds the env-routed / indirect-file / reusable-workflow
/ supply-chain classes octoscan has no rule for.

### Tools not run

| tool   | status (2026-06-03) | reason |
|--------|---------------------|--------|
| raven  | not run             | requires a Redis + Neo4j backend and a repo downloader; not an offline single-tree analyzer |
| gato-x | not run             | enumeration/attack tool driven by the GitHub API with a token; not suited to scanning an offline corpus |

Marked honestly rather than estimated. Both could be added with a heavier harness
(a local Neo4j for raven; a mock GitHub API for gato-x); neither fits the current
offline-tree methodology.

## Takeaways

Over this (Caminus-shaped) corpus, the three tools are **complementary**, and the
honest headline is *not* "Caminus wins" but *what each approach buys*:

- **Caminus** — the only tool that covers env-routed injection (`CAM-INJ-002`),
  indirect-PPE into executed files (`CAM-PPE-002`), reusable-workflow injection
  (`CAM-PPE-003`), supply-chain pinning (`CAM-SUP-001/002`), and GitLab — and it
  did so at **100% precision** (0 FP) because it traces dataflow to the sink.
- **octoscan** — strongest on injection breadth via a coarse input-side heuristic;
  catches the `script:` / nested / JS cases Caminus misses, at the cost of 1 FP.
- **poutine** — solid on the classic pwn-request / self-hosted / debug surface and
  supply-chain themes Caminus does not model (confused-deputy, unpinnable, known-
  vulnerable components — not yet in this corpus).

The actionable output for Caminus: the three known gaps (github-script `script:`,
nested composite, local JS) are exactly where octoscan's input-side check adds
value — candidates for a future Caminus rule that flags untrusted input crossing
into an action whose sink it cannot resolve (an UNASSESSED-style signal), keeping
precision while closing the recall gap.
