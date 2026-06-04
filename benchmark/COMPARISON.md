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
as a committed git repo. Per-corpus result (after the M7 gap-closing rules grew
the corpus to 15 covered classes):

```
TP=5  FN=10  FP=0  TN=6   gaps: 1 missed, 0 caught
precision=100%   recall=33%  (over the 15 covered classes of this corpus)
```

poutine detects `inj-direct`, `inj-github-script` (`injection`), `ppe-pwnrequest`
(`untrusted_checkout_exec`), `run-selfhosted` (`pr_runs_on_self_hosted`), and
`gl-debug` (`debug_enabled`); it misses the env-routed / indirect-file / reusable-
workflow / composite / supply-chain classes and the `$GITHUB_ENV` gap.

Per-case verdicts are reproducible live — `python3 benchmark/score_comparison.py`
prints the current table for both tools from `results-*.jsonl`. Caminus detects
all 15 covered classes; poutine's 5 are the injection / pwn-request / self-hosted
/ debug surface, and it has no rule for the dataflow-depth, supply-chain, or
GitLab-injection classes. Both hold 100% precision on the six near-miss cases.

### octoscan v0.1.x (Synacktiv) — measured 2026-06-03

octoscan is a Go tool built on `actionlint`; it analyzes individual workflow
files (`compare_octoscan.sh` scans each case's `.github/workflows/*.yml`). It is
**GitHub-only**, so the two GitLab cases are scored **N/A**, not missed.

```
TP=7  FN=6  FP=1  TN=5  N/A=2   gaps: 1 missed, 0 caught
precision=88%   recall=54%  (over the 13 covered GitHub classes; GitLab N/A)
```

octoscan detects `inj-direct`, `inj-github-script`, `ppe-pwnrequest`,
`ppe-composite`, `ppe-nested-composite`, `ppe-local-js` (all via its broad
`expression-injection` / `dangerous-checkout` / `runner-label` rules), and
`run-selfhosted`. It misses the env-routed, indirect-file, reusable-workflow, and
supply-chain classes, and the `$GITHUB_ENV` gap. Its one false positive remains
`safe-composite-safeinput`.

**The precision/recall tradeoff, measured — and how Caminus closed it.** octoscan's
`expression-injection` fires whenever an untrusted `${{ }}` appears in a `run:`, a
step `with:`, or a `script:` — *without tracing whether the action actually uses
it*. That coarse, input-side heuristic is why octoscan catches the github-script /
nested-composite / local-JS cases — it does not follow the sink — but it is also
why it **false-positives on `safe-composite-safeinput`**, flagging the tainted
`title` the composite never consumes. In M6 these three cases were Caminus's known
gaps. In M7 Caminus **closed them** the precision-preserving way: `CAM-INJ-003`
models the github-script `script:` eval directly (a confident detection), and
`CAM-PPE-005` raises an **Info/UNASSESSED** signal when a tainted input crosses
into an action whose sink it cannot resolve (a nested-forwarding composite, or a
JS/Docker action). `CAM-PPE-005` stays **silent on the resolvable-safe
composite** — Caminus reads the manifest, sees `title` is unused, and does not
raise it — so Caminus now matches octoscan's reach on this surface **without
inheriting its false positive**. The remaining honest gap (`$GITHUB_ENV` cross-
step laundering) is missed by all three tools.

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
- **octoscan** — strong injection breadth via a coarse input-side heuristic, but
  it pays 1 FP for it; Caminus now matches its injection-into-action reach
  (`CAM-INJ-003` + `CAM-PPE-005`) at 0 FP.
- **poutine** — solid on the classic pwn-request / self-hosted / debug surface and
  supply-chain themes Caminus does not model (confused-deputy, unpinnable, known-
  vulnerable components — not yet in this corpus).

M7 acted on M6's actionable output: the three gaps octoscan's input-side check
exposed are now closed — `CAM-INJ-003` (confident) for github-script, and the
UNASSESSED-style `CAM-PPE-005` for the unresolvable-sink cases — keeping 100%
precision while raising recall to all 15 covered classes. The frontier moves on:
`$GITHUB_ENV` / `$GITHUB_OUTPUT` cross-step laundering is the next candidate, and
it is missed by every tool benchmarked here.
