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

## Results

_Pending — to be populated by the comparison harness as each tool is run._

| case class                | Caminus | poutine | raven | octoscan | gato-x |
|---------------------------|:-------:|:-------:|:-----:|:--------:|:------:|
| _all rows pending_        |   ✓     |    —    |   —   |    —     |   —    |

Caminus baseline (from `benchmark/README.md`, 2026-06-03): precision 100%,
recall 100% over 12 covered classes, 0 FP on 6 near-miss safe cases, 3 known gaps
documented.
