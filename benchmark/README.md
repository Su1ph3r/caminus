# Caminus benchmark — precision & recall

This is the credibility artifact for Caminus: a **labeled corpus** of CI/CD
pipelines with ground truth, and a reproducible scorer that measures Caminus's
false-negative and false-positive rates per rule class.

The corpus encodes **known** pipeline-attack patterns (OWASP CICD-SEC, GitHub
Security Lab pwn-request / untrusted-input research, reusable-workflow and
composite-action injection) — *including patterns Caminus does not yet detect*.
The scorecard is therefore an honest statement of coverage, not a victory lap:
the "known coverage gaps" section is a permanent, tested record of the frontier.

## Run it

```bash
go test ./benchmark/ -run Benchmark -v
```

The test builds the real `caminus` binary, scans every corpus case with it
(`caminus scan <case> --format json --gate none --min-severity info`), and scores
the output against `manifest.jsonl`. It **fails** if a covered vulnerability is
missed (regression), if a safe pipeline is flagged (precision regression), or if
a `known_gap` case is now detected (so the label gets updated).

Regenerate the corpus from scratch with `bash benchmark/gen_corpus.sh`.

## Layout

```
benchmark/
  gen_corpus.sh        # regenerates corpus/ deterministically
  manifest.jsonl       # one JSON object per case = ground truth
  corpus/<id>/         # a self-contained mini-repo per case
  benchmark_test.go    # the scorer
```

## Manifest schema

Each line of `manifest.jsonl`:

| field        | meaning                                                              |
|--------------|---------------------------------------------------------------------|
| `id` / `dir` | case identifier and its directory under `corpus/`                   |
| `platform`   | `github` \| `gitlab`                                                 |
| `polarity`   | `vuln` (something should be found) \| `safe` (nothing should)        |
| `expect`     | rule IDs that **should** fire (a `vuln` case is a TP if any fires)   |
| `forbid`     | rule IDs that must **not** fire (a `safe` case is an FP if any does) |
| `known_gap`  | `true` = a real vuln Caminus is **not expected** to catch yet        |
| `source`     | the pattern's provenance (advisory / research / CICD-SEC class)      |
| `note`       | one-line description                                                 |

## Scoring (per rule class)

A blanket "any finding on a safe file = FP" would be wrong here: Caminus
correctly emits a Medium `CAM-PPE-001` on *any* privileged trigger, which is a
true positive even in a file whose injection is safely written. So scoring is
**per rule class**:

- **TP** — a `vuln` case where an `expect` rule fired.
- **FN** — a `vuln` case where no `expect` rule fired (a real miss; fails the test).
- **FP** — a `safe` case where a `forbid` rule fired (fails the test).
- **TN** — a `safe` case where no `forbid` rule fired.
- **gap** — a `known_gap` case; scored separately and excluded from recall.

`precision = TP / (TP + FP)`  ·  `recall = TP / (TP + FN)` (over covered classes).

The **safe / near-miss** cases are the heart of the precision claim: each is the
exact pattern a naive line-grep scanner false-positives on — an env-routed value
that *is* quoted, a reusable workflow passed a *static* value, a composite using
only a *non-tainted* input, an executed script that *quotes* the variable, an
action pinned to a *SHA*. Caminus must stay silent on all of them.

## Current results (2026-06-03)

```
corpus: 23 cases  (15 covered-vuln, 7 safe, 1 known-gap)
TP=15  FN=0  FP=0  TN=7   (gaps: 1 missed, 0 now-covered)
precision = 100.0%
recall    = 100.0%   (over covered classes; gaps excluded by design)
```

Covered classes: `CAM-INJ-001/002/003`, `CAM-PPE-001/002/003/004/005`,
`CAM-RUN-001`, `CAM-PERM-001`, `CAM-SUP-001/002`, `CAM-GL-INJ-001`,
`CAM-GL-DBG-001`.

### Closing the frontier (M7)

The three gaps the M6 benchmark exposed are now **closed** — and closed without
losing precision (still 0 FP):

- **`actions/github-script` injection** → `CAM-INJ-003` (Critical). The `script:`
  input is JavaScript eval'd with the workflow token; an untrusted `${{ }}` in it
  is a confident injection, modeled directly.
- **Nested composite actions** and **local JavaScript actions** → `CAM-PPE-005`
  (Info / UNASSESSED). When a tainted input crosses into an action whose sink
  Caminus cannot resolve — a composite that forwards it onward, or a non-composite
  JS/Docker action — Caminus surfaces it as UNKNOWN rather than scoring it clean.
  The Info tier keeps it below the gate and out of the precision-sensitive set,
  and it stays silent on the *resolvable-safe* composite (no false UNASSESSED).

### Known coverage gap (the honest frontier)

One real, exploitable pattern remains uncovered — and is missed by **all three**
scanners benchmarked, not just Caminus:

1. **`$GITHUB_ENV` cross-step laundering** — an untrusted value written into
   `$GITHUB_ENV` in one step (with the write itself quoted, so the inline rules
   stay silent) and then used unquoted in a *later* step. Caminus does not track
   values that flow between steps through `$GITHUB_ENV`.

Further catalogued (not yet in the corpus): `$GITHUB_OUTPUT` /
`${{ steps.*.outputs.* }}` taint laundering, cache/artifact poisoning on
`workflow_run`, and JS sinks reached through a reusable workflow.

## Comparison with other scanners

A like-for-like comparison against `poutine`, `raven`, `octoscan`, and `gato-x`
runs the same corpus through each tool and maps its output to the per-case ground
truth. Status and methodology: see [`COMPARISON.md`](COMPARISON.md). Numbers are
only published for tools actually executed — no estimated or asserted figures.

**Measured so far (2026-06-03, with the M7 gap-closing rules):**

- `poutine` (Linux/WSL) — 5/15 covered classes, 0 FP.
- `octoscan` (Synacktiv, Go, GitHub-only) — 7/13 covered GitHub classes (GitLab
  N/A), **1 FP** (precision 88%) on `safe-composite-safeinput`.

Now that Caminus covers the github-script / nested-composite / local-JS surface
(via `CAM-INJ-003` + `CAM-PPE-005`), it matches octoscan's reach there **without**
octoscan's false positive, and remains the only tool covering env-routed /
indirect-file / reusable-workflow / supply-chain / GitLab classes — at 100%
precision. All three miss the one remaining corpus gap (`$GITHUB_ENV` laundering).
See [`COMPARISON.md`](COMPARISON.md) for the per-case tables, the measured
precision/recall tradeoff, and the note that this corpus is shaped toward
Caminus's classes (a coverage comparison, not an unbiased ranking).
