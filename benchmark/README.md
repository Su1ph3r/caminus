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
corpus: 21 cases  (12 covered-vuln, 6 safe, 3 known-gap)
TP=12  FN=0  FP=0  TN=6   (gaps: 3 missed, 0 now-covered)
precision = 100.0%
recall    = 100.0%   (over covered classes; gaps excluded by design)
```

Covered classes: `CAM-INJ-001/002`, `CAM-PPE-001/002/003/004`, `CAM-RUN-001`,
`CAM-PERM-001`, `CAM-SUP-001/002`, `CAM-GL-INJ-001`, `CAM-GL-DBG-001`.

### Known coverage gaps (the honest frontier)

These are real, exploitable patterns the corpus encodes that Caminus does **not**
yet detect. Each is a candidate for a future rule:

1. **`actions/github-script` injection** — untrusted input interpolated into the
   `script:` (a JavaScript context), not a `run:` shell. Caminus models `run:`
   sinks only.
2. **Nested composite actions** — taint forwarded from an outer composite to an
   inner one; Caminus follows a single call hop.
3. **Local JavaScript actions** — untrusted input reaching a shell inside a local
   `node20` action's `index.js`; Caminus does not analyze JS.

Further catalogued (not yet in the corpus): `$GITHUB_ENV` / `$GITHUB_OUTPUT`
injection consumed by a later step, cache/artifact poisoning on `workflow_run`,
and `${{ steps.*.outputs.* }}` taint laundering.

## Comparison with other scanners

A like-for-like comparison against `poutine`, `raven`, `octoscan`, and `gato-x`
runs the same corpus through each tool and maps its output to the per-case ground
truth. Status and methodology: see [`COMPARISON.md`](COMPARISON.md). Numbers are
only published for tools actually executed — no estimated or asserted figures.
