#!/usr/bin/env python3
"""Scores other scanners against the Caminus corpus ground truth.

Reads manifest.jsonl (ground truth) and results-<tool>.jsonl (the rule IDs each
tool reported per case, produced by compare_<tool>.sh), maps each tool's rule
taxonomy onto the corpus vulnerability classes, and prints a per-case comparison
table plus a precision/recall summary. Honest by construction: only tools whose
results file exists are scored.

Usage:  python3 benchmark/score_comparison.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# Maps a tool rule ID -> the set of Caminus rule classes it is equivalent to, so
# "did the tool detect this case?" = "did it fire a rule mapping to the case's
# expected class?". Only genuine equivalences are listed; a tool rule with no
# Caminus counterpart (or vice versa) simply does not match, which is the point.
POUTINE_MAP = {
    "injection": {"CAM-INJ-001", "CAM-INJ-002"},
    "untrusted_checkout_exec": {"CAM-PPE-001"},
    "pr_runs_on_self_hosted": {"CAM-RUN-001"},
    "debug_enabled": {"CAM-GL-DBG-001"},
    # default_permissions_on_risky_events, unpinnable_action, job_all_secrets:
    # related themes but NOT equivalent to a Caminus rule (different semantics),
    # so they are intentionally unmapped — see COMPARISON.md.
}

# octoscan's expression-injection fires on an untrusted ${{ }} in run:, in a step
# with:, or in script: — so it maps to the whole injection family (including the
# reusable/composite cases, where it flags the input side). It does NOT trace
# whether the action actually uses the input, which is why it both catches the
# gap cases and false-positives on safe-composite-safeinput (see COMPARISON.md).
OCTOSCAN_MAP = {
    "expression-injection": {"CAM-INJ-001", "CAM-INJ-002", "CAM-PPE-003", "CAM-PPE-004"},
    "dangerous-checkout": {"CAM-PPE-001"},
    "runner-label": {"CAM-RUN-001"},
    # local-action (informational), dangerous-write ($GITHUB_ENV — no Caminus
    # rule), repo-jacking, etc.: intentionally unmapped.
}

TOOLS = {
    "poutine": {"map": POUTINE_MAP, "github_only": False},
    "octoscan": {"map": OCTOSCAN_MAP, "github_only": True},
}


def detected(tool_rules, expect, mapping):
    """True if any tool rule maps to any expected Caminus class."""
    covered = set()
    for r in tool_rules:
        covered |= mapping.get(r, set())
    return bool(covered & set(expect))


def main():
    manifest = {c["id"]: c for c in load_jsonl(os.path.join(HERE, "manifest.jsonl"))}

    for tool, cfg in TOOLS.items():
        mapping, github_only = cfg["map"], cfg["github_only"]
        results_path = os.path.join(HERE, f"results-{tool}.jsonl")
        if not os.path.exists(results_path):
            print(f"# {tool}: results-{tool}.jsonl not found — skipped (run compare_{tool}.sh)")
            continue
        results = {r["id"]: r["rules"] for r in load_jsonl(results_path)}

        tp = fn = fp = tn = gap_caught = gap_missed = na = 0
        rows = []
        for cid, c in manifest.items():
            fired = results.get(cid, [])
            pol, gap = c["polarity"], c.get("known_gap", False)

            if github_only and c.get("platform") == "gitlab":
                rows.append((cid, pol, "gap" if gap else "-", "N/A (GitHub-only)"))
                na += 1
                continue

            det = detected(fired, c.get("expect", []), mapping)
            if pol == "vuln" and gap:
                verdict = "catches (Caminus gap!)" if det else "miss"
                gap_caught += det
                gap_missed += not det
            elif pol == "vuln":
                verdict = "detect" if det else "MISS"
                tp += det
                fn += not det
            else:  # safe
                bad = any(mapping.get(r, set()) & set(c.get("forbid", [])) for r in fired)
                verdict = "FALSE POSITIVE" if bad else "clean"
                fp += bad
                tn += not bad
            rows.append((cid, pol, "gap" if gap else "-", verdict))

        print(f"\n===== {tool} vs Caminus corpus =====")
        for cid, pol, gap, verdict in rows:
            print(f"  {cid:28s} {pol:5s} {gap:4s} {verdict}")
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        print(f"\n  TP={tp} FN={fn} FP={fp} TN={tn}  N/A={na}  gaps: {gap_missed} missed, {gap_caught} caught")
        print(f"  precision={100*prec:.0f}%  recall={100*rec:.0f}% over the corpus's covered classes (N/A excluded)")


if __name__ == "__main__":
    sys.exit(main())
