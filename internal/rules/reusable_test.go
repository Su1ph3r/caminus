package rules

import (
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

// reusableFindings loads the caller workflow and returns the CAM-PPE-003
// findings (id + severity) the reusable-workflow rule produces.
func reusableFindings(t *testing.T, root string) []string {
	t.Helper()
	doc, err := workflow.Load(filepath.Join(root, ".github", "workflows", "wf.yml"))
	if err != nil {
		t.Fatalf("load workflow: %v", err)
	}
	var ids []string
	for _, f := range (ReusableWorkflowInjection{}).Apply(doc) {
		ids = append(ids, f.RuleID+"/"+string(f.Severity))
	}
	return ids
}

const callerUntrustedWith = `name: ci
on:
  pull_request_target:
    types: [opened]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ github.event.pull_request.title }}
      safe: hello
    secrets: inherit
`

// calleeInterpolates uses the input directly in a run: — the injection sink.
const calleeInterpolates = `on:
  workflow_call:
    inputs:
      title:
        required: true
        type: string
      safe:
        required: false
        type: string
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks ${{ inputs.title }}"
`

func TestReusable_UntrustedInputReachesRun(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerUntrustedWith,
		".github/workflows/reusable.yml": calleeInterpolates,
	})
	ids := reusableFindings(t, root)
	if !has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("expected CAM-PPE-003/critical for untrusted input interpolated into run:, got %v", ids)
	}
}

// calleeUsesOnlySafeInput interpolates a non-tainted input — must not flag.
const calleeUsesOnlySafeInput = `on:
  workflow_call:
    inputs:
      title: { type: string }
      safe: { type: string }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.safe }}"
`

func TestReusable_SafeInputNotFlagged(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerUntrustedWith,
		".github/workflows/reusable.yml": calleeUsesOnlySafeInput,
	})
	if ids := reusableFindings(t, root); has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("only the non-tainted input is used in the callee; should NOT flag, got %v", ids)
	}
}

// calleeNoRunUse references the input in a non-run context (an if:) — not a sink.
const calleeNoRunUse = `on:
  workflow_call:
    inputs:
      title: { type: string }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ inputs.title != '' }}
        run: echo done
`

func TestReusable_InputOutsideRunNotFlagged(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerUntrustedWith,
		".github/workflows/reusable.yml": calleeNoRunUse,
	})
	if ids := reusableFindings(t, root); has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("input used only in if: (not a run: shell) is not an injection sink, got %v", ids)
	}
}

// callerSafeWith passes only a static value — nothing untrusted crosses.
const callerSafeWith = `name: ci
on:
  pull_request_target:
    types: [opened]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with:
      title: hardcoded-release
`

func TestReusable_NoUntrustedInputNoFinding(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerSafeWith,
		".github/workflows/reusable.yml": calleeInterpolates,
	})
	if ids := reusableFindings(t, root); has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("caller passes only a static value; nothing untrusted crosses the boundary, got %v", ids)
	}
}

// callerSafeTrigger is a non-attacker trigger — the with: value is not attacker
// controlled, so even a tainted-looking expression must not flag.
const callerSafeTrigger = `name: ci
on:
  push:
    branches: [main]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ github.event.pull_request.title }}
`

func TestReusable_NonAttackerTriggerNotFlagged(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerSafeTrigger,
		".github/workflows/reusable.yml": calleeInterpolates,
	})
	if ids := reusableFindings(t, root); has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("push trigger does not carry attacker-controlled PR fields; should NOT flag, got %v", ids)
	}
}

func TestReusable_AbsentCalleeIsSilent(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": callerUntrustedWith,
		// reusable.yml intentionally absent
	})
	if ids := reusableFindings(t, root); len(ids) != 0 {
		t.Fatalf("absent reusable workflow must yield no finding (no speculative FP), got %v", ids)
	}
}

// calleeEnvRoutedUnquoted routes the input through an env: var, then uses it
// unquoted in run: — the second-hop env-routed sink.
const calleeEnvRoutedUnquoted = `on:
  workflow_call:
    inputs:
      title: { type: string }
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      T: ${{ inputs.title }}
    steps:
      - run: echo building $T
`

func TestReusable_EnvRoutedUnquotedInCallee(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerUntrustedWith,
		".github/workflows/reusable.yml": calleeEnvRoutedUnquoted,
	})
	if ids := reusableFindings(t, root); !has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("env-routed tainted input used unquoted in callee run: should flag, got %v", ids)
	}
}

// calleeEnvRoutedQuoted routes through env: and quotes the use — recommended-safe.
const calleeEnvRoutedQuoted = `on:
  workflow_call:
    inputs:
      title: { type: string }
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      T: ${{ inputs.title }}
    steps:
      - run: echo building "$T"
`

func TestReusable_EnvRoutedQuotedIsSafe(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerUntrustedWith,
		".github/workflows/reusable.yml": calleeEnvRoutedQuoted,
	})
	if ids := reusableFindings(t, root); has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("quoted \"$T\" in the callee is the recommended-safe form; should NOT flag, got %v", ids)
	}
}

// callerFlowWith uses the inline flow-mapping with: form.
const callerFlowWith = `name: ci
on: [pull_request_target]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with: { title: ${{ github.event.pull_request.title }} }
`

func TestReusable_FlowMappingWith(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerFlowWith,
		".github/workflows/reusable.yml": calleeInterpolates,
	})
	if ids := reusableFindings(t, root); !has(ids, "CAM-PPE-003/critical") {
		t.Fatalf("flow-mapping with: should be parsed for taint, got %v", ids)
	}
}

// callerRemoteUses references a remote reusable workflow (another repo) — out of
// scope for the dataflow rule (cannot read it); must not be treated as local.
const callerRemoteUses = `name: ci
on: [pull_request_target]
jobs:
  greet:
    uses: acme/ci/.github/workflows/reusable.yml@main
    with:
      title: ${{ github.event.pull_request.title }}
`

func TestReusable_RemoteUsesNotResolvedAsLocal(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerRemoteUses,
		".github/workflows/reusable.yml": calleeInterpolates, // present but not the target
	})
	if ids := reusableFindings(t, root); len(ids) != 0 {
		t.Fatalf("a remote org/repo@ref reusable workflow is not a local file; should not flag, got %v", ids)
	}
}
