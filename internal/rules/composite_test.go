package rules

import (
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

func compositeFindings(t *testing.T, root string) []string {
	t.Helper()
	doc, err := workflow.Load(filepath.Join(root, ".github", "workflows", "wf.yml"))
	if err != nil {
		t.Fatalf("load workflow: %v", err)
	}
	var ids []string
	for _, f := range (CompositeActionInjection{}).Apply(doc) {
		ids = append(ids, f.RuleID+"/"+string(f.Severity))
	}
	return ids
}

// compositeManifestVuln interpolates the input directly into a run: step.
const compositeManifestVuln = `name: greet
inputs:
  title:
    required: true
runs:
  using: composite
  steps:
    - run: echo "Hi ${{ inputs.title }}"
      shell: bash
`

// callerStepUsesComposite — uses: is NOT the first key (name: carries the dash),
// so the uses line has no dash and with: is a sibling continuation key.
const callerStepUsesComposite = `name: ci
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: greet the author
        uses: ./.github/actions/greet
        with:
          title: ${{ github.event.pull_request.title }}
`

func TestComposite_UntrustedInputReachesRun(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":         callerStepUsesComposite,
		".github/actions/greet/action.yml": compositeManifestVuln,
	})
	if ids := compositeFindings(t, root); !has(ids, "CAM-PPE-004/critical") {
		t.Fatalf("expected CAM-PPE-004/critical for untrusted input into a composite run:, got %v", ids)
	}
}

// callerDashOnUses — the dash sits on the uses line (`- uses:`), with: follows.
const callerDashOnUses = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/greet
        with:
          title: ${{ github.event.pull_request.title }}
`

func TestComposite_DashOnUsesLine(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":         callerDashOnUses,
		".github/actions/greet/action.yml": compositeManifestVuln,
	})
	if ids := compositeFindings(t, root); !has(ids, "CAM-PPE-004/critical") {
		t.Fatalf("with: must be scoped to the step even when the dash is on the uses line, got %v", ids)
	}
}

// callerTwoSteps — a preceding step also has a with:, but feeds a DIFFERENT
// action a safe value. The taint of step 2 must not leak from step 1, and the
// safe step-1 value must not be attributed to step 2.
const callerTwoSteps = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: first
        uses: ./.github/actions/other
        with:
          note: hardcoded
      - name: second
        uses: ./.github/actions/greet
        with:
          title: ${{ github.event.pull_request.title }}
`

func TestComposite_StepScopingAcrossSiblings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":         callerTwoSteps,
		".github/actions/greet/action.yml": compositeManifestVuln,
		".github/actions/other/action.yml": "name: other\nruns:\n  using: composite\n  steps:\n    - run: echo done\n      shell: bash\n",
	})
	if ids := compositeFindings(t, root); !has(ids, "CAM-PPE-004/critical") {
		t.Fatalf("the tainted second step should flag, got %v", ids)
	}
}

func TestComposite_SafeStepNotFlagged(t *testing.T) {
	// Step 1 (other) gets a static value; its manifest interpolates an input but
	// the caller passes nothing untrusted, so it must NOT flag.
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":         callerTwoSteps,
		".github/actions/greet/action.yml": "name: greet\nruns:\n  using: composite\n  steps:\n    - run: echo safe\n      shell: bash\n",
		".github/actions/other/action.yml": "name: other\ninputs:\n  note: {}\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.note }}\"\n      shell: bash\n",
	})
	if ids := compositeFindings(t, root); has(ids, "CAM-PPE-004/critical") {
		t.Fatalf("step passing only a static value must not flag, got %v", ids)
	}
}

func TestComposite_YamlManifestExtension(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":          callerStepUsesComposite,
		".github/actions/greet/action.yaml": compositeManifestVuln, // .yaml, not .yml
	})
	if ids := compositeFindings(t, root); !has(ids, "CAM-PPE-004/critical") {
		t.Fatalf("action.yaml manifest should resolve, got %v", ids)
	}
}

func TestComposite_AbsentManifestSilent(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": callerStepUsesComposite,
		// no action manifest on disk
	})
	if ids := compositeFindings(t, root); len(ids) != 0 {
		t.Fatalf("absent composite manifest must yield no finding, got %v", ids)
	}
}

// callerReusableNotComposite — a .yml target is a reusable workflow, owned by
// CAM-PPE-003; the composite rule must not also claim it.
const callerReusableNotComposite = `name: ci
on: [pull_request_target]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ github.event.pull_request.title }}
`

func TestComposite_DoesNotClaimReusableWorkflow(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml":       callerReusableNotComposite,
		".github/workflows/reusable.yml": calleeInterpolates,
	})
	if ids := compositeFindings(t, root); len(ids) != 0 {
		t.Fatalf("a .yml reusable-workflow target is not a composite action; CAM-PPE-004 must not fire, got %v", ids)
	}
}

// callerRemoteAction references a published action (owner/repo@ref) — remote,
// out of scope for the on-disk dataflow rule.
const callerRemoteAction = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.pull_request.title }}")
`

func TestComposite_RemoteActionNotResolved(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": callerRemoteAction,
	})
	if ids := compositeFindings(t, root); len(ids) != 0 {
		t.Fatalf("a remote owner/repo@ref action is not a local composite; should not flag, got %v", ids)
	}
}
