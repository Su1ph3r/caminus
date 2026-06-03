package rules

import (
	"testing"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

// supIDs returns "<rule>/<sev>" for every CAM-SUP-001 and CAM-SUP-002 finding on
// the given source, so a test can assert which supply-chain rule owns a ref.
func supIDs(src string) []string {
	doc := workflow.Parse(".github/workflows/wf.yml", []byte(src))
	var ids []string
	for _, r := range []Rule{UnpinnedAction{}, UnpinnedReusableWorkflow{}} {
		for _, f := range r.Apply(doc) {
			ids = append(ids, f.RuleID+"/"+string(f.Severity))
		}
	}
	return ids
}

const remoteReusableMutable = `name: ci
on: [push]
jobs:
  build:
    uses: acme/ci/.github/workflows/build.yml@main
`

func TestSup002_RemoteReusableMutableRef(t *testing.T) {
	ids := supIDs(remoteReusableMutable)
	if !has(ids, "CAM-SUP-002/medium") {
		t.Fatalf("a remote reusable workflow on @main should be CAM-SUP-002/medium, got %v", ids)
	}
	// Must NOT be double-reported as a CAM-SUP-001 unpinned action.
	for _, id := range ids {
		if id == "CAM-SUP-001/low" {
			t.Fatalf("reusable workflow must not also be reported by CAM-SUP-001, got %v", ids)
		}
	}
}

const remoteReusableInherit = `name: ci
on: [push]
jobs:
  build:
    uses: acme/ci/.github/workflows/build.yml@v1
    secrets: inherit
`

func TestSup002_EscalatesOnSecretsInherit(t *testing.T) {
	ids := supIDs(remoteReusableInherit)
	if !has(ids, "CAM-SUP-002/high") {
		t.Fatalf("secrets: inherit to a mutable-ref reusable workflow should escalate to High, got %v", ids)
	}
}

const remoteReusablePinned = `name: ci
on: [push]
jobs:
  build:
    uses: acme/ci/.github/workflows/build.yml@1234567890123456789012345678901234567890
`

func TestSup002_PinnedReusableIsSafe(t *testing.T) {
	if ids := supIDs(remoteReusablePinned); len(ids) != 0 {
		t.Fatalf("a SHA-pinned reusable workflow is safe; should not flag, got %v", ids)
	}
}

const stepActionMutable = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`

func TestSup001_StillOwnsStepActions(t *testing.T) {
	ids := supIDs(stepActionMutable)
	if !has(ids, "CAM-SUP-001/low") {
		t.Fatalf("a third-party step action on @v4 is still CAM-SUP-001, got %v", ids)
	}
	for _, id := range ids {
		if id == "CAM-SUP-002/medium" || id == "CAM-SUP-002/high" {
			t.Fatalf("a non-.yml step action must not be claimed by CAM-SUP-002, got %v", ids)
		}
	}
}

// localReusableNoRef — a local reusable workflow carries no @ref and must not be
// flagged by either supply-chain rule (it is CAM-PPE-003's dataflow concern).
const localReusableNoRef = `name: ci
on: [pull_request_target]
jobs:
  build:
    uses: ./.github/workflows/build.yml
`

func TestSup002_LocalReusableNotFlagged(t *testing.T) {
	if ids := supIDs(localReusableNoRef); len(ids) != 0 {
		t.Fatalf("a local reusable workflow (no @ref) is not a supply-chain pinning issue, got %v", ids)
	}
}
