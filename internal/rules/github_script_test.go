package rules

import (
	"testing"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

func injIDs(src string) []string {
	doc := workflow.Parse(".github/workflows/wf.yml", []byte(src))
	var ids []string
	for _, f := range (GitHubScriptInjection{}).Apply(doc) {
		ids = append(ids, f.RuleID)
	}
	return ids
}

const ghScriptInline = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.pull_request.title }}")
`

func TestGHScript_InlineUntrusted(t *testing.T) {
	if ids := injIDs(ghScriptInline); !has(ids, "CAM-INJ-003") {
		t.Fatalf("expected CAM-INJ-003 for untrusted expr in inline github-script, got %v", ids)
	}
}

const ghScriptBlock = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const t = "${{ github.event.issue.title }}"
            console.log(t)
`

func TestGHScript_BlockScalarUntrusted(t *testing.T) {
	if ids := injIDs(ghScriptBlock); !has(ids, "CAM-INJ-003") {
		t.Fatalf("expected CAM-INJ-003 for untrusted expr in a block-scalar script, got %v", ids)
	}
}

// ghScriptEnvSafe routes the value through env: and reads it via process.env —
// the recommended-safe pattern; the script: itself has no ${{ }}.
const ghScriptEnvSafe = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        env:
          TITLE: ${{ github.event.pull_request.title }}
        with:
          script: console.log(process.env.TITLE)
`

func TestGHScript_EnvRoutedIsSafe(t *testing.T) {
	if ids := injIDs(ghScriptEnvSafe); has(ids, "CAM-INJ-003") {
		t.Fatalf("env-routed github-script (process.env) is the recommended-safe form; must not flag, got %v", ids)
	}
}

// ghScriptOtherAction has a script: input on a DIFFERENT action — not eval'd as
// JS by github-script, so the rule (which is github-script-specific) must not fire.
const ghScriptOtherAction = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/other-action@v1
        with:
          script: echo "${{ github.event.pull_request.title }}"
`

func TestGHScript_OnlyGitHubScriptAction(t *testing.T) {
	if ids := injIDs(ghScriptOtherAction); has(ids, "CAM-INJ-003") {
		t.Fatalf("CAM-INJ-003 is specific to actions/github-script; must not fire on other actions, got %v", ids)
	}
}

const ghScriptStatic = `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("hello world")
`

func TestGHScript_StaticScriptNotFlagged(t *testing.T) {
	if ids := injIDs(ghScriptStatic); has(ids, "CAM-INJ-003") {
		t.Fatalf("a static script with no untrusted expression must not flag, got %v", ids)
	}
}
