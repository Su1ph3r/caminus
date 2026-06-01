package rules

import (
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// reUntrustedCheckout matches an actions/checkout `ref:` that pins the PR head
// — i.e. the workflow deliberately checks out attacker-controlled code.
var reUntrustedCheckout = regexp.MustCompile(
	`ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)|ref:\s*\$\{\{\s*github\.head_ref`)

var reCheckoutUses = regexp.MustCompile(`uses:\s*actions/checkout`)

// PwnRequest detects the "pwn request" (Public-PPE) pattern: a workflow that
// runs on a privileged, fork-influenced trigger (pull_request_target,
// workflow_run, issue_comment) where the workflow token and secrets are
// available to code influenced by an external attacker. The High→Critical
// escalation fires when the workflow also checks out the untrusted head ref,
// which turns "secrets exposed" into "attacker code runs with secrets".
type PwnRequest struct{}

func (PwnRequest) ID() string { return "CAM-PPE-001" }

func (PwnRequest) Apply(doc *workflow.Doc) []model.Finding {
	// Privileged triggers that expose the base-repo token/secrets to runs
	// influenced by forks or arbitrary external users.
	privileged := []string{"pull_request_target", "workflow_run", "issue_comment", "issues"}
	if !doc.HasTrigger(privileged...) {
		return nil
	}

	// Find the trigger line for evidence.
	trigLine := firstLineMatching(doc, func(s string) bool {
		t := strings.TrimSpace(s)
		for _, p := range privileged {
			if strings.HasPrefix(t, p+":") || t == p || strings.Contains(t, "["+p) || strings.Contains(t, " "+p) {
				return true
			}
		}
		return false
	})

	// Does the workflow check out untrusted code?
	untrusted := -1
	for i, line := range doc.Lines {
		if reUntrustedCheckout.MatchString(line) {
			untrusted = i
			break
		}
	}
	hasCheckout := false
	for _, line := range doc.Lines {
		if reCheckoutUses.MatchString(line) {
			hasCheckout = true
			break
		}
	}

	if untrusted >= 0 {
		return []model.Finding{{
			RuleID:   "CAM-PPE-001",
			Title:    "Pwn request: privileged trigger checks out untrusted PR head",
			Severity: model.SevCritical,
			Category: model.CatPwnRequest,
			File:     doc.Path,
			Line:     untrusted + 1,
			Evidence: trim(doc.Lines[untrusted]),
			Description: "The workflow runs on a privileged trigger (it can read the base repository's " +
				"secrets and GITHUB_TOKEN) and explicitly checks out the pull request head ref. A fork " +
				"PR author controls that code, so any build/test/script step executes attacker code with " +
				"the base repo's secrets — full Poisoned Pipeline Execution.",
			Remediation: "Do not check out and execute untrusted PR code in a privileged-trigger workflow. " +
				"Split into an unprivileged `pull_request` build job and a privileged job that consumes only " +
				"validated artifacts; or gate on a manual label/approval and never run fork code with secrets.",
			Confirmable: true,
			References: []string{
				"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
			},
		}}
	}

	// Privileged trigger present but no observed untrusted checkout: still a
	// material exposure (secrets reachable on a fork-influenced run), but not a
	// confirmed code-exec primitive.
	sev := model.SevMedium
	desc := "The workflow runs on a privileged, externally influenced trigger that exposes the " +
		"base repository's secrets and a write-capable GITHUB_TOKEN. Review every step for paths " +
		"by which a fork PR or external comment could influence execution."
	if hasCheckout {
		sev = model.SevHigh
		desc = "The workflow runs on a privileged trigger and performs a checkout. If any checkout " +
			"resolves to the PR head (directly or via a default ref), this becomes a pwn request."
	}
	line := 1
	if trigLine >= 0 {
		line = trigLine + 1
	}
	return []model.Finding{{
		RuleID:      "CAM-PPE-001",
		Title:       "Privileged trigger exposes secrets to externally influenced run",
		Severity:    sev,
		Category:    model.CatPwnRequest,
		File:        doc.Path,
		Line:        line,
		Evidence:    evidenceAt(doc, trigLine),
		Description: desc,
		Remediation: "Prefer `pull_request` (no secrets) for fork-facing CI. Reserve privileged triggers " +
			"for trusted automation and scope `permissions:` to the minimum.",
		Confirmable: false,
		References: []string{
			"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
		},
	}}
}
