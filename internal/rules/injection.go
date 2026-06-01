package rules

import (
	"fmt"
	"regexp"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// untrustedExpr lists GitHub Actions expression contexts whose values are
// attacker-controllable on a fork PR / issue / comment / discussion, and which
// are the classic sources for expression-injection (CICD-SEC-4). When one of
// these is interpolated into a `run:` shell, an attacker can break out of the
// intended command and execute arbitrary code on the runner.
//
// Reference: GitHub Security Lab, "Keeping your GitHub Actions and workflows
// secure: Untrusted input".
var untrustedExpr = []*regexp.Regexp{
	regexp.MustCompile(`github\.event\.issue\.title`),
	regexp.MustCompile(`github\.event\.issue\.body`),
	regexp.MustCompile(`github\.event\.pull_request\.title`),
	regexp.MustCompile(`github\.event\.pull_request\.body`),
	regexp.MustCompile(`github\.event\.pull_request\.head\.ref`),
	regexp.MustCompile(`github\.event\.pull_request\.head\.label`),
	regexp.MustCompile(`github\.event\.comment\.body`),
	regexp.MustCompile(`github\.event\.review\.body`),
	regexp.MustCompile(`github\.event\.review_comment\.body`),
	regexp.MustCompile(`github\.event\.discussion\.title`),
	regexp.MustCompile(`github\.event\.discussion\.body`),
	regexp.MustCompile(`github\.event\.pages\.[^ ]*\.page_name`),
	regexp.MustCompile(`github\.event\.commits\.[^ ]*\.message`),
	regexp.MustCompile(`github\.event\.commits\.[^ ]*\.author\.(?:name|email)`),
	regexp.MustCompile(`github\.event\.head_commit\.message`),
	regexp.MustCompile(`github\.event\.head_commit\.author\.(?:name|email)`),
	regexp.MustCompile(`github\.head_ref`),
}

// reExprWrap confirms the match sits inside a ${{ ... }} expression on the line.
var reExprWrap = regexp.MustCompile(`\$\{\{[^}]*\}\}`)

// ExpressionInjection flags untrusted expression contexts interpolated directly
// into a `run:` shell command — the high-confidence, dynamically-confirmable
// case for expression injection (CICD-SEC-4).
//
// It deliberately does NOT flag the same expression when it is routed through an
// intermediate `env:` variable, because that (with shell quoting) is the
// recommended remediation; flagging it would false-positive on best practice.
// Detecting unsafe *use* of an env-routed value requires dataflow and is
// tracked for a later milestone (see DESIGN.md §Roadmap).
type ExpressionInjection struct{}

func (ExpressionInjection) ID() string { return "CAM-INJ-001" }

func (ExpressionInjection) Apply(doc *workflow.Doc) []model.Finding {
	var out []model.Finding
	for i, line := range doc.Lines {
		if !reExprWrap.MatchString(line) || !doc.InRunContext(i) {
			continue
		}
		for _, rx := range untrustedExpr {
			loc := rx.FindString(line)
			if loc == "" {
				continue
			}
			out = append(out, model.Finding{
				RuleID:   "CAM-INJ-001",
				Title:    fmt.Sprintf("Untrusted input %q interpolated into a run: shell command", loc),
				Severity: model.SevCritical,
				Category: model.CatInjection,
				File:     doc.Path,
				Line:     i + 1,
				Evidence: trim(line),
				Description: "An attacker-controllable expression context is interpolated directly into a " +
					"run: shell step. On a fork pull request, issue, comment, or discussion, the attacker " +
					"controls this value and can inject shell metacharacters to run arbitrary code on the " +
					"runner with the workflow's token and secrets.",
				Remediation: "Pass untrusted input through an intermediate environment variable and " +
					"reference it with shell quoting (e.g. env: TITLE: ${{ github.event.issue.title }} " +
					"then \"$TITLE\"); never interpolate ${{ ... }} straight into run:.",
				Confirmable: true,
				References: []string{
					"https://securitylab.github.com/resources/github-actions-untrusted-input/",
					"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
				},
			})
			break // one finding per line is enough; avoid duplicate noise
		}
	}
	return out
}
