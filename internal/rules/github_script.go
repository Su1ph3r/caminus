package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// github-script injection (CAM-INJ-003).
//
// actions/github-script runs its `script:` input as JavaScript with the workflow
// token. An untrusted ${{ github.event.* }} expression interpolated into that
// script is expression injection exactly like the run: case (CAM-INJ-001) — GitHub
// substitutes the value into the script source before Node evaluates it — but the
// sink is a JS context, not a shell, so the run:-only rules never see it. This is
// the most common injection sink Caminus's run: model missed; octoscan flags it,
// and it appeared on the benchmark's coverage frontier.
type GitHubScriptInjection struct{}

func (GitHubScriptInjection) ID() string { return "CAM-INJ-003" }

// reGitHubScriptUses matches a step invoking actions/github-script (any ref).
var reGitHubScriptUses = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*["']?actions/github-script@`)

// reScriptKey matches a `script:` input key and captures any inline value.
var reScriptKey = regexp.MustCompile(`^\s*script:\s*(.*)$`)

func (GitHubScriptInjection) Apply(doc *workflow.Doc) []model.Finding {
	var out []model.Finding
	for i := range doc.Lines {
		if !reGitHubScriptUses.MatchString(doc.Lines[i]) {
			continue
		}
		for _, site := range githubScriptSites(doc.Lines, i) {
			out = append(out, model.Finding{
				RuleID:   "CAM-INJ-003",
				Title:    fmt.Sprintf("Untrusted input %q interpolated into an actions/github-script script", site.name),
				Severity: model.SevCritical,
				Category: model.CatInjection,
				File:     doc.Path,
				Line:     site.line,
				Evidence: trim(site.text),
				Description: "An attacker-controllable expression context is interpolated into an " +
					"actions/github-script `script:`, which is evaluated as JavaScript with the workflow's token. " +
					"GitHub substitutes the expression into the script source before Node runs it, so on a fork " +
					"pull request, issue, or comment the attacker controls this value and can inject JavaScript " +
					"(and from there shell commands) running with the workflow's token and secrets — the same " +
					"impact as run: injection, in a sink a shell-only scan does not model.",
				Remediation: "Do not interpolate ${{ ... }} into a github-script `script:`. Pass untrusted input " +
					"through the `env:` map and read it with `process.env` inside the script (e.g. env: TITLE: " +
					"${{ github.event.pull_request.title }} then process.env.TITLE), which is not evaluated as code.",
				Confirmable: true,
				References: []string{
					"https://securitylab.github.com/resources/github-actions-untrusted-input/",
					"https://github.com/actions/github-script#use-env-as-input",
					"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
				},
			})
		}
	}
	return out
}

type scriptSite struct {
	line int
	text string
	name string
}

// githubScriptSites returns the lines of the github-script step's `script:` input
// (inline value or block-scalar body) that interpolate an untrusted expression.
func githubScriptSites(lines []string, usesIdx int) []scriptSite {
	lo, hi, kc := stepSpan(lines, usesIdx)
	var out []scriptSite
	for i := lo; i <= hi; i++ {
		m := reScriptKey.FindStringSubmatch(lines[i])
		if m == nil || keyColumn(lines[i]) <= kc {
			continue // `script:` is a with: entry, deeper than the step key column
		}
		inline := strings.TrimSpace(m[1])
		if inline != "" && !strings.HasPrefix(inline, "|") && !strings.HasPrefix(inline, ">") {
			if name, ok := firstUntrustedExpr(lines[i]); ok {
				out = append(out, scriptSite{line: i + 1, text: lines[i], name: name})
			}
			continue
		}
		// Block scalar: scan the body (lines indented past the script: key).
		scriptIndent := keyColumn(lines[i])
		for j := i + 1; j <= hi; j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if keyColumn(lines[j]) <= scriptIndent {
				break // dedented out of the block scalar
			}
			if name, ok := firstUntrustedExpr(lines[j]); ok {
				out = append(out, scriptSite{line: j + 1, text: lines[j], name: name})
			}
		}
	}
	return out
}

// firstUntrustedExpr returns the first untrusted expression context on a line
// that also carries a ${{ }} wrapper (matching CAM-INJ-001's precision).
func firstUntrustedExpr(line string) (string, bool) {
	if !reExprWrap.MatchString(line) {
		return "", false
	}
	for _, rx := range untrustedExpr {
		if s := rx.FindString(line); s != "" {
			return s, true
		}
	}
	return "", false
}

// stepSpan returns the inclusive line span [lo,hi] of the YAML list item (step)
// containing usesIdx, plus the key column its keys share. Dash-aware: a list
// item's keys align at the same column whether or not the `- ` sits on the line,
// so siblings inside one `- ` item are found regardless of which key has the dash.
func stepSpan(lines []string, usesIdx int) (lo, hi, keyCol int) {
	keyCol = keyColumn(lines[usesIdx])
	dashCol := -1
	lo = usesIdx
	for i := usesIdx; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if keyColumn(lines[i]) < keyCol {
			break
		}
		if hasListDash(lines[i]) && keyColumn(lines[i]) == keyCol {
			dashCol = leadingSpaces(lines[i])
			lo = i
			break
		}
	}
	if dashCol < 0 {
		return usesIdx, usesIdx, keyCol
	}
	hi = lo
	for i := lo + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if hasListDash(lines[i]) && leadingSpaces(lines[i]) == dashCol {
			break
		}
		if keyColumn(lines[i]) < keyCol {
			break
		}
		hi = i
	}
	return lo, hi, keyCol
}
