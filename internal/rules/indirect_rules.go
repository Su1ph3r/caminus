package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// indirectTriggers are the attacker-influenced GitHub events that deliver
// untrusted data into the workflow run. Only when one is present can an
// env-routed untrusted value actually carry attacker input.
var indirectTriggers = []string{
	"pull_request", "pull_request_target", "issue_comment", "issues",
	"discussion", "discussion_comment", "workflow_run",
}

// IndirectPPE detects indirect Poisoned Pipeline Execution: an attacker-
// controllable value that is routed through an env: variable (the pattern the
// direct injection rule treats as safe) but then used unsafely inside a local
// file the pipeline executes — a shell script, a Makefile recipe, or a
// package.json script. The injection sink lives one file-hop out of the YAML,
// invisible to a workflow-only scan.
type IndirectPPE struct{}

func (IndirectPPE) ID() string { return "CAM-PPE-002" }

func (IndirectPPE) Apply(doc *workflow.Doc) []model.Finding {
	names, triggers := githubIndirectSources(doc)
	if !anyTrigger(triggers, indirectTriggers) {
		return nil
	}
	if len(names) == 0 {
		return nil
	}

	root := repoRootOf(doc.Path)
	refs := scriptRefsFrom(doc.Lines, doc.InRunContext)

	var out []model.Finding
	for _, ref := range refs {
		site := analyzeRef(root, ref, names)
		if site == nil {
			continue
		}
		if site.Unassessed {
			out = append(out, unassessedFinding("CAM-PPE-002", doc.Path, ref, site))
			continue
		}
		out = append(out, model.Finding{
			RuleID:   "CAM-PPE-002",
			Title:    fmt.Sprintf("Indirect PPE: untrusted %q reaches a shell in executed file %s", site.Name, shortRel(root, site.File)),
			Severity: model.SevCritical,
			Category: model.CatPPEIndirect,
			File:     site.File,
			Line:     site.Line,
			Evidence: site.Code,
			Description: "The workflow runs on an attacker-influenced trigger and routes untrusted input " +
				"into the environment variable " + site.Name + ". That value is the recommended-safe form " +
				"in the YAML — but the workflow then executes a local file (" + shortRel(root, site.File) +
				", invoked at " + doc.Path + ":" + fmt.Sprint(ref.Line) + ") which uses it unquoted or via " +
				"eval/command-substitution. An attacker controls the value and injects shell commands that " +
				"run on the runner with the workflow's token and secrets — the same impact as direct " +
				"expression injection, but in a file a workflow-only scan never reads.",
			Remediation: "Quote the variable everywhere it is used in the referenced file (\"$" + site.Name +
				"\"), never pass it to eval or an unquoted command substitution, and validate it before use. " +
				"Treat any repo file executed by a privileged-trigger pipeline as part of the trusted surface.",
			Confirmable: true,
			References: []string{
				"https://securitylab.github.com/resources/github-actions-untrusted-input/",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
			},
		})
	}
	return out
}

// InlineEnvInjection detects an attacker-controllable value that is routed
// through an env: variable (the form CAM-INJ-001 deliberately treats as safe)
// and then used UNSAFELY — unquoted, or via eval/command-substitution —
// directly in a run: shell of the same workflow. CAM-INJ-001 fires only on the
// literal ${{ github.event.* }} form, so the env-routed-but-unquoted case fell
// between it and the indirect (referenced-file) rule. This is the same-step
// dataflow completion of the injection family; no file is read.
type InlineEnvInjection struct{}

func (InlineEnvInjection) ID() string { return "CAM-INJ-002" }

func (InlineEnvInjection) Apply(doc *workflow.Doc) []model.Finding {
	names, triggers := githubIndirectSources(doc)
	if !anyTrigger(triggers, indirectTriggers) || len(names) == 0 {
		return nil
	}

	var out []model.Finding
	var seg []physLine
	flush := func() {
		for _, site := range scanShellSites(doc.Path, seg, names, false) {
			out = append(out, model.Finding{
				RuleID:   "CAM-INJ-002",
				Title:    fmt.Sprintf("Env-routed untrusted input %q used unsafely in a run: shell", site.Name),
				Severity: model.SevCritical,
				Category: model.CatInjection,
				File:     doc.Path,
				Line:     site.Line,
				Evidence: site.Code,
				Description: "The workflow runs on an attacker-influenced trigger and routes untrusted input " +
					"into the environment variable " + site.Name + ". Routing through env: is the recommended " +
					"mitigation, but only if the value is then quoted: here it is used unquoted (or via " +
					"eval/command-substitution) in a run: shell, so an attacker controls the value and injects " +
					"shell commands on the runner with the workflow's token and secrets.",
				Remediation: "Quote the variable in the run: step (\"$" + site.Name + "\"); never use it " +
					"unquoted or pass it to eval/an unquoted command substitution.",
				Confirmable: true,
				References: []string{
					"https://securitylab.github.com/resources/github-actions-untrusted-input/",
					"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
				},
			})
		}
		seg = nil
	}
	// Group consecutive run-context lines into segments so heredoc/continuation
	// handling stays within a single run: block. A blank or comment-only line
	// inside a `run: |` block scalar reports InRunContext == false (it dedents to
	// column 0), but it is still part of the script — flushing on it would split
	// the segment mid-heredoc and rescan body data as commands (a false positive).
	// So such lines stay in an open segment; scanShellSites skips them internally.
	// They never merge two distinct run: blocks, because the intervening step keys
	// (`- run:`, `- name:`, …) are non-blank non-run lines that do flush.
	for i := range doc.Lines {
		switch {
		case doc.InRunContext(i):
			seg = append(seg, physLine{idx: i, text: doc.Lines[i]})
		case len(seg) > 0 && isBlankOrComment(doc.Lines[i]):
			seg = append(seg, physLine{idx: i, text: doc.Lines[i]})
		default:
			flush()
		}
	}
	flush()
	return out
}

// shortRel renders a referenced-file path relative to the repo root for readable
// titles, falling back to the full path.
func shortRel(root, full string) string {
	if r, err := relPath(root, full); err == nil {
		return r
	}
	return full
}

// githubIndirectSources returns the set of env names carrying untrusted input
// and the workflow triggers. It prefers the structural parser (built with
// -tags yaml, which resolves anchors/aliases and flow forms); otherwise it uses
// the line model.
func githubIndirectSources(doc *workflow.Doc) (map[string]bool, []string) {
	if names, triggers, ok := structuredGitHubSources(doc); ok {
		return names, triggers
	}
	triggers := doc.Triggers()
	names := collectUntrustedEnvLineModel(doc)
	if hasAny(triggers, "pull_request", "pull_request_target") {
		// GitHub injects GITHUB_HEAD_REF (the source branch name, attacker-named)
		// into the environment on pull-request events.
		names["GITHUB_HEAD_REF"] = true
	}
	return names, triggers
}

// reEnvKey matches an `env:` block opener (workflow, job, or step). The block
// form has nothing after the colon; the inline flow form `env: { … }` carries
// the map on the same line and is handled separately.
var reEnvKey = regexp.MustCompile(`^(\s*)(?:-\s+)?env:\s*$`)

// reEnvFlow matches the single-line flow-mapping form: `env: { A: x, B: y }`.
var reEnvFlow = regexp.MustCompile(`^\s*(?:-\s+)?env:\s*\{(.*)\}\s*$`)

// reMapEntry matches a `NAME: value` mapping entry. Names are shell/identifier
// form ([A-Za-z_][A-Za-z0-9_]*) — a `-` cannot appear in a referenced shell
// variable, so allowing it would only record inert entries.
var reMapEntry = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$`)

// collectUntrustedEnvLineModel walks env: blocks (block and single-line flow
// form) and records every variable whose value interpolates an untrusted
// expression context. It intentionally scans all env: scopes in the file
// (workflow/job/step); the structural parser refines this to the scope actually
// visible to each step and additionally resolves anchors/aliases and multi-line
// flow maps the line model cannot connect.
func collectUntrustedEnvLineModel(doc *workflow.Doc) map[string]bool {
	names := map[string]bool{}
	for i := 0; i < len(doc.Lines); i++ {
		if fm := reEnvFlow.FindStringSubmatch(doc.Lines[i]); fm != nil {
			collectFlowEnv(fm[1], names)
			continue
		}
		m := reEnvKey.FindStringSubmatch(doc.Lines[i])
		if m == nil {
			continue
		}
		envIndent := len(m[1])
		for j := i + 1; j < len(doc.Lines); j++ {
			t := strings.TrimSpace(doc.Lines[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if indentOfLine(doc.Lines[j]) <= envIndent {
				break // dedented out of the env: block
			}
			em := reMapEntry.FindStringSubmatch(doc.Lines[j])
			if em == nil {
				continue
			}
			if valueIsUntrusted(em[2]) {
				names[em[1]] = true
			}
		}
	}
	return names
}

// collectFlowEnv parses the inner text of a flow-mapping env (`A: x, B: y`).
// Splitting on commas is sufficient here because GitHub expressions
// `${{ … }}` contain no top-level commas in the contexts this rule cares about
// (event field accesses); a value with an embedded comma would simply not match
// an untrusted pattern, never produce a wrong NAME.
func collectFlowEnv(inner string, names map[string]bool) {
	for _, entry := range strings.Split(inner, ",") {
		em := reMapEntry.FindStringSubmatch(entry)
		if em == nil {
			continue
		}
		if valueIsUntrusted(em[2]) {
			names[em[1]] = true
		}
	}
}

// unassessedFinding reports that a referenced, pipeline-executed file was
// present but could not be read or parsed. It is emitted at Info severity (below
// the default `--gate high`, so it never breaks an existing CI gate) precisely
// so the scanner does not silently report "no finding" on a path it failed to
// analyze: the path is UNKNOWN, not clean.
func unassessedFinding(ruleID, pipelinePath string, ref scriptRef, site *unsafeSite) model.Finding {
	return model.Finding{
		RuleID:   ruleID,
		Title:    "Referenced file could not be analyzed — indirect-PPE coverage incomplete",
		Severity: model.SevInfo,
		Category: model.CatPPEIndirect,
		File:     site.File,
		Line:     site.Line,
		Evidence: site.Code,
		Description: "The pipeline executes a local file (invoked at " + pipelinePath + ":" +
			fmt.Sprint(ref.Line) + "), but Caminus could not read or parse it, so it was NOT assessed for " +
			"indirect injection. Treat this path as UNKNOWN rather than clean: fix the file's readability " +
			"(permissions, encoding, valid JSON) and re-scan, or review it manually.",
		Remediation: "Ensure the referenced file is readable and well-formed so it can be analyzed; " +
			"a present-but-unreadable file is a coverage gap, not a clean result.",
		Confirmable: false,
	}
}

// valueIsUntrusted reports whether a YAML scalar interpolates an untrusted
// ${{ github.event.* }} / github.head_ref expression context.
func valueIsUntrusted(v string) bool {
	if !reExprWrap.MatchString(v) {
		return false
	}
	for _, rx := range untrustedExpr {
		if rx.MatchString(v) {
			return true
		}
	}
	return false
}

func isBlankOrComment(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.HasPrefix(t, "#")
}

func indentOfLine(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
			continue
		}
		break
	}
	return n
}

func anyTrigger(have, want []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if set[w] {
			return true
		}
	}
	return false
}

func hasAny(have []string, want ...string) bool {
	return anyTrigger(have, want)
}
