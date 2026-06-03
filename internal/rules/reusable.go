package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// Reusable-workflow injection (CAM-PPE-003).
//
// A caller workflow on an attacker-influenced trigger invokes a LOCAL reusable
// workflow (jobs.<id>.uses: ./.github/workflows/wf.yml) and passes an untrusted
// expression to it through `with:`. The called workflow then interpolates that
// input (${{ inputs.<name> }}) directly into a run: shell. The injection sink is
// in a *different file* the caller hands execution to — invisible to a scan of
// either file alone, because the taint crosses the call boundary.
//
// This mirrors CAM-INJ-001 (untrusted expression → run:) one workflow-hop out,
// with the same file-resolution + precision discipline as CAM-PPE-002: a local
// `./`-prefixed target only (a remote org/repo@ref lives in another repository,
// cannot be read from disk, and is the supply-chain rule's concern); an absent
// target yields silence (no speculative FP); a present-but-unreadable target is
// surfaced as UNASSESSED rather than scored clean.
//
// Like CAM-INJ-001, the sink test is presence of `${{ inputs.<tainted> }}` in a
// run: context: GitHub substitutes the expression textually into the script
// before the shell runs, so YAML/shell quoting does not neutralize it — direct
// interpolation of a tainted input is unsafe regardless of quoting. (Env-routing
// the input inside the callee and then using it unquoted is a deeper hop tracked
// as a follow-up; this increment covers the direct-interpolation sink.)
type ReusableWorkflowInjection struct{}

func (ReusableWorkflowInjection) ID() string { return "CAM-PPE-003" }

// reReusableUses matches a job-level local reusable-workflow reference:
//
//	uses: ./.github/workflows/reusable.yml
//
// Only a repo-local (`./`-prefixed) .yml/.yaml target is matched; GitHub requires
// local reusable workflows to start with `./`. Remote `org/repo/...@ref`
// references are the supply-chain rule's concern (another repo, unreadable here).
var reReusableUses = regexp.MustCompile(`^(\s*)(?:-\s+)?uses:\s*["']?(\./[^\s"'#]+\.ya?ml)["']?\s*$`)

// reInputName matches a workflow_call input name. Unlike shell-variable names,
// GitHub action/workflow input ids may contain hyphens, so the name class is
// wider than reMapEntry's identifier form.
var reInputName = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$`)

// reInputsRef matches a reference to a workflow_call input, `inputs.<name>`,
// inside the called workflow (the sink side). Hyphens allowed (see reInputName).
var reInputsRef = regexp.MustCompile(`inputs\.([A-Za-z_][A-Za-z0-9_-]*)`)

// reWithFlow matches the single-line flow-mapping form `with: { a: x, b: y }`.
var reWithFlow = regexp.MustCompile(`^\s*(?:-\s+)?with:\s*\{(.*)\}\s*$`)

// reusableCall is a job-level invocation of a local reusable workflow, with the
// set of input names the caller populated with an untrusted expression.
type reusableCall struct {
	Line    int             // 1-based line of the uses: in the caller
	Path    string          // repo-relative path to the called workflow (as written)
	Tainted map[string]bool // input names fed an untrusted ${{ github.event.* }} value
}

func (ReusableWorkflowInjection) Apply(doc *workflow.Doc) []model.Finding {
	// The `with:` value is only attacker-controlled under an attacker-influenced
	// trigger; gate exactly as the indirect rules do.
	if !anyTrigger(doc.Triggers(), indirectTriggers) {
		return nil
	}
	calls := reusableCallsFrom(doc)
	if len(calls) == 0 {
		return nil
	}
	root := repoRootOf(doc.Path)

	var out []model.Finding
	for _, call := range calls {
		if len(call.Tainted) == 0 {
			continue // caller passes nothing untrusted to this workflow
		}
		data, real, st := readConfined(root, call.Path)
		switch st {
		case rsAbsent:
			continue // called workflow not on disk — silence, no speculative FP
		case rsUnreadable:
			out = append(out, reusableUnassessed(doc.Path, call, real))
			continue
		}
		callee := workflow.Parse(real, data)
		for _, site := range scanReusableCallee(callee, call.Tainted) {
			out = append(out, model.Finding{
				RuleID:   "CAM-PPE-003",
				Title:    fmt.Sprintf("Reusable-workflow injection: untrusted input %q reaches a run: in called workflow %s", site.Input, shortRel(root, site.File)),
				Severity: model.SevCritical,
				Category: model.CatPPEIndirect,
				File:     site.File,
				Line:     site.Line,
				Evidence: site.Code,
				Description: "The caller workflow runs on an attacker-influenced trigger and passes an untrusted " +
					"expression to the local reusable workflow " + shortRel(root, site.File) + " through its " +
					"`with:` input " + site.Input + " (invoked at " + doc.Path + ":" + fmt.Sprint(call.Line) + "). " +
					"The called workflow then interpolates ${{ inputs." + site.Input + " }} directly into a run: " +
					"shell. GitHub substitutes the expression into the script before the shell runs, so an " +
					"attacker controls the value and injects commands on the runner with the workflow's token and " +
					"secrets — expression injection across the reusable-workflow call boundary, which a scan of " +
					"either file alone cannot see.",
				Remediation: "Do not pass attacker-controllable expressions into a reusable workflow that " +
					"interpolates an input into run:. In the called workflow, route the input through an " +
					"intermediate env: variable and reference it quoted (\"$VAR\"); validate the value before " +
					"use. Treat any reusable workflow invoked by a privileged-trigger caller as part of the " +
					"trusted execution surface.",
				Confirmable: true,
				References: []string{
					"https://securitylab.github.com/resources/github-actions-untrusted-input/",
					"https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow",
					"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
				},
			})
		}
	}
	return out
}

// reusableCallsFrom finds every job-level local reusable-workflow invocation in
// the caller and, for each, the input names it feeds an untrusted expression.
func reusableCallsFrom(doc *workflow.Doc) []reusableCall {
	var out []reusableCall
	for i := range doc.Lines {
		m := reReusableUses.FindStringSubmatch(doc.Lines[i])
		if m == nil {
			continue
		}
		indent := len(m[1])
		out = append(out, reusableCall{
			Line:    i + 1,
			Path:    m[2],
			Tainted: taintedWithInputs(doc.Lines, i, indent),
		})
	}
	return out
}

// taintedWithInputs returns the input names whose `with:` value interpolates an
// untrusted expression, for the job whose `uses:` is at usesIdx/indent. The
// `with:` block is a sibling of `uses:` at the same indent; its entries sit one
// level deeper. Both directions of the job body are searched because YAML map
// order is not guaranteed (with: may precede or follow uses:).
func taintedWithInputs(lines []string, usesIdx, indent int) map[string]bool {
	names := map[string]bool{}
	lo, hi := jobContentBounds(lines, usesIdx, indent)
	for i := lo; i <= hi; i++ {
		if fm := reWithFlow.FindStringSubmatch(lines[i]); fm != nil && indentOfLine(lines[i]) == indent {
			collectFlowInputs(fm[1], names)
			continue
		}
		if indentOfLine(lines[i]) != indent || strings.TrimSpace(lines[i]) != "with:" {
			continue
		}
		// Block form: collect entries indented deeper than `with:`.
		for j := i + 1; j <= hi; j++ {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if indentOfLine(lines[j]) <= indent {
				break // dedented out of the with: block
			}
			if em := reInputName.FindStringSubmatch(lines[j]); em != nil && valueIsUntrusted(em[2]) {
				names[em[1]] = true
			}
		}
	}
	return names
}

// collectFlowInputs parses the inner text of a flow-mapping with (`a: x, b: y`)
// and records each input whose value is untrusted. As in collectFlowEnv,
// splitting on commas is sufficient because the untrusted expression contexts
// carry no top-level commas; a value that splits wrong simply fails to match an
// untrusted pattern rather than recording a wrong name.
func collectFlowInputs(inner string, names map[string]bool) {
	for _, entry := range strings.Split(inner, ",") {
		if em := reInputName.FindStringSubmatch(entry); em != nil && valueIsUntrusted(em[2]) {
			names[em[1]] = true
		}
	}
}

// jobContentBounds returns the inclusive line-index span of the contiguous block
// at indent >= the job-content indent around idx — i.e. the body of one job.
// Blank/comment lines do not break the span; a non-blank line at a shallower
// indent does.
func jobContentBounds(lines []string, idx, indent int) (lo, hi int) {
	lo, hi = idx, idx
	for i := idx - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if indentOfLine(lines[i]) < indent {
			break
		}
		lo = i
	}
	for i := idx + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if indentOfLine(lines[i]) < indent {
			break
		}
		hi = i
	}
	return lo, hi
}

// calleeSite is an unsafe use of a tainted input in the called workflow.
type calleeSite struct {
	File  string
	Line  int
	Input string
	Code  string
}

// scanReusableCallee finds run-context lines in the called workflow that
// interpolate a tainted input (${{ inputs.<name> }}). Mirrors CAM-INJ-001's
// precision: an expression wrapper present on a run-context line, with the
// reference naming a tainted input.
func scanReusableCallee(callee *workflow.Doc, tainted map[string]bool) []calleeSite {
	var out []calleeSite
	for i, line := range callee.Lines {
		if !reExprWrap.MatchString(line) || !callee.InRunContext(i) {
			continue
		}
		for _, m := range reInputsRef.FindAllStringSubmatch(line, -1) {
			if tainted[m[1]] {
				out = append(out, calleeSite{File: callee.Path, Line: i + 1, Input: m[1], Code: trim(line)})
				break // one finding per line is enough
			}
		}
	}
	return out
}

// reusableUnassessed reports that a called reusable workflow was present but
// could not be read, so its injection surface was not assessed. Info severity
// (below the default gate) so it never breaks a CI gate, but it is recorded so
// the scanner does not silently report "clean" on a path it failed to analyze.
func reusableUnassessed(callerPath string, call reusableCall, real string) model.Finding {
	return model.Finding{
		RuleID:   "CAM-PPE-003",
		Title:    "Reusable workflow could not be analyzed — injection coverage incomplete",
		Severity: model.SevInfo,
		Category: model.CatPPEIndirect,
		File:     real,
		Line:     0,
		Description: "The caller invokes a local reusable workflow (at " + callerPath + ":" + fmt.Sprint(call.Line) +
			") and passes it untrusted input, but Caminus could not read the called workflow, so it was NOT " +
			"assessed for injection. Treat this path as UNKNOWN rather than clean: fix the file's readability " +
			"and re-scan, or review it manually.",
		Remediation: "Ensure the referenced reusable workflow is readable so it can be analyzed; a present-but-" +
			"unreadable file is a coverage gap, not a clean result.",
		Confirmable: false,
	}
}
