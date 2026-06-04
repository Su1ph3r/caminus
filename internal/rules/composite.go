package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// Composite-action injection (CAM-PPE-004).
//
// The step-level sibling of CAM-PPE-003. A workflow step on an attacker-
// influenced trigger invokes a LOCAL composite action by directory
// (steps[].uses: ./.github/actions/foo) and passes an untrusted expression to it
// through `with:`. The composite action's manifest (foo/action.yml, runs.using:
// composite) then interpolates ${{ inputs.<name> }} directly into one of its
// `run:` steps. As with reusable workflows the injection sink lives in a
// different file the step hands execution to, invisible to a scan of either.
//
// Two things differ from the reusable-workflow case and are handled here:
//   - the invocation is a STEP (inside a `- ` list item), so the matching `with:`
//     must be scoped to that one step item — dash-aware bounds, not job bounds;
//   - the target is a DIRECTORY; the manifest is <dir>/action.yml or .yaml.
//
// Same precision discipline: local `./`-prefixed dir only (a remote owner/repo@ref
// action is the supply-chain rule's concern); absent manifest → silence;
// present-but-unreadable → UNASSESSED.
type CompositeActionInjection struct{}

func (CompositeActionInjection) ID() string { return "CAM-PPE-004" }

// reCompositeUses matches a step-level local composite-action reference by
// directory: `uses: ./.github/actions/foo`. A `./`-prefixed path that does NOT
// end in .yml/.yaml (those are reusable workflows, CAM-PPE-003) and carries no
// `@ref` (remote, out of scope). The leading `(?:-\s+)?` tolerates `- uses:`.
var reCompositeUses = regexp.MustCompile(`^(\s*)(?:-\s+)?uses:\s*["']?(\./[^\s"'#@]+)["']?\s*$`)

// compositeManifests are the action-manifest filenames tried under the dir.
var compositeManifests = []string{"action.yml", "action.yaml"}

func (CompositeActionInjection) Apply(doc *workflow.Doc) []model.Finding {
	if !anyTrigger(doc.Triggers(), indirectTriggers) {
		return nil
	}
	root := repoRootOf(doc.Path)

	var out []model.Finding
	for i := range doc.Lines {
		m := reCompositeUses.FindStringSubmatch(doc.Lines[i])
		if m == nil {
			continue
		}
		dir := m[2]
		if hasYAMLExt(dir) {
			continue // a `.yml`/`.yaml` target is a reusable workflow (CAM-PPE-003)
		}
		tainted := stepTaintedInputs(doc.Lines, i)
		if len(tainted) == 0 {
			continue
		}

		data, real, st, found := readManifest(root, dir)
		if !found {
			continue // no manifest on disk — silence, no speculative FP
		}
		if st == rsUnreadable {
			out = append(out, compositeUnassessed(doc.Path, i+1, dir, real))
			continue
		}
		callee := workflow.Parse(real, data)
		resolved := map[string]bool{}
		for _, site := range scanReusableCallee(callee, tainted) {
			resolved[site.Input] = true
			out = append(out, model.Finding{
				RuleID:   "CAM-PPE-004",
				Title:    fmt.Sprintf("Composite-action injection: untrusted input %q reaches a run: in action %s", site.Input, shortRel(root, site.File)),
				Severity: model.SevCritical,
				Category: model.CatPPEIndirect,
				File:     site.File,
				Line:     site.Line,
				Evidence: site.Code,
				Description: "The caller workflow runs on an attacker-influenced trigger and passes an untrusted " +
					"expression to the local composite action " + dir + " through its `with:` input " + site.Input +
					" (invoked at " + doc.Path + ":" + fmt.Sprint(i+1) + "). " + calleeSinkClause(site) +
					" An attacker controls the value and injects commands on the runner with the workflow's token " +
					"and secrets — expression injection across the composite-action call boundary, which a scan of " +
					"either file alone cannot see.",
				Remediation: "Do not pass attacker-controllable expressions into a composite action that " +
					"interpolates an input into run:. In the action, route the input through an intermediate " +
					"env: variable and reference it quoted (\"$VAR\"); validate it before use. Treat any composite " +
					"action invoked by a privileged-trigger workflow as part of the trusted execution surface.",
				Confirmable: true,
				References: []string{
					"https://securitylab.github.com/resources/github-actions-untrusted-input/",
					"https://docs.github.com/en/actions/creating-actions/creating-a-composite-action",
					"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
				},
			})
		}
		// A tainted input with no resolved run: sink is not automatically safe: the
		// action's sink may be in a context Caminus cannot read (a non-composite
		// JS/Docker action) or one hop further out (the composite forwards the input
		// to a nested action). Surface that as UNASSESSED (Info, below the gate) so
		// the path is reported as UNKNOWN rather than silently scored clean — while
		// staying silent when the input genuinely is not used (the composite
		// resolved it as safe). This is the precision-preserving close of the
		// reusable/composite coverage frontier the benchmark identified.
		for name := range tainted {
			if resolved[name] {
				continue
			}
			if reason, ok := unresolvableSink(callee, name); ok {
				out = append(out, unresolvedSinkFinding(doc, i, dir, shortRel(root, real), name, reason))
			}
		}
	}
	return out
}

// unresolvableSink reports whether a composite manifest's injection surface for
// the input `name` is one Caminus cannot resolve — so a tainted input reaching it
// is UNKNOWN, not clean. Two cases: the action is not a composite (a JS/Docker
// action whose sink Caminus does not read), or it is composite but forwards the
// input to a further `uses:` (a nested action Caminus does not follow). It returns
// false for a composite that simply does not use the input (genuinely safe), so
// no false UNASSESSED is raised on the recommended-safe shape.
func unresolvableSink(callee *workflow.Doc, name string) (string, bool) {
	using := manifestUsing(callee)
	if using != "" && using != "composite" {
		return "the action is a `" + using + "` action whose injection sink Caminus does not analyze", true
	}
	if manifestHasNestedUses(callee) && manifestReferencesInput(callee, name) {
		return "the composite forwards the input to a nested local action Caminus does not follow", true
	}
	return "", false
}

var reUsingKey = regexp.MustCompile(`^\s*using:\s*["']?([A-Za-z0-9_.-]+)`)

// manifestUsing returns the runs.using value of an action manifest ("composite",
// "node20", "docker", …), or "" if none is found.
func manifestUsing(callee *workflow.Doc) string {
	for _, line := range callee.Lines {
		if m := reUsingKey.FindStringSubmatch(line); m != nil {
			return strings.ToLower(m[1])
		}
	}
	return ""
}

var reAnyUses = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*\S`)

// manifestHasNestedUses reports whether the manifest invokes another action.
func manifestHasNestedUses(callee *workflow.Doc) bool {
	for _, line := range callee.Lines {
		if reAnyUses.MatchString(line) {
			return true
		}
	}
	return false
}

// manifestReferencesInput reports whether the manifest references inputs.<name>
// anywhere (e.g. forwarded into a nested action's with:).
func manifestReferencesInput(callee *workflow.Doc, name string) bool {
	for _, line := range callee.Lines {
		for _, m := range reInputsRef.FindAllStringSubmatch(line, -1) {
			if m[1] == name {
				return true
			}
		}
	}
	return false
}

// unresolvedSinkFinding builds the CAM-PPE-005 UNASSESSED finding.
func unresolvedSinkFinding(doc *workflow.Doc, usesIdx int, dir, manifest, name, reason string) model.Finding {
	return model.Finding{
		RuleID:   "CAM-PPE-005",
		Title:    "Untrusted input reaches a local action whose injection sink could not be analyzed",
		Severity: model.SevInfo,
		Category: model.CatPPEIndirect,
		File:     doc.Path,
		Line:     usesIdx + 1,
		Evidence: trim(doc.Lines[usesIdx]),
		Description: "The workflow runs on an attacker-influenced trigger and passes untrusted input " + name +
			" to the local action " + dir + " (manifest " + manifest + "), but " + reason + ". The injection " +
			"surface was therefore NOT assessed — treat this path as UNKNOWN rather than clean. Review the " +
			"action by hand, or refactor so the untrusted input does not cross into an unanalyzable sink.",
		Remediation: "Do not pass attacker-controllable input into an action whose body cannot be reviewed by a " +
			"workflow scan (a JavaScript/Docker action, or a composite that forwards it onward). Validate or drop " +
			"the input before the call, or inline the logic so the sink is visible.",
		Confirmable: false,
	}
}

// readManifest resolves <dir>/action.yml then .yaml under root. found is false
// only when no manifest exists (absent); a present-but-unreadable manifest
// returns found=true with status rsUnreadable so the caller can surface it.
func readManifest(root, dir string) (data []byte, real string, st readStatus, found bool) {
	for _, name := range compositeManifests {
		d, r, s := readConfined(root, dir+"/"+name)
		switch s {
		case rsOK:
			return d, r, rsOK, true
		case rsUnreadable:
			return nil, r, rsUnreadable, true
		}
	}
	return nil, "", rsAbsent, false
}

// hasYAMLExt reports a .yml/.yaml suffix (case-insensitive).
func hasYAMLExt(p string) bool {
	l := strings.ToLower(p)
	return strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".yaml")
}

// stepTaintedInputs returns the input names a single step item — the one whose
// `uses:` is at usesIdx — feeds an untrusted expression via `with:`. The step is
// bounded dash-aware: a YAML list item's keys share a key column regardless of
// whether the `- ` sits on the same line, so the matching `with:` is the one at
// that key column within this item, and the item ends at the next sibling `- `
// (same dash column) or a dedent below the key column.
func stepTaintedInputs(lines []string, usesIdx int) map[string]bool {
	kc := keyColumn(lines[usesIdx])

	// Find the dash column of the owning list item: the nearest line at or above
	// usesIdx that carries a `- ` and whose keys align at kc.
	dashCol := -1
	for i := usesIdx; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" || strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
			continue
		}
		if keyColumn(lines[i]) < kc {
			break // dedented out of the step item without finding its dash
		}
		if hasListDash(lines[i]) && keyColumn(lines[i]) == kc {
			dashCol = leadingSpaces(lines[i])
			usesIdx = i // start the scan at the item's first line
			break
		}
	}
	if dashCol < 0 {
		return nil
	}

	names := map[string]bool{}
	for i := usesIdx; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if i > usesIdx {
			// A sibling list item (dash at the same column) or any dedent below the
			// key column ends this step item.
			if hasListDash(lines[i]) && leadingSpaces(lines[i]) == dashCol {
				break
			}
			if keyColumn(lines[i]) < kc {
				break
			}
		}
		// Flow form: `with: { a: x }` on one line at this item's key column.
		if fm := reWithFlow.FindStringSubmatch(lines[i]); fm != nil && keyColumn(lines[i]) == kc {
			collectFlowInputs(fm[1], names)
			continue
		}
		// Block form: a `with:` key at this item's key column; entries sit deeper.
		if keyColumn(lines[i]) == kc && strings.TrimSpace(lines[i]) == "with:" {
			for j := i + 1; j < len(lines); j++ {
				tj := strings.TrimSpace(lines[j])
				if tj == "" || strings.HasPrefix(tj, "#") {
					continue
				}
				if keyColumn(lines[j]) <= kc {
					break // dedented out of the with: block
				}
				if em := reInputName.FindStringSubmatch(lines[j]); em != nil && valueIsUntrusted(em[2]) {
					names[em[1]] = true
				}
			}
		}
	}
	return names
}

// leadingSpaces counts leading space/tab characters.
func leadingSpaces(s string) int {
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

// hasListDash reports whether the first non-space character is a YAML list dash.
func hasListDash(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, "- ") || t == "-"
}

// keyColumn returns the column where a line's mapping key begins, skipping
// leading whitespace and any YAML list dashes. This normalizes list-item keys
// (`- name:`) and continuation keys (`  uses:`) to the same column so siblings
// inside one `- ` item are recognized regardless of which key carries the dash.
func keyColumn(s string) int {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for i < len(s) && s[i] == '-' {
		i++
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	return i
}

// compositeUnassessed reports that a composite action's manifest was present but
// could not be read, so its injection surface was not assessed. Info severity so
// it never breaks a CI gate, but recorded so a failed read is not scored clean.
func compositeUnassessed(callerPath string, callerLine int, dir, real string) model.Finding {
	return model.Finding{
		RuleID:   "CAM-PPE-004",
		Title:    "Composite action manifest could not be analyzed — injection coverage incomplete",
		Severity: model.SevInfo,
		Category: model.CatPPEIndirect,
		File:     real,
		Line:     0,
		Description: "The workflow invokes a local composite action " + dir + " (at " + callerPath + ":" +
			fmt.Sprint(callerLine) + ") and passes it untrusted input, but Caminus could not read the action " +
			"manifest, so it was NOT assessed for injection. Treat this path as UNKNOWN rather than clean: fix " +
			"the manifest's readability and re-scan, or review it manually.",
		Remediation: "Ensure the composite action manifest is readable so it can be analyzed; a present-but-" +
			"unreadable file is a coverage gap, not a clean result.",
		Confirmable: false,
	}
}
