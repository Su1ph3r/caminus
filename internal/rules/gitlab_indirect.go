package rules

import (
	"fmt"

	"github.com/Su1ph3r/caminus/internal/gitlabci"
	"github.com/Su1ph3r/caminus/internal/model"
)

// glUntrustedNames is the set of attacker-controllable GitLab predefined
// variables (merge-request fields, branch names, commit message/author). GitLab
// auto-exports every CI/CD variable into the job environment, so a local script
// the pipeline runs can read these directly with `$CI_…` — no YAML routing
// needed. The names mirror glUntrustedVar (the direct-injection matcher).
var glUntrustedNames = map[string]bool{
	"CI_MERGE_REQUEST_TITLE":                      true,
	"CI_MERGE_REQUEST_DESCRIPTION":                true,
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME":         true,
	"CI_MERGE_REQUEST_LABELS":                     true,
	"CI_COMMIT_MESSAGE":                           true,
	"CI_COMMIT_TITLE":                             true,
	"CI_COMMIT_DESCRIPTION":                       true,
	"CI_COMMIT_AUTHOR":                            true,
	"CI_COMMIT_REF_NAME":                          true,
	"CI_COMMIT_BRANCH":                            true,
	"CI_COMMIT_TAG":                               true,
	"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME": true,
}

// GLIndirectInjection detects indirect script injection in GitLab CI: a
// script:/before_script:/after_script: step runs a local repo file (shell
// script, Makefile, package.json) that uses an attacker-controllable predefined
// variable unquoted or via eval/command-substitution. The injection is in the
// referenced file, which a .gitlab-ci.yml-only scan never reads.
type GLIndirectInjection struct{}

func (GLIndirectInjection) ID() string { return "CAM-GL-INJ-002" }

func (GLIndirectInjection) Apply(doc *gitlabci.Doc) []model.Finding {
	root := repoRootOf(doc.Path)
	refs := scriptRefsFrom(doc.Lines, doc.ExecContext)

	var out []model.Finding
	for _, ref := range refs {
		site := analyzeRef(root, ref, glUntrustedNames)
		if site == nil {
			continue
		}
		if site.Unassessed {
			out = append(out, unassessedFinding("CAM-GL-INJ-002", doc.Path, ref, site))
			continue
		}
		out = append(out, model.Finding{
			RuleID:   "CAM-GL-INJ-002",
			Title:    fmt.Sprintf("Indirect injection: untrusted %q reaches a shell in executed file %s", site.Name, shortRel(root, site.File)),
			Severity: model.SevCritical,
			Category: model.CatPPEIndirect,
			File:     site.File,
			Line:     site.Line,
			Evidence: site.Code,
			Description: "The pipeline runs a local file (" + shortRel(root, site.File) + ", invoked at " +
				doc.Path + ":" + fmt.Sprint(ref.Line) + ") that uses the attacker-controllable predefined " +
				"variable " + site.Name + " unquoted or via eval/command-substitution. GitLab auto-exports " +
				"this variable into the job environment, so an attacker who opens a merge request or pushes " +
				"a branch controls its value and injects shell commands on the runner — a script-injection " +
				"sink invisible to a .gitlab-ci.yml-only scan.",
			Remediation: "Quote the variable in the referenced file (\"$" + site.Name + "\"), never pass it " +
				"to eval or an unquoted command substitution, and validate it before use.",
			// Attacker-influenced via a branch push or merge request regardless of
			// the pipeline's trigger config, so the primitive is always confirmable.
			Confirmable: true,
			References: []string{
				"https://docs.gitlab.com/ee/ci/variables/#cicd-variable-security",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
			},
		})
	}
	return out
}
