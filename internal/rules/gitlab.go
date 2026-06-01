package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/gitlabci"
	"github.com/Su1ph3r/caminus/internal/model"
)

// GitLabRule is a static detector over a GitLab CI document. GitLab semantics
// differ enough from GitHub Actions that rules operate on their own doc type
// rather than a forced shared interface.
type GitLabRule interface {
	ID() string
	Apply(doc *gitlabci.Doc) []model.Finding
}

// DefaultGitLab returns the built-in GitLab CI rule set.
func DefaultGitLab() []GitLabRule {
	return []GitLabRule{
		GLExpressionInjection{},
		GLMergeRequestExposure{},
		GLDebugTrace{},
		GLPrivilegedRunner{},
		GLUnpinnedInclude{},
	}
}

// RunGitLab applies every GitLab rule to a document.
func RunGitLab(doc *gitlabci.Doc) []model.Finding {
	var out []model.Finding
	for _, r := range DefaultGitLab() {
		out = append(out, r.Apply(doc)...)
	}
	return out
}

// firstLineContaining returns the index of the first line containing sub, or -1.
func firstLineContaining(doc *gitlabci.Doc, sub string) int {
	for i, l := range doc.Lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

func glEvidence(doc *gitlabci.Doc, idx int) string {
	if idx < 0 || idx >= len(doc.Lines) {
		return ""
	}
	return trim(doc.Lines[idx])
}

// --- CAM-GL-INJ-001: script injection -------------------------------------

// glUntrustedVar matches GitLab predefined variables an attacker controls on a
// merge request, branch push, or commit: MR fields, branch names, and commit
// message/author. Interpolated into a script: block, these allow shell command
// injection on the runner.
var glUntrustedVar = regexp.MustCompile(
	`\$\{?CI_(?:MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|LABELS)` +
		`|COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|AUTHOR|REF_NAME|BRANCH|TAG)` +
		`|EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\}?`)

type GLExpressionInjection struct{}

func (GLExpressionInjection) ID() string { return "CAM-GL-INJ-001" }

func (GLExpressionInjection) Apply(doc *gitlabci.Doc) []model.Finding {
	var out []model.Finding
	for i, line := range doc.Lines {
		if !doc.ExecContext(i) {
			continue
		}
		loc := glUntrustedVar.FindString(line)
		if loc == "" {
			continue
		}
		out = append(out, model.Finding{
			RuleID:   "CAM-GL-INJ-001",
			Title:    fmt.Sprintf("Untrusted variable %q interpolated into a script: command", strings.Trim(loc, "${}")),
			Severity: model.SevCritical,
			Category: model.CatInjection,
			File:     doc.Path,
			Line:     i + 1,
			Evidence: trim(line),
			Description: "An attacker-controllable predefined variable (a merge-request field, branch " +
				"name, or commit message/author) is interpolated directly into a shell script. An " +
				"attacker who opens an MR or pushes a branch controls this value and can inject shell " +
				"metacharacters to run arbitrary code on the runner.",
			Remediation: "Do not interpolate CI variables into script: directly. Read them from the " +
				"environment with quoting (the variable is already exported), e.g. \"$CI_COMMIT_MESSAGE\", " +
				"and validate before use.",
			Confirmable: true,
			References: []string{
				"https://docs.gitlab.com/ee/ci/variables/#cicd-variable-security",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-4)",
			},
		})
	}
	return out
}

// --- CAM-GL-PPE-001: merge-request pipeline exposure -----------------------

type GLMergeRequestExposure struct{}

func (GLMergeRequestExposure) ID() string { return "CAM-GL-PPE-001" }

func (GLMergeRequestExposure) Apply(doc *gitlabci.Doc) []model.Finding {
	if !doc.MergeRequestTriggered() {
		return nil
	}
	line := firstLineContaining(doc, "merge_request")
	if line < 0 {
		line = firstLineContaining(doc, "external_pull_request")
	}
	at := 1
	if line >= 0 {
		at = line + 1
	}
	return []model.Finding{{
		RuleID:   "CAM-GL-PPE-001",
		Title:    "Merge-request pipeline may expose secrets to externally influenced code",
		Severity: model.SevMedium,
		Category: model.CatPwnRequest,
		File:     doc.Path,
		Line:     at,
		Evidence: glEvidence(doc, line),
		Description: "This pipeline runs on merge-request (or external pull-request) events. GitLab " +
			"protects variables to protected branches/tags by default, so this is narrower than a " +
			"GitHub pwn-request — but review that no protected/secret variables are surfaced to MR " +
			"pipelines, that CI_JOB_TOKEN scope is limited, and that fork MRs cannot reach privileged " +
			"jobs or self-managed runners.",
		Remediation: "Keep secrets in protected variables, restrict the CI_JOB_TOKEN allowlist, and " +
			"require approval before running MR pipelines from forks/first-time contributors.",
		Confirmable: false,
		References: []string{
			"https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html",
			"https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html",
		},
	}}
}

// --- CAM-GL-DBG-001: debug trace leaks secrets -----------------------------

var reDebugTrace = regexp.MustCompile(`(?i)\bCI_DEBUG_(TRACE|SERVICES)\s*:\s*["']?(?:true|1|yes)["']?`)

type GLDebugTrace struct{}

func (GLDebugTrace) ID() string { return "CAM-GL-DBG-001" }

func (GLDebugTrace) Apply(doc *gitlabci.Doc) []model.Finding {
	var out []model.Finding
	for i, line := range doc.Lines {
		if !reDebugTrace.MatchString(line) {
			continue
		}
		out = append(out, model.Finding{
			RuleID:   "CAM-GL-DBG-001",
			Title:    "Debug tracing enabled — secrets written to job logs",
			Severity: model.SevHigh,
			Category: model.CatSecret,
			File:     doc.Path,
			Line:     i + 1,
			Evidence: trim(line),
			Description: "CI_DEBUG_TRACE / CI_DEBUG_SERVICES dumps the full job environment — including " +
				"masked and protected variables — into the job log. Anyone who can read pipeline logs " +
				"(often broad) can harvest those secrets.",
			Remediation: "Never enable debug tracing in committed config. Remove it, rotate any secrets " +
				"that may have been logged, and restrict who can view job logs.",
			Confirmable: false,
			References: []string{
				"https://docs.gitlab.com/ee/ci/variables/index.html#enable-debug-logging",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-6)",
			},
		})
	}
	return out
}

// --- CAM-GL-RUN-001: privileged container build ----------------------------

var reDind = regexp.MustCompile(`docker:[\w.\-]*dind`)

type GLPrivilegedRunner struct{}

func (GLPrivilegedRunner) ID() string { return "CAM-GL-RUN-001" }

func (GLPrivilegedRunner) Apply(doc *gitlabci.Doc) []model.Finding {
	mr := doc.MergeRequestTriggered()
	var out []model.Finding
	for i, line := range doc.Lines {
		if !reDind.MatchString(line) {
			continue
		}
		sev := model.SevMedium
		desc := "The pipeline uses Docker-in-Docker, which typically requires a privileged runner. " +
			"Code in the build then runs with effective host access on that runner and can break out " +
			"or poison it."
		if mr {
			sev = model.SevHigh
			desc = "The pipeline uses Docker-in-Docker (privileged runner) AND runs on merge-request " +
				"events. An attacker's MR can execute in a privileged container and pivot to or persist " +
				"on the runner host."
		}
		out = append(out, model.Finding{
			RuleID:      "CAM-GL-RUN-001",
			Title:       "Privileged Docker-in-Docker build exposed to pipeline execution",
			Severity:    sev,
			Category:    model.CatRunner,
			File:        doc.Path,
			Line:        i + 1,
			Evidence:    trim(line),
			Description: desc,
			Remediation: "Avoid privileged dind for untrusted code; use rootless build backends " +
				"(BuildKit rootless, Kaniko, Buildah) and never run fork/MR pipelines on privileged " +
				"self-managed runners.",
			Confirmable: mr,
			References: []string{
				"https://docs.gitlab.com/runner/executors/docker.html#use-docker-in-docker",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-7)",
			},
		})
	}
	return out
}

// --- CAM-GL-SUP-001: unpinned include --------------------------------------

type GLUnpinnedInclude struct{}

func (GLUnpinnedInclude) ID() string { return "CAM-GL-SUP-001" }

func (GLUnpinnedInclude) Apply(doc *gitlabci.Doc) []model.Finding {
	var out []model.Finding
	for _, inc := range doc.Includes() {
		var title, desc string
		switch inc.Kind {
		case "remote":
			title = "Remote include pulls pipeline config from an external URL"
			desc = "An include: remote: fetches CI config over the network at pipeline time. If the " +
				"host or content changes (or is attacker-influenced), arbitrary pipeline config runs in " +
				"your project."
		case "project":
			if reSHA40.MatchString(inc.Ref) {
				continue // pinned to a commit SHA — safe
			}
			ref := inc.Ref
			if ref == "" {
				ref = "(default branch)"
			}
			title = "Cross-project include not pinned to a commit SHA: ref " + ref
			desc = "An include: project: resolves to a mutable ref (" + ref + "). Whoever can move that " +
				"branch/tag — or compromise the source project — can alter your pipeline config."
		default:
			continue // local / template / file: lower risk, skip for now
		}
		out = append(out, model.Finding{
			RuleID:      "CAM-GL-SUP-001",
			Title:       title,
			Severity:    model.SevLow,
			Category:    model.CatSupplyChain,
			File:        doc.Path,
			Line:        inc.Line,
			Evidence:    glEvidence(doc, inc.Line-1),
			Description: desc,
			Remediation: "Pin cross-project includes to a commit SHA (ref: <sha>); avoid remote: includes " +
				"or mirror the file into the repo and review changes.",
			Confirmable: false,
			References: []string{
				"https://docs.gitlab.com/ee/ci/yaml/includes.html",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-3)",
			},
		})
	}
	return out
}
