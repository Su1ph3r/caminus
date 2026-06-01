package rules

import (
	"regexp"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

var reRunsOn = regexp.MustCompile(`^\s*runs-on:\s*(.+?)\s*$`)

// SelfHostedRunner flags jobs that execute on a self-hosted runner. The risk
// (CICD-SEC-7) is sharp when the same repository accepts fork-triggered runs:
// non-ephemeral self-hosted runners give fork code persistence and lateral
// reach into internal networks. Severity escalates to High when a fork-facing
// trigger is present.
type SelfHostedRunner struct{}

func (SelfHostedRunner) ID() string { return "CAM-RUN-001" }

func (SelfHostedRunner) Apply(doc *workflow.Doc) []model.Finding {
	forkFacing := doc.HasTrigger("pull_request", "pull_request_target", "fork")
	var out []model.Finding
	for i, line := range doc.Lines {
		m := reRunsOn.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if !strings.Contains(m[1], "self-hosted") {
			continue
		}
		sev := model.SevMedium
		desc := "The job runs on a self-hosted runner. Self-hosted runners are not ephemeral by " +
			"default; code that runs on them can persist (poison caches, tooling, the runner's " +
			"environment) and pivot into the network the runner lives in."
		if forkFacing {
			sev = model.SevHigh
			desc = "The job runs on a self-hosted runner AND the workflow has a fork-facing trigger. " +
				"A fork pull request can schedule code onto your self-hosted runner, achieving code " +
				"execution inside your infrastructure with runner-level persistence."
		}
		out = append(out, model.Finding{
			RuleID:      "CAM-RUN-001",
			Title:       "Self-hosted runner exposed to pipeline execution",
			Severity:    sev,
			Category:    model.CatRunner,
			File:        doc.Path,
			Line:        i + 1,
			Evidence:    trim(line),
			Description: desc,
			Remediation: "Use ephemeral, just-in-time self-hosted runners; never run fork PRs on " +
				"self-hosted runners (require approval for first-time contributors and restrict " +
				"`pull_request` to GitHub-hosted runners).",
			Confirmable: forkFacing,
			References: []string{
				"https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-7)",
			},
		})
	}
	return out
}

var rePermsWriteAll = regexp.MustCompile(`^\s*permissions:\s*write-all\b`)

// ExcessivePermissions flags `permissions: write-all`, which grants the
// GITHUB_TOKEN write scope across all APIs (CICD-SEC-5). Combined with any
// injection or pwn-request primitive, this is the difference between read-only
// nuisance and pushing code / publishing packages / altering releases.
type ExcessivePermissions struct{}

func (ExcessivePermissions) ID() string { return "CAM-PERM-001" }

func (ExcessivePermissions) Apply(doc *workflow.Doc) []model.Finding {
	var out []model.Finding
	for i, line := range doc.Lines {
		if !rePermsWriteAll.MatchString(line) {
			continue
		}
		out = append(out, model.Finding{
			RuleID:   "CAM-PERM-001",
			Title:    "GITHUB_TOKEN granted write-all permissions",
			Severity: model.SevMedium,
			Category: model.CatPermissions,
			File:     doc.Path,
			Line:     i + 1,
			Evidence: trim(line),
			Description: "`permissions: write-all` gives the workflow token write access to contents, " +
				"packages, deployments, issues, and more. Any code-execution primitive in this " +
				"workflow inherits that scope, amplifying impact to repo and release tampering.",
			Remediation: "Set a least-privilege top-level `permissions:` (default to `contents: read`) " +
				"and grant specific write scopes only on the jobs that need them.",
			Confirmable: false,
			References: []string{
				"https://docs.github.com/actions/security-guides/automatic-token-authentication",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-5)",
			},
		})
	}
	return out
}

// reUses matches a third-party action reference and captures owner/repo and ref.
var reUses = regexp.MustCompile(`uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#]+)`)

// reSHA40 matches a full 40-hex commit SHA (the only safe action pin).
var reSHA40 = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// UnpinnedAction flags third-party actions referenced by a mutable tag or
// branch instead of a full commit SHA (CICD-SEC-3). A tag like @v3 or a branch
// like @main can be force-moved by the action owner (or an attacker who
// compromises it) to point at malicious code that then runs in your pipeline.
type UnpinnedAction struct{}

func (UnpinnedAction) ID() string { return "CAM-SUP-001" }

func (UnpinnedAction) Apply(doc *workflow.Doc) []model.Finding {
	var out []model.Finding
	for i, line := range doc.Lines {
		m := reUses.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		repo, ref := m[1], m[2]
		// Local (./...) and reusable-workflow refs handled elsewhere; skip
		// digest-pinned refs, which are safe.
		if reSHA40.MatchString(ref) {
			continue
		}
		out = append(out, model.Finding{
			RuleID:   "CAM-SUP-001",
			Title:    "Third-party action not pinned to a commit SHA: " + repo + "@" + ref,
			Severity: model.SevLow,
			Category: model.CatSupplyChain,
			File:     doc.Path,
			Line:     i + 1,
			Evidence: trim(line),
			Description: "The action is referenced by the mutable ref \"" + ref + "\". Tags and branches " +
				"can be repointed by the action's owner or an attacker who compromises the repo, " +
				"silently introducing malicious code into your pipeline.",
			Remediation: "Pin to a full 40-character commit SHA (e.g. " + repo + "@<sha>) and update via " +
				"a reviewed bump; optionally keep the tag in a trailing comment for readability.",
			Confirmable: false,
			References: []string{
				"https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-3)",
			},
		})
	}
	return out
}
