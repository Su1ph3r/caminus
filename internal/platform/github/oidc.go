package github

import (
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
)

// GitHub's OIDC token carries a `sub` (subject) claim that cloud trust policies
// match against to decide whether to hand out credentials. By default the
// subject is scoped to the ref/pull-request/environment of the run
// (e.g. repo:ORG/REPO:ref:refs/heads/main). A repository can customize which
// claims compose the subject; if that customization drops the per-run scoping,
// every workflow run — including a fork-influenced pull_request_target run —
// presents the same repo-wide subject. A cloud role whose trust policy matches
// that subject can then be assumed from any run.
//
// oidcScopingClaims are the customization keys that keep the subject scoped to a
// single ref / environment / workflow; a customized subject containing none of
// them is repo-wide (over-broad).
var oidcScopingClaims = map[string]bool{
	"context":          true,
	"ref":              true,
	"ref_type":         true,
	"environment":      true,
	"head_ref":         true,
	"base_ref":         true,
	"workflow_ref":     true,
	"job_workflow_ref": true,
}

// oidcSubject returns the effective subject pattern, whether it is over-broad
// (repo-wide, lacking per-run scoping), and a human-readable reason.
func oidcSubject(fullName string, sub oidcSub) (pattern string, overBroad bool, reason string) {
	if sub.UseDefault {
		return "repo:" + fullName + ":{ref|pull_request|environment:…}", false, ""
	}
	if len(sub.IncludeClaimKeys) == 0 {
		return "repo:" + fullName, true,
			"OIDC subject customized with no claims — resolves repo-wide"
	}
	for _, k := range sub.IncludeClaimKeys {
		if oidcScopingClaims[k] {
			return "{" + strings.Join(sub.IncludeClaimKeys, "+") + "}", false, ""
		}
	}
	return "{" + strings.Join(sub.IncludeClaimKeys, "+") + "}", true,
		"OIDC subject omits ref/environment scoping (" + strings.Join(sub.IncludeClaimKeys, ",") + ") — repo-wide token"
}

// oidcFinding builds the CAM-OIDC-001 finding for an over-broad subject. It is
// framed as a risk indicator, not a confirmed exploit: it becomes actionable
// only if a cloud trust policy matches the subject without a branch/environment
// condition (resolved in the cloud stage). Honest severity: Medium.
func oidcFinding(fullName, pattern, reason string) model.Finding {
	return model.Finding{
		RuleID:   "CAM-OIDC-001",
		Title:    "Over-broad OIDC subject — repo-wide federation token",
		Severity: model.SevMedium,
		Category: model.CatOIDC,
		File:     fullName,
		Evidence: "sub = " + pattern,
		Description: reason + ". Every workflow run in this repository — including a " +
			"fork-influenced pull_request_target run — presents this repo-wide OIDC subject. Any cloud " +
			"role whose trust policy matches it without an additional branch/environment condition can " +
			"be assumed from an attacker-controllable run.",
		Remediation: "Re-enable the default subject claim (which includes the ref/environment context) " +
			"or add a scoping claim (ref, environment) to the customization; and require branch/" +
			"environment conditions on the cloud trust policy.",
		Confirmable: false,
		References: []string{
			"https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers#customizing-the-token-claims",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-6)",
		},
	}
}
