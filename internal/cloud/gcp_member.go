package cloud

import "strings"

// GCP Workload Identity Federation grants a GitHub Actions workflow the ability
// to impersonate a service account by binding an IAM principal/principalSet on
// that SA to a workload-identity-pool member. The member string encodes which
// GitHub subjects are admitted. This file parses those member strings into the
// provider-neutral GitHubTrust subject model — pure, dependency-free, and
// unit-tested without the GCP SDK (the SDK glue lives in gcp.go behind -tags
// cloud, mirroring the AWS trust.go / aws.go split).

// gcpMemberClass classifies an IAM member string relative to GitHub federation.
type gcpMemberClass int

const (
	memberNotGitHub    gcpMemberClass = iota // not a GitHub-federating pool member
	memberMapped                             // mapped to a concrete GitHub subject scope
	memberUnmappedAttr                       // references a GitHub pool but via an attribute we don't model
)

const (
	prefixPrincipalSet = "principalSet://iam.googleapis.com/"
	prefixPrincipal    = "principal://iam.googleapis.com/"
)

// parseGCPMember interprets an IAM binding member against the set of
// GitHub-federating workload-identity-pool resource names. It returns the GitHub
// OIDC sub patterns the member admits, whether the member carries a subject
// condition at all, and a classification telling the caller whether to build a
// trust (memberMapped), log-and-skip (memberUnmappedAttr), or ignore silently
// (memberNotGitHub).
func parseGCPMember(member string, githubPools map[string]bool) (patterns []string, hasSub bool, class gcpMemberClass) {
	rest := ""
	switch {
	case strings.HasPrefix(member, prefixPrincipalSet):
		rest = member[len(prefixPrincipalSet):]
	case strings.HasPrefix(member, prefixPrincipal):
		rest = member[len(prefixPrincipal):]
	default:
		return nil, false, memberNotGitHub
	}

	// Identify the pool this member targets. Match the longest pool name that is
	// a prefix, so a pool whose name is a prefix of another does not shadow it.
	var pool string
	for p := range githubPools {
		if (rest == p || strings.HasPrefix(rest, p+"/")) && len(p) > len(pool) {
			pool = p
		}
	}
	if pool == "" {
		return nil, false, memberNotGitHub
	}

	suffix := strings.TrimPrefix(rest[len(pool):], "/")
	switch {
	case suffix == "" || suffix == "*":
		// Whole-pool binding: any identity federated through this GitHub pool can
		// impersonate the SA — no subject condition.
		return nil, false, memberMapped
	case strings.HasPrefix(suffix, "attribute.repository/"):
		// attribute.repository maps to the GitHub "repository" claim (owner/repo).
		repo := strings.TrimPrefix(suffix, "attribute.repository/")
		if repo == "" {
			return nil, false, memberUnmappedAttr
		}
		return []string{"repo:" + repo + ":*"}, true, memberMapped
	case strings.HasPrefix(suffix, "attribute.repository_owner/"):
		owner := strings.TrimPrefix(suffix, "attribute.repository_owner/")
		if owner == "" {
			return nil, false, memberUnmappedAttr
		}
		return []string{"repo:" + owner + "/*:*"}, true, memberMapped
	case strings.HasPrefix(suffix, "subject/"):
		// google.subject is conventionally mapped from assertion.sub, i.e. the
		// raw GitHub OIDC subject.
		sub := strings.TrimPrefix(suffix, "subject/")
		if sub == "" {
			return nil, false, memberUnmappedAttr
		}
		return []string{sub}, true, memberMapped
	default:
		// A custom attribute mapping we can't translate to a GitHub subject; flag
		// it for the operator rather than guess (false-positive-averse).
		return nil, false, memberUnmappedAttr
	}
}

// gcpImpersonationRoles are the IAM roles that let a federated principal mint a
// service-account token (assume the SA).
func gcpImpersonationRole(role string) bool {
	switch role {
	case "roles/iam.workloadIdentityUser", "roles/iam.serviceAccountTokenCreator":
		return true
	default:
		return false
	}
}
