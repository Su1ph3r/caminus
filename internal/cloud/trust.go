// Package cloud resolves the OIDC → cloud blast radius: it parses IAM role
// trust policies that federate to GitHub Actions OIDC, matches their subject
// conditions against the CI subjects Caminus enumerated, and records which
// pipelines can assume which roles.
//
// The trust-policy parsing and subject matching in this file are pure and
// dependency-free, so the security-critical logic is fully unit-tested without
// the AWS SDK. The SDK is used only to fetch role trust documents and lives
// behind the `cloud` build tag (see aws.go / aws_stub.go).
package cloud

import (
	"encoding/json"
	"regexp"
	"strings"
)

// GitHubOIDCIssuer is the GitHub Actions OIDC issuer host. IAM condition keys
// for these federations are prefixed with it (e.g. "<issuer>:sub").
const GitHubOIDCIssuer = "token.actions.githubusercontent.com"

// GitHubTrust is a parsed GitHub-OIDC federation granted by an IAM role's
// AssumeRolePolicyDocument.
type GitHubTrust struct {
	RoleARN     string   `json:"role_arn"`
	RoleName    string   `json:"role_name"`
	Account     string   `json:"account"`
	SubPatterns []string `json:"sub_patterns"` // :sub condition values (empty = no sub condition!)
	Audiences   []string `json:"audiences"`    // :aud condition values
	HasSub      bool     `json:"has_sub"`
}

// Broadness classifies how permissive a federation is.
type Broadness int

const (
	TrustScoped       Broadness = iota // every sub pattern pins a specific repo+ref/env
	TrustRefWildcard                   // pins the repo but wildcards the ref/env (any branch/PR)
	TrustRepoWildcard                  // wildcards the repo/owner (any repo can assume)
	TrustNoSubject                     // no :sub condition at all (any GitHub repo can assume)
)

func (b Broadness) String() string {
	switch b {
	case TrustRefWildcard:
		return "ref-wildcard"
	case TrustRepoWildcard:
		return "repo-wildcard"
	case TrustNoSubject:
		return "no-subject-condition"
	default:
		return "scoped"
	}
}

// Broadness reports the most permissive classification across the trust's sub
// patterns.
func (t GitHubTrust) Broadness() Broadness {
	if !t.HasSub || len(t.SubPatterns) == 0 {
		return TrustNoSubject
	}
	worst := TrustScoped
	for _, p := range t.SubPatterns {
		b := classifyPattern(p)
		if b > worst {
			worst = b
		}
	}
	return worst
}

// classifyPattern judges a single sub pattern. A GitHub sub looks like
// "repo:<owner>/<repo>:<context>"; a wildcard in the owner/repo segment means
// any repository, a wildcard only in the trailing context means any ref/env.
func classifyPattern(p string) Broadness {
	rest := strings.TrimPrefix(p, "repo:")
	// owner/repo is everything up to the third ':' boundary (the context start)
	repoSeg := rest
	if i := strings.Index(rest, ":"); i >= 0 {
		repoSeg = rest[:i]
	}
	if strings.Contains(repoSeg, "*") || strings.Contains(repoSeg, "?") || p == "*" {
		return TrustRepoWildcard
	}
	ctx := ""
	if i := strings.Index(rest, ":"); i >= 0 {
		ctx = rest[i+1:]
	}
	if ctx == "" || strings.Contains(ctx, "*") || strings.Contains(ctx, "?") {
		return TrustRefWildcard
	}
	return TrustScoped
}

// SubjectMatches reports whether an IAM StringLike/StringEquals condition
// pattern (glob with '*' and '?') matches a concrete OIDC subject.
func SubjectMatches(pattern, subject string) bool {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(subject)
}

// Assumable reports whether any of the candidate subjects can assume this trust
// (i.e. satisfies at least one sub pattern, or the trust has no sub condition).
func (t GitHubTrust) Assumable(candidateSubjects []string) bool {
	if !t.HasSub {
		return true // no :sub condition — any federated repo qualifies
	}
	for _, p := range t.SubPatterns {
		for _, s := range candidateSubjects {
			if SubjectMatches(p, s) {
				return true
			}
		}
	}
	return false
}

// --- trust policy parsing --------------------------------------------------

type policyDoc struct {
	Statement json.RawMessage `json:"Statement"`
}

type statement struct {
	Effect    string `json:"Effect"`
	Principal struct {
		Federated json.RawMessage `json:"Federated"`
	} `json:"Principal"`
	Action    json.RawMessage                       `json:"Action"`
	Condition map[string]map[string]json.RawMessage `json:"Condition"`
}

// ParseTrustPolicy parses an IAM AssumeRolePolicyDocument (URL-decoded JSON) and
// returns the GitHub-OIDC federations it grants for the given role.
func ParseTrustPolicy(roleARN, roleName, account, doc string) ([]GitHubTrust, error) {
	var pd policyDoc
	if err := json.Unmarshal([]byte(doc), &pd); err != nil {
		return nil, err
	}
	stmts, err := decodeStatements(pd.Statement)
	if err != nil {
		return nil, err
	}

	var out []GitHubTrust
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if !containsFold(flexStrings(s.Action), "sts:AssumeRoleWithWebIdentity") {
			continue
		}
		if !federatesGitHub(flexStrings(s.Principal.Federated)) {
			continue
		}
		t := GitHubTrust{RoleARN: roleARN, RoleName: roleName, Account: account}
		subKey := GitHubOIDCIssuer + ":sub"
		audKey := GitHubOIDCIssuer + ":aud"
		for _, vals := range s.Condition { // StringEquals / StringLike / …
			if raw, ok := vals[subKey]; ok {
				t.SubPatterns = append(t.SubPatterns, flexStrings(raw)...)
			}
			if raw, ok := vals[audKey]; ok {
				t.Audiences = append(t.Audiences, flexStrings(raw)...)
			}
		}
		t.HasSub = len(t.SubPatterns) > 0
		out = append(out, t)
	}
	return out, nil
}

// decodeStatements handles Statement being a single object or an array.
func decodeStatements(raw json.RawMessage) ([]statement, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var arr []statement
		return arr, json.Unmarshal(raw, &arr)
	}
	var one statement
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []statement{one}, nil
}

// flexStrings decodes a JSON value that may be a string or an array of strings.
func flexStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		var arr []string
		_ = json.Unmarshal(raw, &arr)
		return arr
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return []string{s}
}

func federatesGitHub(principals []string) bool {
	for _, p := range principals {
		if strings.HasSuffix(p, "oidc-provider/"+GitHubOIDCIssuer) || strings.Contains(p, GitHubOIDCIssuer) {
			return true
		}
	}
	return false
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
