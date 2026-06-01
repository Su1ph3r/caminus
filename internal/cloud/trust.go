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
	"fmt"
	"regexp"
	"strings"
	"sync"
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

// globCache memoizes the compiled regexp for each distinct IAM condition
// pattern. Matching runs in an O(roles × repos × patterns × subjects) loop, so
// compiling a pattern once (rather than per subject) matters on real accounts.
var (
	globCacheMu sync.Mutex
	globCache   = map[string]*regexp.Regexp{}
)

// compileGlob translates an IAM StringLike/StringEquals pattern (glob with '*'
// and '?') into an anchored regexp, caching the result. A nil entry is cached
// for un-compilable patterns so they are not retried. RE2 (Go's regexp) is
// linear-time, so this is not subject to catastrophic backtracking.
func compileGlob(pattern string) *regexp.Regexp {
	globCacheMu.Lock()
	defer globCacheMu.Unlock()
	if re, ok := globCache[pattern]; ok {
		return re
	}
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
		re = nil
	}
	globCache[pattern] = re
	return re
}

// SubjectMatches reports whether an IAM StringLike/StringEquals condition
// pattern (glob with '*' and '?') matches a concrete OIDC subject.
func SubjectMatches(pattern, subject string) bool {
	re := compileGlob(pattern)
	if re == nil {
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
		re := compileGlob(p)
		if re == nil {
			continue
		}
		for _, s := range candidateSubjects {
			if re.MatchString(s) {
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
		// A statement whose Action or Principal can't be decoded is one we
		// can't evaluate — skip it rather than guess.
		actions, err := flexStrings(s.Action)
		if err != nil || !containsFold(actions, "sts:AssumeRoleWithWebIdentity") {
			continue
		}
		feds, err := flexStrings(s.Principal.Federated)
		if err != nil || !federatesGitHub(feds) {
			continue
		}
		t := GitHubTrust{RoleARN: roleARN, RoleName: roleName, Account: account}
		subKey := GitHubOIDCIssuer + ":sub"
		audKey := GitHubOIDCIssuer + ":aud"
		for _, vals := range s.Condition { // StringEquals / StringLike / …
			// A present-but-unparsable :sub/:aud is a hard error: silently
			// dropping it would make HasSub=false and misclassify the trust as
			// "no subject condition" — the most permissive class — purely
			// because of a decode failure. Fail loudly so the caller skips the
			// role with a logged reason instead.
			if raw, ok := vals[subKey]; ok {
				vs, err := flexStrings(raw)
				if err != nil {
					return nil, fmt.Errorf("github trust :sub condition for %s: %w", roleARN, err)
				}
				t.SubPatterns = append(t.SubPatterns, vs...)
			}
			if raw, ok := vals[audKey]; ok {
				vs, err := flexStrings(raw)
				if err != nil {
					return nil, fmt.Errorf("github trust :aud condition for %s: %w", roleARN, err)
				}
				t.Audiences = append(t.Audiences, vs...)
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
// A decode failure is returned, not swallowed, so callers can distinguish
// "absent" from "present but malformed".
func flexStrings(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		var arr []string
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return []string{s}, nil
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
