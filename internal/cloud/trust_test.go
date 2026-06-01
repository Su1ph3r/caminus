package cloud

import "testing"

func policy(sub, extra string) string {
	subCond := ""
	if sub != "" {
		subCond = `,"StringLike":{"token.actions.githubusercontent.com:sub":` + sub + `}`
	}
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},` +
		`"Action":"sts:AssumeRoleWithWebIdentity",` +
		`"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}` + subCond + extra + `}}]}`
}

func TestParseTrustPolicyScoped(t *testing.T) {
	ts, err := ParseTrustPolicy("arn:aws:iam::123456789012:role/deployer", "deployer", "123456789012",
		policy(`"repo:acme/widgets:ref:refs/heads/main"`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 {
		t.Fatalf("want 1 trust, got %d", len(ts))
	}
	if !ts[0].HasSub || ts[0].Broadness() != TrustScoped {
		t.Errorf("want scoped trust, got hasSub=%v broadness=%v", ts[0].HasSub, ts[0].Broadness())
	}
	if len(ts[0].Audiences) != 1 || ts[0].Audiences[0] != "sts.amazonaws.com" {
		t.Errorf("aud = %v", ts[0].Audiences)
	}
}

func TestBroadnessClassification(t *testing.T) {
	cases := []struct {
		sub  string
		want Broadness
	}{
		{`"repo:acme/widgets:ref:refs/heads/main"`, TrustScoped},
		{`"repo:acme/widgets:*"`, TrustRefWildcard},
		{`"repo:acme/*:*"`, TrustRepoWildcard},
		{`"*"`, TrustRepoWildcard},
		{"", TrustNoSubject}, // no :sub condition at all
	}
	for _, c := range cases {
		ts, err := ParseTrustPolicy("arn", "r", "1", policy(c.sub, ""))
		if err != nil {
			t.Fatal(err)
		}
		if len(ts) != 1 {
			t.Fatalf("sub=%q: want 1 trust, got %d", c.sub, len(ts))
		}
		if got := ts[0].Broadness(); got != c.want {
			t.Errorf("sub=%q broadness = %v, want %v", c.sub, got, c.want)
		}
	}
}

func TestNonGitHubFederationIgnored(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},` +
		`"Action":"sts:AssumeRoleWithWebIdentity"}]}`
	ts, err := ParseTrustPolicy("arn", "r", "1", doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 0 {
		t.Errorf("non-GitHub federation should be ignored, got %d trusts", len(ts))
	}
}

func TestMalformedSubConditionIsError(t *testing.T) {
	// A :sub value that is neither a string nor a string array (here, an object)
	// must produce an error — never be silently dropped, which would misclassify
	// the trust as "no subject condition" (the most permissive class).
	_, err := ParseTrustPolicy("arn:aws:iam::1:role/x", "x", "1",
		policy(`{"unexpected":"object"}`, ""))
	if err == nil {
		t.Fatal("expected an error for a malformed :sub condition, got nil")
	}
}

func TestSubjectMatches(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		{"repo:acme/widgets:*", "repo:acme/widgets:pull_request", true},
		{"repo:acme/widgets:ref:refs/heads/main", "repo:acme/widgets:pull_request", false},
		{"repo:acme/*:*", "repo:acme/other:ref:refs/heads/x", true},
		{"repo:acme/widgets:ref:refs/heads/main", "repo:acme/widgets:ref:refs/heads/main", true},
		{"*", "literally-anything", true},
	}
	for _, c := range cases {
		if got := SubjectMatches(c.pattern, c.subject); got != c.want {
			t.Errorf("SubjectMatches(%q,%q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}
