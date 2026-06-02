package cloud

import (
	"reflect"
	"testing"
)

func TestParseGCPMember(t *testing.T) {
	pool := "projects/myproj/locations/global/workloadIdentityPools/github-pool"
	pools := map[string]bool{pool: true}
	base := "principalSet://iam.googleapis.com/" + pool

	cases := []struct {
		name     string
		member   string
		patterns []string
		hasSub   bool
		class    gcpMemberClass
	}{
		{"repository", base + "/attribute.repository/acme/widgets", []string{"repo:acme/widgets:*"}, true, memberMapped},
		{"repository_owner", base + "/attribute.repository_owner/acme", []string{"repo:acme/*:*"}, true, memberMapped},
		{"subject", "principal://iam.googleapis.com/" + pool + "/subject/repo:acme/widgets:ref:refs/heads/main",
			[]string{"repo:acme/widgets:ref:refs/heads/main"}, true, memberMapped},
		{"whole-pool-star", base + "/*", nil, false, memberMapped},
		{"whole-pool-bare", base, nil, false, memberMapped},
		{"custom-attr", base + "/attribute.environment/prod", nil, false, memberUnmappedAttr},
		{"other-pool", "principalSet://iam.googleapis.com/projects/x/locations/global/workloadIdentityPools/other/attribute.repository/a/b", nil, false, memberNotGitHub},
		{"plain-sa", "serviceAccount:foo@bar.iam.gserviceaccount.com", nil, false, memberNotGitHub},
		{"user", "user:dev@example.com", nil, false, memberNotGitHub},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pat, hasSub, _, class := parseGCPMember(c.member, pools)
			if class != c.class {
				t.Fatalf("class = %v, want %v", class, c.class)
			}
			if hasSub != c.hasSub {
				t.Errorf("hasSub = %v, want %v", hasSub, c.hasSub)
			}
			if !reflect.DeepEqual(pat, c.patterns) {
				t.Errorf("patterns = %v, want %v", pat, c.patterns)
			}
		})
	}
}

// TestParseGCPMemberBroadness confirms the parsed patterns classify to the
// expected federation broadness via the shared classifier.
func TestParseGCPMemberBroadness(t *testing.T) {
	pool := "projects/p/locations/global/workloadIdentityPools/gh"
	pools := map[string]bool{pool: true}
	mk := func(suffix string) GitHubTrust {
		pat, hasSub, _, _ := parseGCPMember("principalSet://iam.googleapis.com/"+pool+suffix, pools)
		return GitHubTrust{Provider: "gcp", SubPatterns: pat, HasSub: hasSub}
	}
	if b := mk("/attribute.repository/acme/widgets").Broadness(); b != TrustRefWildcard {
		t.Errorf("repository broadness = %v, want ref-wildcard", b)
	}
	if b := mk("/attribute.repository_owner/acme").Broadness(); b != TrustRepoWildcard {
		t.Errorf("repository_owner broadness = %v, want repo-wildcard", b)
	}
	if b := mk("/*").Broadness(); b != TrustNoSubject {
		t.Errorf("whole-pool broadness = %v, want no-subject", b)
	}
}
