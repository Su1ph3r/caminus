//go:build cloud

package cloud

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/vcr"
)

// TestFetchReplay drives the real AWS SDK ListRoles path (request signing, XML
// deserialization) against a recorded IAM response — no AWS account or
// credentials required. It is compiled only with `-tags cloud`.
func TestFetchReplay(t *testing.T) {
	rt, err := vcr.Replay(filepath.Join("testdata", "iam-listroles.cassette.json"))
	if err != nil {
		t.Fatalf("load cassette: %v", err)
	}

	trusts, err := Fetch(context.Background(), Options{Transport: rt, Anonymous: true, Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Two GitHub-OIDC trusts; the cognito role is filtered out.
	if len(trusts) != 2 {
		t.Fatalf("expected 2 GitHub trusts (cognito filtered), got %d: %+v", len(trusts), trusts)
	}

	byName := map[string]GitHubTrust{}
	for _, tr := range trusts {
		byName[tr.RoleName] = tr
	}

	dep, ok := byName["deployer"]
	if !ok {
		t.Fatal("missing role 'deployer'")
	}
	if dep.Broadness() != TrustRefWildcard {
		t.Errorf("deployer broadness = %v, want ref-wildcard", dep.Broadness())
	}
	if dep.Account != "123456789012" {
		t.Errorf("deployer account = %q", dep.Account)
	}

	ro, ok := byName["ci-readonly"]
	if !ok {
		t.Fatal("missing role 'ci-readonly'")
	}
	if ro.Broadness() != TrustScoped {
		t.Errorf("ci-readonly broadness = %v, want scoped", ro.Broadness())
	}
}
