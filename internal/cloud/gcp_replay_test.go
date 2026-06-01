//go:build cloud

package cloud

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/vcr"
)

// TestFetchGCPReplay drives the real Google IAM API client (URL construction,
// JSON deserialization, pagination) against recorded responses — no GCP project
// or credentials required. Compiled only with `-tags cloud`.
func TestFetchGCPReplay(t *testing.T) {
	rt, err := vcr.Replay(filepath.Join("testdata", "gcp-wif.cassette.json"))
	if err != nil {
		t.Fatalf("load cassette: %v", err)
	}

	trusts, err := FetchGCP(context.Background(), Options{Transport: rt, Anonymous: true, Project: "myproj"})
	if err != nil {
		t.Fatalf("FetchGCP: %v", err)
	}
	if len(trusts) != 2 {
		t.Fatalf("expected 2 GitHub→SA trusts, got %d: %+v", len(trusts), trusts)
	}

	byEmail := map[string]GitHubTrust{}
	for _, tr := range trusts {
		if tr.Provider != "gcp" {
			t.Errorf("trust %s provider = %q, want gcp", tr.RoleARN, tr.Provider)
		}
		if tr.Account != "myproj" {
			t.Errorf("trust %s account = %q, want myproj", tr.RoleARN, tr.Account)
		}
		byEmail[tr.RoleARN] = tr
	}

	dep, ok := byEmail["deployer@myproj.iam.gserviceaccount.com"]
	if !ok {
		t.Fatal("missing deployer SA trust")
	}
	if dep.Broadness() != TrustRefWildcard {
		t.Errorf("deployer broadness = %v, want ref-wildcard", dep.Broadness())
	}

	ro, ok := byEmail["readonly@myproj.iam.gserviceaccount.com"]
	if !ok {
		t.Fatal("missing readonly SA trust")
	}
	if ro.Broadness() != TrustScoped {
		t.Errorf("readonly broadness = %v, want scoped", ro.Broadness())
	}
}
