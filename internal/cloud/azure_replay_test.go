//go:build cloud

package cloud

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/vcr"
)

// TestFetchAzureReplay drives the real azcore pipeline (bearer policy, request
// construction, JSON decoding) against recorded Microsoft Graph responses — no
// Azure tenant or credentials required. Compiled only with `-tags cloud`.
func TestFetchAzureReplay(t *testing.T) {
	rt, err := vcr.Replay(filepath.Join("testdata", "azure-fic.cassette.json"))
	if err != nil {
		t.Fatalf("load cassette: %v", err)
	}

	trusts, err := FetchAzure(context.Background(), Options{Transport: rt, Anonymous: true})
	if err != nil {
		t.Fatalf("FetchAzure: %v", err)
	}

	// Only the GitHub-issuer FIC qualifies; the google-issuer one is filtered.
	if len(trusts) != 1 {
		t.Fatalf("expected 1 GitHub→app trust (google issuer filtered), got %d: %+v", len(trusts), trusts)
	}
	tr := trusts[0]
	if tr.Provider != "azure" {
		t.Errorf("provider = %q, want azure", tr.Provider)
	}
	if tr.RoleARN != "client-aaa" {
		t.Errorf("RoleARN (appId) = %q, want client-aaa", tr.RoleARN)
	}
	if tr.Account != "tenant-1234" {
		t.Errorf("account (tenant) = %q, want tenant-1234", tr.Account)
	}
	if tr.Broadness() != TrustScoped {
		t.Errorf("broadness = %v, want scoped", tr.Broadness())
	}
}
