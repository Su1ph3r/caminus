package github

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/platform"
	"github.com/Su1ph3r/caminus/internal/vcr"
)

// enumFromCassette replays the recorded API responses (no token) and returns
// the populated graph.
func enumFromCassette(t *testing.T) *model.Graph {
	t.Helper()
	rt, err := vcr.Replay(filepath.Join("testdata", "widgets.cassette.json"))
	if err != nil {
		t.Fatalf("load cassette: %v", err)
	}
	c := NewClient(platform.Credentials{}, &http.Client{Transport: rt})
	g := model.NewGraph()
	if err := New(c).Enumerate(context.Background(), platform.Credentials{}, platform.Target{Org: "acme", Repo: "widgets"}, g); err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	return g
}

func TestEnumerateBuildsGraph(t *testing.T) {
	g := enumFromCassette(t)

	mustNode := func(id string, kind model.NodeKind) *model.Node {
		n, ok := g.Nodes[id]
		if !ok {
			t.Fatalf("missing node %q", id)
		}
		if n.Kind != kind {
			t.Errorf("node %q kind = %q, want %q", id, n.Kind, kind)
		}
		return n
	}

	mustNode("gh:org:acme", model.NodeIdentity)
	repo := mustNode("gh:repo:acme/widgets", model.NodeRepo)
	if repo.Attrs["default_branch"] != "main" {
		t.Errorf("repo default_branch = %q, want main", repo.Attrs["default_branch"])
	}
	if repo.Attrs["default_branch_protected"] != "false" {
		t.Errorf("expected default_branch_protected=false (404 protection), got %q", repo.Attrs["default_branch_protected"])
	}

	pipe := mustNode("gh:pipeline:acme/widgets:.github/workflows/release.yml", model.NodePipeline)
	if pipe.Attrs["entrypoint"] != "true" {
		t.Errorf("expected pwn-request workflow to be an entry point, got entrypoint=%q", pipe.Attrs["entrypoint"])
	}

	runner := mustNode("gh:runner:7", model.NodeRunner)
	if runner.Attrs["self_hosted"] != "true" {
		t.Errorf("expected self_hosted=true runner, got %q", runner.Attrs["self_hosted"])
	}

	mustNode("gh:secret:repo:acme/widgets:PROD_DEPLOY_KEY", model.NodeSecret)
	mustNode("gh:secret:org:acme:ORG_NPM_TOKEN", model.NodeSecret)
	oidc := mustNode("gh:oidc:acme/widgets", model.NodeOIDCTrust)
	if oidc.Attrs["subject_pattern"] == "" {
		t.Error("oidc node missing subject_pattern")
	}
	// The fixture's subject includes "context" (scoped), so it is not over-broad
	// and must not raise CAM-OIDC-001.
	if oidc.Attrs["over_broad"] != "false" {
		t.Errorf("oidc over_broad = %q, want false", oidc.Attrs["over_broad"])
	}
	if len(g.Findings) != 0 {
		t.Errorf("expected no enumeration findings for scoped OIDC, got %d", len(g.Findings))
	}

	// org -> repo containment edge exists
	var hasContain bool
	for _, e := range g.Edges {
		if e.From == "gh:org:acme" && e.To == "gh:repo:acme/widgets" && e.Kind == model.EdgeContains {
			hasContain = true
		}
	}
	if !hasContain {
		t.Error("missing org→repo contains edge")
	}
}

func TestEnumerateMissingOrg(t *testing.T) {
	c := NewClient(platform.Credentials{}, &http.Client{})
	err := New(c).Enumerate(context.Background(), platform.Credentials{}, platform.Target{}, model.NewGraph())
	if err == nil {
		t.Fatal("expected error for empty org")
	}
}

func TestNextLink(t *testing.T) {
	link := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`
	if got := nextLink(link); got != "https://api.github.com/x?page=2" {
		t.Errorf("nextLink = %q", got)
	}
	if got := nextLink(""); got != "" {
		t.Errorf("nextLink(empty) = %q", got)
	}
}
