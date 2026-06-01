package graph

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/caminus/internal/model"
)

// sampleGraph builds: org → repo → pipeline(entry), with the repo holding a
// repo secret, an org secret (via org), a self-hosted runner, and OIDC trust.
func sampleGraph() *model.Graph {
	g := model.NewGraph()
	g.AddNode(&model.Node{ID: "gh:org:acme", Label: "acme", Kind: model.NodeIdentity})
	g.AddNode(&model.Node{ID: "gh:repo:acme/widgets", Label: "acme/widgets", Kind: model.NodeRepo})
	g.AddNode(&model.Node{ID: "pipe", Label: "Release", Kind: model.NodePipeline,
		Attrs: map[string]string{"entrypoint": "true", "triggers": "pull_request_target"}})
	g.AddNode(&model.Node{ID: "secret:repo", Label: "PROD_KEY", Kind: model.NodeSecret,
		Attrs: map[string]string{"scope": "repo:acme/widgets"}})
	g.AddNode(&model.Node{ID: "secret:org", Label: "ORG_TOKEN", Kind: model.NodeSecret,
		Attrs: map[string]string{"scope": "org:acme"}})
	g.AddNode(&model.Node{ID: "runner", Label: "selfhost-1", Kind: model.NodeRunner,
		Attrs: map[string]string{"self_hosted": "true"}})
	g.AddNode(&model.Node{ID: "oidc", Label: "oidc", Kind: model.NodeOIDCTrust})

	g.AddEdge("gh:org:acme", "gh:repo:acme/widgets", model.EdgeContains)
	g.AddEdge("gh:repo:acme/widgets", "pipe", model.EdgeContains)
	g.AddEdge("gh:repo:acme/widgets", "secret:repo", model.EdgeCanRead)
	g.AddEdge("gh:org:acme", "secret:org", model.EdgeCanRead)
	g.AddEdge("gh:repo:acme/widgets", "runner", model.EdgeRunsOn)
	g.AddEdge("gh:repo:acme/widgets", "oidc", model.EdgeFederates)
	return g
}

func TestSynthesizeFindsRankedPaths(t *testing.T) {
	paths := Synthesize(sampleGraph())

	if len(paths) != 4 {
		t.Fatalf("expected 4 attack paths (repo secret, org secret, runner, oidc), got %d", len(paths))
	}

	// Highest-scored path is the self-hosted runner (sink value 4, short path).
	if !strings.Contains(paths[0].Title, "self-hosted runner") {
		t.Errorf("expected top path to reach the self-hosted runner, got %q", paths[0].Title)
	}
	if paths[0].Severity != model.SevCritical {
		t.Errorf("runner path severity = %q, want critical (confirmable entry bump)", paths[0].Severity)
	}

	// Every path starts at the pipeline entry with the PPE technique.
	for _, p := range paths {
		if len(p.Steps) == 0 || p.Steps[0].MITRE != "T1059" {
			t.Errorf("path %q: first step should be the PPE entry (T1059), got %+v", p.Title, p.Steps)
		}
	}

	// Find the runner path and check its terminal technique.
	for _, p := range paths {
		if strings.Contains(p.Title, "self-hosted runner") {
			last := p.Steps[len(p.Steps)-1]
			if last.MITRE != "T1543" {
				t.Errorf("runner sink MITRE = %q, want T1543", last.MITRE)
			}
		}
	}
}

func TestSynthesizeNoEntryPoints(t *testing.T) {
	g := model.NewGraph()
	g.AddNode(&model.Node{ID: "pipe", Label: "CI", Kind: model.NodePipeline,
		Attrs: map[string]string{"entrypoint": "false", "triggers": "push"}})
	g.AddNode(&model.Node{ID: "s", Label: "X", Kind: model.NodeSecret, Attrs: map[string]string{"scope": "repo:x"}})
	g.AddEdge("pipe", "s", model.EdgeCanRead)
	if got := Synthesize(g); len(got) != 0 {
		t.Errorf("expected no paths when no entry points, got %d", len(got))
	}
}
