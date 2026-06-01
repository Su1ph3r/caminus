package cloud

import (
	"context"
	"testing"

	"github.com/Su1ph3r/caminus/internal/model"
)

func graphWithEntry() *model.Graph {
	g := model.NewGraph()
	g.AddNode(&model.Node{ID: "gh:repo:acme/widgets", Label: "acme/widgets", Kind: model.NodeRepo,
		Attrs: map[string]string{"default_branch": "main"}})
	g.AddNode(&model.Node{ID: "gh:oidc:acme/widgets", Label: "oidc", Kind: model.NodeOIDCTrust,
		Attrs: map[string]string{"over_broad": "false"}})
	g.AddNode(&model.Node{ID: "pipe", Label: "Release", Kind: model.NodePipeline,
		Attrs: map[string]string{"entrypoint": "true"}})
	g.AddEdge("gh:repo:acme/widgets", "pipe", model.EdgeContains)
	g.AddEdge("gh:repo:acme/widgets", "gh:oidc:acme/widgets", model.EdgeFederates)
	return g
}

func fetchTrusts(ts ...GitHubTrust) FetchFunc {
	return func(context.Context, Options) ([]GitHubTrust, error) { return ts, nil }
}

func TestEnrichAddsRoleEdgeAndFinding(t *testing.T) {
	g := graphWithEntry()
	role := GitHubTrust{
		RoleARN: "arn:aws:iam::123456789012:role/deployer", RoleName: "deployer",
		Account: "123456789012", SubPatterns: []string{"repo:acme/widgets:*"}, HasSub: true,
	}
	n, err := Enrich(context.Background(), g, fetchTrusts(role), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected >=1 assumable binding, got %d", n)
	}
	if node, ok := g.Nodes[role.RoleARN]; !ok || node.Kind != model.NodeCloudRole {
		t.Errorf("expected cloud-role node for %s", role.RoleARN)
	}
	var edge bool
	for _, e := range g.Edges {
		if e.From == "gh:oidc:acme/widgets" && e.To == role.RoleARN && e.Kind == model.EdgeCanAssume {
			edge = true
		}
	}
	if !edge {
		t.Error("expected can-assume edge from OIDC node to cloud role")
	}
	var found *model.Finding
	for i := range g.Findings {
		if g.Findings[i].RuleID == "CAM-OIDC-002" {
			found = &g.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("expected CAM-OIDC-002 (attacker-controllable pipeline → cloud role)")
	}
	if found.Severity != model.SevHigh {
		t.Errorf("CAM-OIDC-002 severity = %q, want high (ref-wildcard role)", found.Severity)
	}
	if !found.Confirmable {
		t.Error("CAM-OIDC-002 should be Confirmable")
	}
}

func TestEnrichScopedToOtherRepoNoMatch(t *testing.T) {
	g := graphWithEntry()
	role := GitHubTrust{
		RoleARN: "arn:aws:iam::123456789012:role/other", RoleName: "other",
		SubPatterns: []string{"repo:someoneelse/repo:ref:refs/heads/main"}, HasSub: true,
	}
	n, err := Enrich(context.Background(), g, fetchTrusts(role), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 bindings for a role scoped to another repo, got %d", n)
	}
	if _, ok := g.Nodes[role.RoleARN]; ok {
		t.Error("no cloud-role node should be added for an unmatched role")
	}
}

func TestEnrichRepoWildcardIsCritical(t *testing.T) {
	g := graphWithEntry()
	role := GitHubTrust{
		RoleARN: "arn:aws:iam::1:role/broad", RoleName: "broad",
		SubPatterns: []string{"repo:acme/*:*"}, HasSub: true,
	}
	if _, err := Enrich(context.Background(), g, fetchTrusts(role), Options{}); err != nil {
		t.Fatal(err)
	}
	var sev model.Severity
	for _, f := range g.Findings {
		if f.RuleID == "CAM-OIDC-002" {
			sev = f.Severity
		}
	}
	if sev != model.SevCritical {
		t.Errorf("repo-wildcard trust → CAM-OIDC-002 severity = %q, want critical", sev)
	}
}
