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

func TestEnrichMatchesEnumeratedEnvironment(t *testing.T) {
	// A role scoped to a specific environment is assumable only if that
	// environment was enumerated. Previously only "production" was probed; now
	// candidate subjects are derived from the repo's enumerated environments.
	g := graphWithEntry()
	g.Nodes["gh:repo:acme/widgets"].Attrs["environments"] = "staging"
	role := GitHubTrust{
		RoleARN: "arn:aws:iam::123456789012:role/staging-deploy", RoleName: "staging-deploy",
		SubPatterns: []string{"repo:acme/widgets:environment:staging"}, HasSub: true,
	}
	n, err := Enrich(context.Background(), g, fetchTrusts(role), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected a binding for the env-scoped role via the enumerated environment, got %d", n)
	}
	if _, ok := g.Nodes[role.RoleARN]; !ok {
		t.Error("expected a cloud-role node for the env-scoped role")
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

func gitlabGraphWithEntry() *model.Graph {
	g := model.NewGraph()
	g.AddNode(&model.Node{ID: "gl:project:acme/widgets", Label: "acme/widgets", Kind: model.NodeRepo,
		Attrs: map[string]string{"default_branch": "main"}})
	g.AddNode(&model.Node{ID: "gl:oidc:acme/widgets", Label: "oidc", Kind: model.NodeOIDCTrust,
		Attrs: map[string]string{"over_broad": "false"}})
	g.AddNode(&model.Node{ID: "glpipe", Label: "deploy", Kind: model.NodePipeline,
		Attrs: map[string]string{"entrypoint": "true"}})
	g.AddEdge("gl:project:acme/widgets", "glpipe", model.EdgeContains)
	g.AddEdge("gl:project:acme/widgets", "gl:oidc:acme/widgets", model.EdgeFederates)
	return g
}

func TestEnrichGitLabProjectMatch(t *testing.T) {
	g := gitlabGraphWithEntry()
	role := GitHubTrust{
		Provider: "aws", Issuer: "gitlab.com",
		RoleARN: "arn:aws:iam::1:role/gl-deployer", RoleName: "gl-deployer", Account: "1",
		SubPatterns: []string{"project_path:acme/widgets:*"}, HasSub: true,
	}
	n, err := Enrich(context.Background(), g, fetchTrusts(role), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected a GitLab→cloud binding, got %d", n)
	}
	var edge bool
	for _, e := range g.Edges {
		if e.From == "gl:oidc:acme/widgets" && e.To == role.RoleARN && e.Kind == model.EdgeCanAssume {
			edge = true
		}
	}
	if !edge {
		t.Error("expected can-assume edge from the GitLab OIDC node to the cloud role")
	}
	var found bool
	for _, f := range g.Findings {
		if f.RuleID == "CAM-OIDC-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected CAM-OIDC-002 for the GitLab project")
	}
}

func TestEnrichPlatformGate(t *testing.T) {
	// A no-subject-condition GitHub federation must NOT be reported as assumable
	// from a GitLab project (and vice versa) — only the matching CI platform.
	glGraph := gitlabGraphWithEntry()
	ghTrust := GitHubTrust{Provider: "aws", Issuer: GitHubOIDCIssuer,
		RoleARN: "arn:aws:iam::1:role/gh-any", HasSub: false}
	if n, _ := Enrich(context.Background(), glGraph, fetchTrusts(ghTrust), Options{}); n != 0 {
		t.Errorf("GitHub no-subject trust matched a GitLab project (%d bindings); platform gate failed", n)
	}

	ghGraph := graphWithEntry()
	glTrust := GitHubTrust{Provider: "aws", Issuer: "gitlab.com",
		RoleARN: "arn:aws:iam::1:role/gl-any", HasSub: false}
	if n, _ := Enrich(context.Background(), ghGraph, fetchTrusts(glTrust), Options{}); n != 0 {
		t.Errorf("GitLab no-subject trust matched a GitHub repo (%d bindings); platform gate failed", n)
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
