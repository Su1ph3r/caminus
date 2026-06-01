package gitlab

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/platform"
	"github.com/Su1ph3r/caminus/internal/vcr"
)

func enumFromCassette(t *testing.T) *model.Graph {
	t.Helper()
	rt, err := vcr.Replay(filepath.Join("testdata", "acme.cassette.json"))
	if err != nil {
		t.Fatalf("load cassette: %v", err)
	}
	c := NewClient(platform.Credentials{}, &http.Client{Transport: rt})
	g := model.NewGraph()
	if err := New(c).Enumerate(context.Background(), platform.Credentials{}, platform.Target{Org: "acme"}, g); err != nil {
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

	mustNode("gl:group:acme", model.NodeIdentity)
	proj := mustNode("gl:project:acme/widgets", model.NodeRepo)
	if proj.Attrs["default_branch"] != "main" {
		t.Errorf("project default_branch = %q, want main", proj.Attrs["default_branch"])
	}
	if proj.Attrs["visibility"] != "private" {
		t.Errorf("project visibility = %q, want private", proj.Attrs["visibility"])
	}
	if proj.Attrs["default_branch_protected"] != "true" {
		t.Errorf("expected default_branch_protected=true, got %q", proj.Attrs["default_branch_protected"])
	}

	pipe := mustNode("gl:pipeline:acme/widgets:.gitlab-ci.yml", model.NodePipeline)
	if pipe.Attrs["entrypoint"] != "true" {
		t.Errorf("expected MR-triggered injection pipeline to be an entry point, got entrypoint=%q", pipe.Attrs["entrypoint"])
	}

	runner := mustNode("gl:runner:7", model.NodeRunner)
	if runner.Attrs["self_hosted"] != "true" {
		t.Errorf("expected self_hosted=true (project runner), got %q", runner.Attrs["self_hosted"])
	}

	v := mustNode("gl:variable:project:acme/widgets:DEPLOY_TOKEN", model.NodeSecret)
	if v.Attrs["protected"] != "true" || v.Attrs["masked"] != "true" {
		t.Errorf("DEPLOY_TOKEN protected/masked = %q/%q, want true/true", v.Attrs["protected"], v.Attrs["masked"])
	}
	mustNode("gl:variable:group:acme:GROUP_NPM_TOKEN", model.NodeSecret)

	oidc := mustNode("gl:oidc:acme/widgets", model.NodeOIDCTrust)
	if oidc.Attrs["id_tokens_used"] != "true" {
		t.Errorf("expected id_tokens_used=true, got %q", oidc.Attrs["id_tokens_used"])
	}
	if oidc.Attrs["audiences"] != "https://gitlab.com" {
		t.Errorf("oidc audiences = %q, want https://gitlab.com", oidc.Attrs["audiences"])
	}

	// CAM-GL-INJ-001 (Critical) must be present in the graph findings.
	var hasInj bool
	for _, f := range g.Findings {
		if f.RuleID == "CAM-GL-INJ-001" && f.Severity == model.SevCritical {
			hasInj = true
		}
	}
	if !hasInj {
		t.Errorf("expected CAM-GL-INJ-001 critical finding, got %+v", g.Findings)
	}

	// group -> project containment edge exists
	var hasContain bool
	for _, e := range g.Edges {
		if e.From == "gl:group:acme" && e.To == "gl:project:acme/widgets" && e.Kind == model.EdgeContains {
			hasContain = true
		}
	}
	if !hasContain {
		t.Error("missing group→project contains edge")
	}
}

func TestEnumerateMissingTarget(t *testing.T) {
	c := NewClient(platform.Credentials{}, &http.Client{})
	err := New(c).Enumerate(context.Background(), platform.Credentials{}, platform.Target{}, model.NewGraph())
	if err == nil {
		t.Fatal("expected error for empty group/project target")
	}
}

func TestSkipDistinguishesAbsentFromError(t *testing.T) {
	e := New(NewClient(platform.Credentials{}, &http.Client{}))
	if e.skip("x", "y", ErrForbidden) {
		t.Error("ErrForbidden (out of scope) should be skippable, not flagged incomplete")
	}
	if e.skip("x", "y", ErrNotFound) {
		t.Error("ErrNotFound (absent) should be skippable, not flagged incomplete")
	}
	if !e.skip("x", "y", errors.New("connection reset")) {
		t.Error("a genuine transport error should mark the graph incomplete")
	}
}

func TestBranchGlobMatches(t *testing.T) {
	cases := []struct {
		pattern, branch string
		want            bool
	}{
		{"main", "main", true},
		{"*", "anything", true},
		{"release/*", "release/1.0", true},
		{"release/*", "main", false},
		{"develop", "main", false},
	}
	for _, c := range cases {
		if got := branchGlobMatches(c.pattern, c.branch); got != c.want {
			t.Errorf("branchGlobMatches(%q,%q) = %v, want %v", c.pattern, c.branch, got, c.want)
		}
	}
}
