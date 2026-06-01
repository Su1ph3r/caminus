package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/platform"
	"github.com/Su1ph3r/caminus/internal/rules"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// Enumerator performs read-only enumeration of a GitHub target into a graph.
type Enumerator struct {
	c    *Client
	Logf func(string, ...any) // optional; non-fatal warnings (default no-op)
}

// New wraps a client. Logf defaults to a no-op.
func New(c *Client) *Enumerator {
	return &Enumerator{c: c, Logf: func(string, ...any) {}}
}

// Kind reports the provider.
func (e *Enumerator) Kind() platform.Kind { return platform.GitHub }

// --- API response shapes (only the fields Caminus uses) --------------------

type repo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

type workflowList struct {
	Workflows []struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		State string `json:"state"`
	} `json:"workflows"`
}

type contentResp struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type runnerList struct {
	Runners []struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		OS     string `json:"os"`
		Status string `json:"status"`
		Labels []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"labels"`
	} `json:"runners"`
}

type secretList struct {
	Secrets []struct {
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	} `json:"secrets"`
}

type oidcSub struct {
	UseDefault       bool     `json:"use_default"`
	IncludeClaimKeys []string `json:"include_claim_keys"`
}

// Enumerate walks the target and populates g. It is read-only. Optional
// resources that are absent or out of token scope are logged and skipped;
// only a failure to list the target repositories is fatal.
func (e *Enumerator) Enumerate(ctx context.Context, _ platform.Credentials, t platform.Target, g *model.Graph) error {
	if t.Org == "" {
		return errors.New("github: target org/owner is required")
	}
	orgID := "gh:org:" + t.Org
	g.AddNodeOnce(&model.Node{ID: orgID, Label: t.Org, Kind: model.NodeIdentity, Attrs: map[string]string{"provider": "github"}})

	repos, err := e.listRepos(ctx, t)
	if err != nil {
		return fmt.Errorf("github: list repositories: %w", err)
	}
	e.Logf("enumerating %d repo(s) under %s", len(repos), t.Org)

	for _, r := range repos {
		e.enumerateRepo(ctx, t.Org, r, g)
		g.AddEdge(orgID, "gh:repo:"+r.FullName, model.EdgeContains)
	}

	// Org-level runners and secrets (shared across repos).
	e.enumerateOrgRunners(ctx, t.Org, g)
	e.enumerateOrgSecrets(ctx, t.Org, g)
	return nil
}

func (e *Enumerator) listRepos(ctx context.Context, t platform.Target) ([]repo, error) {
	if t.Repo != "" {
		var r repo
		if err := e.c.getJSON(ctx, "/repos/"+t.Org+"/"+t.Repo, &r); err != nil {
			return nil, err
		}
		if r.FullName == "" {
			r.FullName = t.Org + "/" + t.Repo
		}
		return []repo{r}, nil
	}
	var out []repo
	err := e.c.getList(ctx, "/orgs/"+t.Org+"/repos?type=all", func(b []byte) error {
		var page []repo
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

func (e *Enumerator) enumerateRepo(ctx context.Context, owner string, r repo, g *model.Graph) {
	repoID := "gh:repo:" + r.FullName
	attrs := map[string]string{
		"private":        strconv.FormatBool(r.Private),
		"default_branch": r.DefaultBranch,
	}
	repoNode := g.AddNodeOnce(&model.Node{ID: repoID, Label: r.FullName, Kind: model.NodeRepo, Attrs: attrs})

	e.enumerateWorkflows(ctx, r, repoID, g)
	e.enumerateRepoRunners(ctx, r, repoID, g)
	e.enumerateRepoSecrets(ctx, r, repoID, g)
	e.enumerateOIDC(ctx, r, repoID, g)
	e.enumerateBranchProtection(ctx, r, repoNode)
}

func (e *Enumerator) enumerateWorkflows(ctx context.Context, r repo, repoID string, g *model.Graph) {
	var wl workflowList
	if err := e.c.getJSON(ctx, "/repos/"+r.FullName+"/actions/workflows", &wl); err != nil {
		e.skip("workflows", r.FullName, err)
		return
	}
	for _, w := range wl.Workflows {
		pipeID := "gh:pipeline:" + r.FullName + ":" + w.Path
		attrs := map[string]string{"path": w.Path, "state": w.State}

		if src, ok := e.fetchContent(ctx, r.FullName, w.Path); ok {
			doc := workflow.Parse(w.Path, src)
			attrs["triggers"] = strings.Join(doc.Triggers(), ",")
			findings := rules.Run(doc, rules.Default())
			entry, maxRank := false, 0
			for _, f := range findings {
				if f.Confirmable {
					entry = true
				}
				if f.Severity.Rank() > maxRank {
					maxRank = f.Severity.Rank()
				}
			}
			attrs["findings"] = strconv.Itoa(len(findings))
			attrs["entrypoint"] = strconv.FormatBool(entry)
		}
		g.AddNodeOnce(&model.Node{ID: pipeID, Label: w.Name, Kind: model.NodePipeline, Attrs: attrs})
		g.AddEdge(repoID, pipeID, model.EdgeContains)
	}
}

func (e *Enumerator) fetchContent(ctx context.Context, fullName, path string) ([]byte, bool) {
	var cr contentResp
	if err := e.c.getJSON(ctx, "/repos/"+fullName+"/contents/"+path, &cr); err != nil {
		e.skip("workflow content", fullName+"/"+path, err)
		return nil, false
	}
	if cr.Encoding != "base64" {
		return []byte(cr.Content), true
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cr.Content, "\n", ""))
	if err != nil {
		return nil, false
	}
	return dec, true
}

func (e *Enumerator) enumerateRepoRunners(ctx context.Context, r repo, repoID string, g *model.Graph) {
	var rl runnerList
	if err := e.c.getJSON(ctx, "/repos/"+r.FullName+"/actions/runners", &rl); err != nil {
		e.skip("repo runners", r.FullName, err)
		return
	}
	e.addRunners(rl, "repo:"+r.FullName, repoID, g)
}

func (e *Enumerator) enumerateOrgRunners(ctx context.Context, org string, g *model.Graph) {
	var rl runnerList
	if err := e.c.getJSON(ctx, "/orgs/"+org+"/actions/runners", &rl); err != nil {
		e.skip("org runners", org, err)
		return
	}
	e.addRunners(rl, "org:"+org, "gh:org:"+org, g)
}

func (e *Enumerator) addRunners(rl runnerList, scope, ownerID string, g *model.Graph) {
	for _, rn := range rl.Runners {
		selfHosted := true
		var labels []string
		for _, l := range rn.Labels {
			labels = append(labels, l.Name)
			if isHostedLabel(l.Name) {
				selfHosted = false
			}
		}
		id := "gh:runner:" + strconv.Itoa(rn.ID)
		g.AddNodeOnce(&model.Node{ID: id, Label: rn.Name, Kind: model.NodeRunner, Attrs: map[string]string{
			"scope":       scope,
			"os":          rn.OS,
			"status":      rn.Status,
			"self_hosted": strconv.FormatBool(selfHosted),
			"labels":      strings.Join(labels, ","),
		}})
		g.AddEdge(ownerID, id, model.EdgeRunsOn)
	}
}

func (e *Enumerator) enumerateRepoSecrets(ctx context.Context, r repo, repoID string, g *model.Graph) {
	var sl secretList
	if err := e.c.getJSON(ctx, "/repos/"+r.FullName+"/actions/secrets", &sl); err != nil {
		e.skip("repo secrets", r.FullName, err)
		return
	}
	for _, s := range sl.Secrets {
		id := "gh:secret:repo:" + r.FullName + ":" + s.Name
		g.AddNodeOnce(&model.Node{ID: id, Label: s.Name, Kind: model.NodeSecret, Attrs: map[string]string{"scope": "repo:" + r.FullName}})
		g.AddEdge(repoID, id, model.EdgeCanRead)
	}
}

func (e *Enumerator) enumerateOrgSecrets(ctx context.Context, org string, g *model.Graph) {
	var sl secretList
	if err := e.c.getJSON(ctx, "/orgs/"+org+"/actions/secrets", &sl); err != nil {
		e.skip("org secrets", org, err)
		return
	}
	for _, s := range sl.Secrets {
		id := "gh:secret:org:" + org + ":" + s.Name
		g.AddNodeOnce(&model.Node{ID: id, Label: s.Name, Kind: model.NodeSecret, Attrs: map[string]string{
			"scope":      "org:" + org,
			"visibility": s.Visibility,
		}})
		g.AddEdge("gh:org:"+org, id, model.EdgeCanRead)
	}
}

func (e *Enumerator) enumerateOIDC(ctx context.Context, r repo, repoID string, g *model.Graph) {
	var sub oidcSub
	if err := e.c.getJSON(ctx, "/repos/"+r.FullName+"/actions/oidc/customization/sub", &sub); err != nil {
		e.skip("oidc sub", r.FullName, err)
		return
	}
	id := "gh:oidc:" + r.FullName
	g.AddNodeOnce(&model.Node{ID: id, Label: "OIDC subject: " + r.FullName, Kind: model.NodeOIDCTrust, Attrs: map[string]string{
		"use_default": strconv.FormatBool(sub.UseDefault),
		"claim_keys":  strings.Join(sub.IncludeClaimKeys, ","),
		"oidc_issuer": "token.actions.githubusercontent.com",
	}})
	g.AddEdge(repoID, id, model.EdgeFederates)
}

func (e *Enumerator) enumerateBranchProtection(ctx context.Context, r repo, repoNode *model.Node) {
	if r.DefaultBranch == "" {
		return
	}
	err := e.c.getJSON(ctx, "/repos/"+r.FullName+"/branches/"+r.DefaultBranch+"/protection", nil)
	switch {
	case err == nil:
		repoNode.Attrs["default_branch_protected"] = "true"
	case errors.Is(err, ErrNotFound):
		// 404 here means the branch has no protection rule.
		repoNode.Attrs["default_branch_protected"] = "false"
	default:
		e.skip("branch protection", r.FullName, err)
	}
}

func (e *Enumerator) skip(resource, target string, err error) {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) {
		e.Logf("skip %s for %s: %v", resource, target, err)
		return
	}
	e.Logf("error reading %s for %s: %v", resource, target, err)
}

// isHostedLabel reports whether a runner label identifies a GitHub-hosted
// runner (so its absence implies self-hosted).
func isHostedLabel(name string) bool {
	switch strings.ToLower(name) {
	case "ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04", "ubuntu-20.04",
		"windows-latest", "windows-2022", "windows-2019",
		"macos-latest", "macos-14", "macos-13", "macos-12":
		return true
	}
	return false
}
