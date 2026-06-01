package gitlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Su1ph3r/caminus/internal/gitlabci"
	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/platform"
	"github.com/Su1ph3r/caminus/internal/rules"
)

// Enumerator performs read-only enumeration of a GitLab target into a graph.
type Enumerator struct {
	c    *Client
	Logf func(string, ...any) // optional; non-fatal warnings (default no-op)
}

// New wraps a client. Logf defaults to a no-op.
func New(c *Client) *Enumerator {
	return &Enumerator{c: c, Logf: func(string, ...any) {}}
}

// Kind reports the provider.
func (e *Enumerator) Kind() platform.Kind { return platform.GitLab }

// --- API response shapes (only the fields Caminus uses) --------------------

type glProject struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	Visibility        string `json:"visibility"`
	CIConfigPath      string `json:"ci_config_path"`
}

type glFile struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type glRunner struct {
	ID          int    `json:"id"`
	Description string `json:"description"`
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Paused      bool   `json:"paused"`
	IsShared    bool   `json:"is_shared"`
	RunnerType  string `json:"runner_type"`
	Status      string `json:"status"`
}

type glVariable struct {
	Key              string `json:"key"`
	VariableType     string `json:"variable_type"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	EnvironmentScope string `json:"environment_scope"`
}

type glProtectedBranch struct {
	Name string `json:"name"`
}

// Enumerate walks the target and populates g. It is read-only. Optional
// resources that are absent or out of token scope are logged and skipped; only a
// failure to list the target projects is fatal.
func (e *Enumerator) Enumerate(ctx context.Context, _ platform.Credentials, t platform.Target, g *model.Graph) error {
	if t.Org == "" && t.Repo == "" {
		return errors.New("gitlab: target group or project is required")
	}

	var groupID string
	if t.Org != "" {
		groupID = "gl:group:" + t.Org
		g.AddNodeOnce(&model.Node{ID: groupID, Label: t.Org, Kind: model.NodeIdentity, Attrs: map[string]string{"provider": "gitlab"}})
	}

	projects, err := e.listProjects(ctx, t)
	if err != nil {
		return fmt.Errorf("gitlab: list projects: %w", err)
	}
	scope := t.Org
	if scope == "" {
		scope = t.Repo
	}
	e.Logf("enumerating %d project(s) under %s", len(projects), scope)

	for _, p := range projects {
		e.enumerateProject(ctx, p, g)
		if groupID != "" {
			g.AddEdge(groupID, "gl:project:"+p.PathWithNamespace, model.EdgeContains)
		}
	}

	// Group-level runners and CI/CD variables (shared across projects).
	if t.Org != "" {
		e.enumerateGroupRunners(ctx, t.Org, groupID, g)
		e.enumerateGroupVariables(ctx, t.Org, groupID, g)
	}
	return nil
}

func (e *Enumerator) listProjects(ctx context.Context, t platform.Target) ([]glProject, error) {
	if t.Repo != "" {
		var p glProject
		if err := e.c.getJSON(ctx, "/projects/"+pathEsc(t.Repo), &p); err != nil {
			return nil, err
		}
		return []glProject{p}, nil
	}
	var out []glProject
	err := e.c.getList(ctx, "/groups/"+pathEsc(t.Org)+"/projects?include_subgroups=true&with_shared=false", func(b []byte) error {
		var page []glProject
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

func (e *Enumerator) enumerateProject(ctx context.Context, p glProject, g *model.Graph) {
	projID := "gl:project:" + p.PathWithNamespace
	attrs := map[string]string{
		"visibility":     p.Visibility,
		"default_branch": p.DefaultBranch,
		"project_id":     strconv.Itoa(p.ID),
	}
	projNode := g.AddNodeOnce(&model.Node{ID: projID, Label: p.PathWithNamespace, Kind: model.NodeRepo, Attrs: attrs})

	e.enumeratePipeline(ctx, p, projID, projNode, g)
	e.enumerateProjectRunners(ctx, p, projID, g)
	e.enumerateProjectVariables(ctx, p, projID, g)
	e.enumerateProtectedBranches(ctx, p, projNode)
}

// ciConfigPath returns the in-repo pipeline path for a project, honoring a
// customized ci_config_path. An external config (path with "@" or a URL) is not
// fetched from this project's repo; it is reported as a path rather than parsed.
func ciConfigPath(p glProject) (path string, external bool) {
	cfg := strings.TrimSpace(p.CIConfigPath)
	if cfg == "" {
		return ".gitlab-ci.yml", false
	}
	if strings.Contains(cfg, "@") || strings.Contains(cfg, "://") {
		return cfg, true
	}
	return cfg, false
}

func (e *Enumerator) enumeratePipeline(ctx context.Context, p glProject, projID string, projNode *model.Node, g *model.Graph) {
	cfgPath, external := ciConfigPath(p)
	pipeID := "gl:pipeline:" + p.PathWithNamespace + ":" + cfgPath
	attrs := map[string]string{"path": cfgPath, "entrypoint": "false"}

	if external {
		attrs["content_unavailable"] = "true"
		attrs["external_config"] = "true"
		g.AddNodeOnce(&model.Node{ID: pipeID, Label: cfgPath, Kind: model.NodePipeline, Attrs: attrs})
		g.AddEdge(projID, pipeID, model.EdgeContains)
		return
	}

	src, ok := e.fetchFile(ctx, p, cfgPath)
	if !ok {
		// The pipeline file could not be read (commonly: it lives on a branch we
		// can't reach, or the token lacks read_repository). UNASSESSED, not benign.
		attrs["content_unavailable"] = "true"
		g.AddNodeOnce(&model.Node{ID: pipeID, Label: cfgPath, Kind: model.NodePipeline, Attrs: attrs})
		g.AddEdge(projID, pipeID, model.EdgeContains)
		return
	}

	doc := gitlabci.Parse(cfgPath, src)
	attrs["sources"] = strings.Join(doc.Sources(), ",")
	findings := rules.RunGitLab(doc)
	entry := false
	for _, f := range findings {
		if f.Confirmable {
			entry = true
		}
		g.AddFinding(f)
	}
	attrs["findings"] = strconv.Itoa(len(findings))
	attrs["entrypoint"] = strconv.FormatBool(entry)
	g.AddNodeOnce(&model.Node{ID: pipeID, Label: cfgPath, Kind: model.NodePipeline, Attrs: attrs})
	g.AddEdge(projID, pipeID, model.EdgeContains)

	e.enumerateOIDC(p, projID, doc, g)
}

func (e *Enumerator) fetchFile(ctx context.Context, p glProject, path string) ([]byte, bool) {
	ref := p.DefaultBranch
	if ref == "" {
		ref = "HEAD"
	}
	endpoint := fmt.Sprintf("/projects/%d/repository/files/%s?ref=%s", p.ID, pathEsc(path), pathEsc(ref))
	var f glFile
	if err := e.c.getJSON(ctx, endpoint, &f); err != nil {
		e.skip("pipeline file", p.PathWithNamespace+"/"+path, err)
		return nil, false
	}
	if f.Encoding != "base64" {
		return []byte(f.Content), true
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	if err != nil {
		e.skip("pipeline file decode", p.PathWithNamespace+"/"+path, err)
		return nil, false
	}
	return dec, true
}

func (e *Enumerator) enumerateProjectRunners(ctx context.Context, p glProject, projID string, g *model.Graph) {
	runners, err := e.listRunners(ctx, fmt.Sprintf("/projects/%d/runners", p.ID))
	if err != nil {
		if e.skip("project runners", p.PathWithNamespace, err) {
			markIncomplete(g, projID, "runners")
		}
		return
	}
	e.addRunners(runners, "project:"+p.PathWithNamespace, projID, g)
}

func (e *Enumerator) enumerateGroupRunners(ctx context.Context, group, groupID string, g *model.Graph) {
	runners, err := e.listRunners(ctx, "/groups/"+pathEsc(group)+"/runners")
	if err != nil {
		if e.skip("group runners", group, err) {
			markIncomplete(g, groupID, "runners")
		}
		return
	}
	e.addRunners(runners, "group:"+group, groupID, g)
}

func (e *Enumerator) listRunners(ctx context.Context, path string) ([]glRunner, error) {
	var out []glRunner
	err := e.c.getList(ctx, path, func(b []byte) error {
		var page []glRunner
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

func (e *Enumerator) addRunners(runners []glRunner, scope, ownerID string, g *model.Graph) {
	for _, rn := range runners {
		// On GitLab SaaS, shared instance runners are GitLab-hosted; group/project
		// runners (and all runners on self-managed instances) are self-managed and
		// reachable by the owning project's jobs — the higher-risk class.
		selfHosted := !rn.IsShared || rn.RunnerType != "instance_type"
		label := rn.Description
		if label == "" {
			label = rn.Name
		}
		id := "gl:runner:" + strconv.Itoa(rn.ID)
		g.AddNodeOnce(&model.Node{ID: id, Label: label, Kind: model.NodeRunner, Attrs: map[string]string{
			"scope":       scope,
			"runner_type": rn.RunnerType,
			"status":      rn.Status,
			"paused":      strconv.FormatBool(rn.Paused),
			"is_shared":   strconv.FormatBool(rn.IsShared),
			"self_hosted": strconv.FormatBool(selfHosted),
		}})
		g.AddEdge(ownerID, id, model.EdgeRunsOn)
	}
}

func (e *Enumerator) enumerateProjectVariables(ctx context.Context, p glProject, projID string, g *model.Graph) {
	vars, err := e.listVariables(ctx, fmt.Sprintf("/projects/%d/variables", p.ID))
	if err != nil {
		if e.skip("project variables", p.PathWithNamespace, err) {
			markIncomplete(g, projID, "variables")
		}
		return
	}
	for _, v := range vars {
		id := "gl:variable:project:" + p.PathWithNamespace + ":" + v.Key
		g.AddNodeOnce(&model.Node{ID: id, Label: v.Key, Kind: model.NodeSecret, Attrs: variableAttrs("project:"+p.PathWithNamespace, v)})
		g.AddEdge(projID, id, model.EdgeCanRead)
	}
}

func (e *Enumerator) enumerateGroupVariables(ctx context.Context, group, groupID string, g *model.Graph) {
	vars, err := e.listVariables(ctx, "/groups/"+pathEsc(group)+"/variables")
	if err != nil {
		if e.skip("group variables", group, err) {
			markIncomplete(g, groupID, "variables")
		}
		return
	}
	for _, v := range vars {
		id := "gl:variable:group:" + group + ":" + v.Key
		g.AddNodeOnce(&model.Node{ID: id, Label: v.Key, Kind: model.NodeSecret, Attrs: variableAttrs("group:"+group, v)})
		g.AddEdge(groupID, id, model.EdgeCanRead)
	}
}

func variableAttrs(scope string, v glVariable) map[string]string {
	return map[string]string{
		"scope":             scope,
		"protected":         strconv.FormatBool(v.Protected),
		"masked":            strconv.FormatBool(v.Masked),
		"environment_scope": v.EnvironmentScope,
	}
}

func (e *Enumerator) listVariables(ctx context.Context, path string) ([]glVariable, error) {
	var out []glVariable
	err := e.c.getList(ctx, path, func(b []byte) error {
		var page []glVariable
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

func (e *Enumerator) enumerateProtectedBranches(ctx context.Context, p glProject, projNode *model.Node) {
	if p.DefaultBranch == "" {
		return
	}
	var branches []glProtectedBranch
	err := e.c.getList(ctx, fmt.Sprintf("/projects/%d/protected_branches", p.ID), func(b []byte) error {
		var page []glProtectedBranch
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		branches = append(branches, page...)
		return nil
	})
	if err != nil {
		if e.skip("protected branches", p.PathWithNamespace, err) {
			markNodeIncomplete(projNode, "protected_branches")
		}
		return
	}
	protected := false
	for _, b := range branches {
		if b.Name == p.DefaultBranch || branchGlobMatches(b.Name, p.DefaultBranch) {
			protected = true
			break
		}
	}
	projNode.Attrs["default_branch_protected"] = strconv.FormatBool(protected)
}

// branchGlobMatches handles GitLab's wildcard protected-branch names (e.g.
// "main", "release/*", "*") against the default branch.
func branchGlobMatches(pattern, branch string) bool {
	if pattern == "*" {
		return true
	}
	if i := strings.IndexByte(pattern, '*'); i >= 0 {
		return strings.HasPrefix(branch, pattern[:i])
	}
	return pattern == branch
}

var reIDTokens = regexp.MustCompile(`(?m)^\s*id_tokens\s*:`)
var reAud = regexp.MustCompile(`(?m)^\s*aud\s*:\s*["']?([^"'\s#]+)`)

// enumerateOIDC records that a project's pipeline mints GitLab OIDC ID tokens
// (the `id_tokens:` keyword), which is how a GitLab pipeline federates into a
// cloud role. Unlike GitHub, GitLab has no per-project subject customization
// API: the JWT subject is fixed by the instance (project_path:<full>:ref_type:…
// :ref:…). The node records the issuer and representative subject so a later
// GitLab→cloud matching pass (M3) can resolve the blast radius.
func (e *Enumerator) enumerateOIDC(p glProject, projID string, doc *gitlabci.Doc, g *model.Graph) {
	src := strings.Join(doc.Lines, "\n")
	if !reIDTokens.MatchString(src) {
		return
	}
	issuer := "https://gitlab.com"
	if h := e.c.Host(); h != "" {
		issuer = "https://" + h
	}
	branch := p.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	var auds []string
	for _, m := range reAud.FindAllStringSubmatch(src, -1) {
		auds = append(auds, m[1])
	}
	id := "gl:oidc:" + p.PathWithNamespace
	g.AddNodeOnce(&model.Node{ID: id, Label: "OIDC subject: " + p.PathWithNamespace, Kind: model.NodeOIDCTrust, Attrs: map[string]string{
		"id_tokens_used":  "true",
		"oidc_issuer":     issuer,
		"audiences":       strings.Join(auds, ","),
		"subject_pattern": "project_path:" + p.PathWithNamespace + ":ref_type:branch:ref:" + branch,
		"over_broad":      "false",
	}})
	g.AddEdge(projID, id, model.EdgeFederates)
}

// skip logs a non-fatal enumeration error and reports whether it was a GENUINE
// error (transport/5xx/rate-limit) as opposed to "resource absent / out of
// scope" (404/403). A true return means the caller should mark the owning node
// enum_incomplete.
func (e *Enumerator) skip(resource, target string, err error) bool {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) {
		e.Logf("skip %s for %s: %v", resource, target, err)
		return false
	}
	e.Logf("error reading %s for %s: %v", resource, target, err)
	return true
}

// markIncomplete records on a node that a class of resource could not be read.
func markIncomplete(g *model.Graph, nodeID, resource string) {
	markNodeIncomplete(g.Nodes[nodeID], resource)
}

func markNodeIncomplete(n *model.Node, resource string) {
	if n == nil {
		return
	}
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	if prev := n.Attrs["enum_incomplete"]; prev == "" {
		n.Attrs["enum_incomplete"] = resource
	} else if !strings.Contains(prev, resource) {
		n.Attrs["enum_incomplete"] = prev + "," + resource
	}
}
