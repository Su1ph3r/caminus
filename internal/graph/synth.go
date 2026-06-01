// Package graph synthesizes attack paths over a Caminus trust graph: it walks
// from attacker-controllable entry points (poisonable pipelines) to high-value
// sinks (secrets, self-hosted runners, and — once cloud data is present —
// OIDC-federated roles and resources), then ranks the resulting paths.
package graph

import (
	"sort"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
)

// privilegedTriggers are GitHub triggers that expose secrets/tokens to
// externally influenced runs, so a pipeline carrying one is a candidate entry
// point even without a confirmed static finding.
var privilegedTriggers = map[string]bool{
	"pull_request_target": true,
	"workflow_run":        true,
	"issue_comment":       true,
	"issues":              true,
	"pull_request":        true,
	"fork":                true,
}

// entryWeight returns how strong a pipeline is as an attack entry point:
// 2 = a confirmable static finding lands here, 1 = a privileged/fork trigger
// only, 0 = not an entry point.
func entryWeight(n *model.Node) int {
	if n.Kind != model.NodePipeline {
		return 0
	}
	if n.Attrs["entrypoint"] == "true" {
		return 2
	}
	for _, t := range strings.Split(n.Attrs["triggers"], ",") {
		if privilegedTriggers[strings.TrimSpace(t)] {
			return 1
		}
	}
	return 0
}

// sinkValue scores a node as an attack target; 0 means "not a sink".
func sinkValue(n *model.Node) int {
	switch n.Kind {
	case model.NodeCloudRole, model.NodeResource:
		return 5
	case model.NodeRunner:
		if n.Attrs["self_hosted"] == "true" {
			return 4
		}
		return 0 // hosted runners are ephemeral, not a persistence target
	case model.NodeOIDCTrust:
		if n.Attrs["over_broad"] == "true" {
			return 4 // repo-wide federation token is a stronger pivot to cloud
		}
		return 3
	case model.NodeSecret:
		if strings.HasPrefix(n.Attrs["scope"], "org:") {
			return 3
		}
		return 2
	}
	return 0
}

// buildAdjacency turns the trust graph into a directed reachability graph for
// path-finding. Containment edges are walked child→parent (a pipeline reaches
// its repo, a repo reaches its org); capability edges (can-read, runs-on,
// federates, can-assume, reaches) are walked forward. This models "what a
// poisoned pipeline can touch" rather than raw graph direction.
func buildAdjacency(g *model.Graph) map[string][]string {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		switch e.Kind {
		case model.EdgeContains:
			adj[e.To] = append(adj[e.To], e.From) // child -> parent
		case model.EdgeCanRead, model.EdgeRunsOn, model.EdgeFederates,
			model.EdgeCanAssume, model.EdgeReaches, model.EdgeEscalates:
			adj[e.From] = append(adj[e.From], e.To) // forward
		}
	}
	return adj
}

// reachableSinks BFSes from start and returns, for each reachable sink, the
// shortest path (node IDs from start to sink inclusive).
func reachableSinks(g *model.Graph, adj map[string][]string, start string) map[string][]string {
	prev := map[string]string{}
	visited := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		neighbors := adj[cur]
		// deterministic traversal for stable output
		sort.Strings(neighbors)
		for _, nb := range neighbors {
			if visited[nb] {
				continue
			}
			visited[nb] = true
			prev[nb] = cur
			queue = append(queue, nb)
		}
	}
	out := map[string][]string{}
	for id := range visited {
		if id == start {
			continue
		}
		n := g.Nodes[id]
		if n == nil || sinkValue(n) == 0 {
			continue
		}
		path := []string{id}
		for cur := id; cur != start; {
			p := prev[cur]
			path = append([]string{p}, path...)
			cur = p
		}
		out[id] = path
	}
	return out
}

type scored struct {
	path  model.AttackPath
	score float64
}

// Synthesize walks every entry point to every reachable sink and returns the
// attack paths ranked by score (descending). Score rewards strong entry points
// and valuable sinks, and penalizes longer paths.
func Synthesize(g *model.Graph) []model.AttackPath {
	adj := buildAdjacency(g)
	var ranked []scored

	for _, n := range g.Nodes {
		w := entryWeight(n)
		if w == 0 {
			continue
		}
		for sinkID, ids := range reachableSinks(g, adj, n.ID) {
			sink := g.Nodes[sinkID]
			ranked = append(ranked, scored{
				path:  buildPath(g, n, sink, ids, w),
				score: float64(w*sinkValue(sink)) / float64(len(ids)),
			})
		}
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].path.Title < ranked[j].path.Title
	})

	out := make([]model.AttackPath, len(ranked))
	for i, r := range ranked {
		out[i] = r.path
	}
	return out
}

func buildPath(g *model.Graph, entry, sink *model.Node, ids []string, w int) model.AttackPath {
	steps := make([]model.AttackStep, 0, len(ids))
	for _, id := range ids {
		steps = append(steps, stepFor(g.Nodes[id], id == entry.ID))
	}
	return model.AttackPath{
		Title:       entry.Label + " → " + sinkLabel(sink),
		Severity:    pathSeverity(w, sink),
		Steps:       steps,
		BlastRadius: []string{sinkLabel(sink)},
	}
}

// stepFor maps a node to an attack technique with a MITRE ATT&CK ID. The entry
// node is always the poisoned-pipeline primitive; every other node is labelled
// by kind, whether it is the terminal sink or an intermediate hop.
func stepFor(n *model.Node, isEntry bool) model.AttackStep {
	// Guard before dereferencing: a node ID can appear on a path via a dangling
	// edge (an endpoint absent from Nodes, e.g. a hand-edited or truncated
	// graph.json), in which case g.Nodes[id] is nil.
	if n == nil {
		return model.AttackStep{}
	}
	s := model.AttackStep{NodeID: n.ID}
	if isEntry {
		s.Technique = "Poisoned Pipeline Execution"
		s.MITRE = "T1059"
		s.Detail = "attacker-controllable pipeline (" + n.Attrs["triggers"] + ")"
		return s
	}
	switch n.Kind {
	case model.NodeSecret:
		s.Technique = "Credential access from CI secret"
		s.MITRE = "T1552"
		s.Detail = n.Attrs["scope"]
	case model.NodeRunner:
		s.Technique = "Self-hosted runner code execution / persistence"
		s.MITRE = "T1543"
		s.Detail = n.Attrs["scope"]
	case model.NodeOIDCTrust:
		s.Technique = "Cloud access via OIDC federation"
		s.MITRE = "T1550.001"
	case model.NodeCloudRole, model.NodeResource:
		s.Technique = "Assume cloud role"
		s.MITRE = "T1078.004"
		s.Detail = n.Attrs["broadness"]
	case model.NodeRepo:
		s.Technique = "Repository scope"
		s.Detail = "transit"
	case model.NodeIdentity:
		s.Technique = "Organization scope"
		s.Detail = "transit"
	}
	return s
}

func pathSeverity(entryWeight int, sink *model.Node) model.Severity {
	sev := model.SevMedium
	switch sinkValue(sink) {
	case 4, 5:
		sev = model.SevHigh
	case 3:
		sev = model.SevHigh
	default:
		sev = model.SevMedium
	}
	if entryWeight >= 2 { // confirmable entry point — bump one level
		switch sev {
		case model.SevHigh:
			sev = model.SevCritical
		case model.SevMedium:
			sev = model.SevHigh
		}
	}
	return sev
}

func sinkLabel(n *model.Node) string {
	switch n.Kind {
	case model.NodeSecret:
		return "secret " + n.Label
	case model.NodeRunner:
		return "self-hosted runner " + n.Label
	case model.NodeOIDCTrust:
		return "OIDC federation"
	case model.NodeCloudRole:
		return "cloud role " + n.Label
	case model.NodeResource:
		return "resource " + n.Label
	}
	return n.Label
}
