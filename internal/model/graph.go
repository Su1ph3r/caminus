package model

// The trust graph is Caminus's differentiator: it models a CI/CD compromise as a
// reachability problem from an attacker-controllable trigger to a high-value
// asset (a secret, a self-hosted runner, or — via OIDC — a cloud role and the
// resources behind it). The static `scan` stage seeds nodes; the authenticated
// `enum` stage fills in runners, secret names, environments, and OIDC trust;
// the `graph` stage walks edges to synthesize attack paths.
//
// These types are deliberately minimal in the current milestone — they pin the
// shape of the model so the enum/graph stages build on a stable contract.

// NodeKind enumerates the entities Caminus tracks across a pipeline ecosystem.
type NodeKind string

const (
	NodeIdentity  NodeKind = "identity"   // a user, bot, or service account that can push/PR
	NodeRepo      NodeKind = "repo"       // a source repository
	NodePipeline  NodeKind = "pipeline"   // a workflow / .gitlab-ci.yml / Jenkinsfile
	NodeJob       NodeKind = "job"        // a job within a pipeline
	NodeTrigger   NodeKind = "trigger"    // an event that starts a pipeline (PR, comment, cron)
	NodeRunner    NodeKind = "runner"     // a runner/executor (hosted or self-hosted)
	NodeSecret    NodeKind = "secret"     // a CI secret / variable / environment secret
	NodeOIDCTrust NodeKind = "oidc-trust" // a federation trust policy (CI subject -> cloud)
	NodeCloudRole NodeKind = "cloud-role" // an assumable cloud identity (AWS role, GCP SA, Azure app)
	NodeResource  NodeKind = "resource"   // a cloud resource reachable via a role
)

// EdgeKind enumerates the relationships between nodes.
type EdgeKind string

const (
	EdgeContains  EdgeKind = "contains"        // org -> repo, repo -> pipeline
	EdgeTriggers  EdgeKind = "triggers"        // trigger -> pipeline
	EdgeRunsOn    EdgeKind = "runs-on"         // job -> runner
	EdgeCanRead   EdgeKind = "can-read-secret" // job -> secret
	EdgeFederates EdgeKind = "federates-to"    // pipeline -> oidc-trust
	EdgeCanAssume EdgeKind = "can-assume"      // oidc-trust -> cloud-role
	EdgeReaches   EdgeKind = "reaches"         // cloud-role -> resource
	EdgeEscalates EdgeKind = "escalates-to"    // any -> any (privilege escalation primitive)
)

// Node is a vertex in the trust graph.
type Node struct {
	ID    string            `json:"id"`
	Label string            `json:"label"`
	Kind  NodeKind          `json:"kind"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	From  string            `json:"from"`
	To    string            `json:"to"`
	Kind  EdgeKind          `json:"kind"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Graph is the trust graph for a target ecosystem.
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge           `json:"edges"`
}

// NewGraph returns an empty graph ready for AddNode/AddEdge.
func NewGraph() *Graph {
	return &Graph{Nodes: make(map[string]*Node)}
}

// AddNode inserts or replaces a node by ID and returns it.
func (g *Graph) AddNode(n *Node) *Node {
	g.Nodes[n.ID] = n
	return n
}

// AddNodeOnce inserts n only if its ID is not already present, returning the
// node that ends up in the graph (existing or new). Useful when the same
// runner/secret/identity is discovered from multiple repos.
func (g *Graph) AddNodeOnce(n *Node) *Node {
	if ex, ok := g.Nodes[n.ID]; ok {
		return ex
	}
	g.Nodes[n.ID] = n
	return n
}

// AddEdge appends a directed edge.
func (g *Graph) AddEdge(from, to string, kind EdgeKind) {
	g.Edges = append(g.Edges, Edge{From: from, To: to, Kind: kind})
}

// AttackStep is one hop in a synthesized attack path.
type AttackStep struct {
	NodeID    string `json:"node_id"`
	Technique string `json:"technique"`
	MITRE     string `json:"mitre,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// AttackPath is a synthesized chain from an attacker-controllable entry point to
// a high-value asset, with the cloud/secret blast radius it unlocks.
type AttackPath struct {
	Title       string       `json:"title"`
	Severity    Severity     `json:"severity"`
	Steps       []AttackStep `json:"steps"`
	BlastRadius []string     `json:"blast_radius,omitempty"`
}
