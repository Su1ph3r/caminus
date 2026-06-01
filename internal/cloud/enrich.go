package cloud

import (
	"context"
	"errors"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
)

// ErrNotBuilt is returned by the stub Fetch when cloud support is not compiled
// in. It lives here (always compiled) so callers can errors.Is against it
// regardless of build tags.
var ErrNotBuilt = errors.New("cloud support not built in; rebuild with: go build -tags cloud")

// Options configures cloud enumeration.
type Options struct {
	Region  string
	Profile string
}

// FetchFunc retrieves GitHub-OIDC IAM trusts. It is implemented by the AWS SDK
// behind the `cloud` build tag (aws.go) and by a stub otherwise (aws_stub.go),
// so Enrich and its tests stay dependency-free.
type FetchFunc func(ctx context.Context, opts Options) ([]GitHubTrust, error)

// repoInfo is the per-repository context needed to match cloud trusts.
type repoInfo struct {
	full          string
	defaultBranch string
	overBroad     bool
	oidcNodeID    string
	hasEntry      bool
}

// Enrich fetches GitHub-OIDC IAM trusts, matches them against the repositories
// already in g, and adds CloudRole nodes + can-assume edges. Where an
// attacker-controllable pipeline can assume a permissively-trusted role it
// emits CAM-OIDC-002 — the full CI-compromise-to-cloud chain. It returns the
// number of can-assume bindings added.
func Enrich(ctx context.Context, g *model.Graph, fetch FetchFunc, opts Options) (int, error) {
	trusts, err := fetch(ctx, opts)
	if err != nil {
		return 0, err
	}
	repos := summarizeRepos(g)

	bindings := 0
	for _, t := range trusts {
		for _, ri := range repos {
			if !t.Assumable(candidateSubjects(ri)) {
				continue
			}
			g.AddNodeOnce(&model.Node{
				ID:    t.RoleARN,
				Label: t.RoleName,
				Kind:  model.NodeCloudRole,
				Attrs: map[string]string{
					"provider":     "aws",
					"account":      t.Account,
					"broadness":    t.Broadness().String(),
					"sub_patterns": strings.Join(t.SubPatterns, " | "),
				},
			})
			from := ri.oidcNodeID
			if from == "" {
				from = "gh:repo:" + ri.full
			}
			g.AddEdge(from, t.RoleARN, model.EdgeCanAssume)
			bindings++

			if ri.hasEntry && t.Broadness() >= TrustRefWildcard {
				g.AddFinding(oidc002(ri, t))
			}
		}
	}
	return bindings, nil
}

func summarizeRepos(g *model.Graph) []*repoInfo {
	infos := map[string]*repoInfo{}
	for _, n := range g.Nodes {
		if n.Kind == model.NodeRepo {
			infos[n.ID] = &repoInfo{
				full:          strings.TrimPrefix(n.ID, "gh:repo:"),
				defaultBranch: n.Attrs["default_branch"],
			}
		}
	}
	for _, n := range g.Nodes {
		if n.Kind != model.NodeOIDCTrust {
			continue
		}
		full := strings.TrimPrefix(n.ID, "gh:oidc:")
		if ri := infos["gh:repo:"+full]; ri != nil {
			ri.oidcNodeID = n.ID
			ri.overBroad = n.Attrs["over_broad"] == "true"
		}
	}
	for _, e := range g.Edges {
		if e.Kind != model.EdgeContains {
			continue
		}
		ri := infos[e.From]
		if ri == nil {
			continue
		}
		if p := g.Nodes[e.To]; p != nil && p.Kind == model.NodePipeline && p.Attrs["entrypoint"] == "true" {
			ri.hasEntry = true
		}
	}
	out := make([]*repoInfo, 0, len(infos))
	for _, ri := range infos {
		out = append(out, ri)
	}
	return out
}

// candidateSubjects builds the OIDC subjects a repository's runs could present.
func candidateSubjects(ri *repoInfo) []string {
	branch := ri.defaultBranch
	if branch == "" {
		branch = "main"
	}
	subs := []string{
		"repo:" + ri.full + ":ref:refs/heads/" + branch,
		"repo:" + ri.full + ":pull_request",
		"repo:" + ri.full + ":environment:production",
	}
	if ri.overBroad {
		// an over-broad subject lets the repo present any context; this probe
		// matches only ref-wildcard (or broader) trust patterns.
		subs = append(subs, "repo:"+ri.full+":__caminus_any__")
	}
	return subs
}

func oidc002(ri *repoInfo, t GitHubTrust) model.Finding {
	sev := model.SevHigh
	if t.Broadness() >= TrustRepoWildcard {
		sev = model.SevCritical
	}
	return model.Finding{
		RuleID:   "CAM-OIDC-002",
		Title:    "Attacker-controllable pipeline can assume cloud role " + t.RoleName,
		Severity: sev,
		Category: model.CatOIDC,
		File:     ri.full,
		Evidence: "role " + t.RoleARN + " trust=" + t.Broadness().String() + " sub=" + strings.Join(t.SubPatterns, " | "),
		Description: "Repository " + ri.full + " has an attacker-controllable pipeline (entry point) and " +
			"federates to AWS role " + t.RoleARN + ", whose trust policy (" + t.Broadness().String() + ") admits " +
			"a subject this repository's runs can present. A poisoned pipeline can mint a GitHub OIDC token, " +
			"call sts:AssumeRoleWithWebIdentity, and obtain that role's permissions in account " + t.Account + ".",
		Remediation: "Constrain the role's trust sub condition to specific protected branches/environments " +
			"(no repo-wide or ref wildcards), require the aud condition, and remove the pipeline's " +
			"attacker-controllable trigger or isolate privileged jobs.",
		Confirmable: true,
		References: []string{
			"https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/ (CICD-SEC-6)",
		},
	}
}
