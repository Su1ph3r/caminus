// Package platform abstracts a CI/CD provider so the enumeration and graph
// stages can treat GitHub Actions, GitLab CI, Jenkins, etc. uniformly.
//
// Multi-platform coverage is a core Caminus differentiator: gato-x is
// GitHub-only and the static scanners stop at YAML patterns. Caminus models each
// provider as a Platform that contributes nodes and edges to the shared trust
// graph (model.Graph), so an attack path can cross provider boundaries (e.g. a
// GitLab pipeline that federates into an AWS role enumerated from cloud).
//
// The interface is defined now to stabilize the contract; concrete clients
// (internal/platform/github, internal/platform/gitlab) land in milestone M2.
package platform

import (
	"context"

	"github.com/Su1ph3r/caminus/internal/model"
)

// Kind identifies a CI/CD provider.
type Kind string

const (
	GitHub Kind = "github"
	GitLab Kind = "gitlab"
)

// Credentials carries the auth material for authenticated enumeration.
type Credentials struct {
	Token   string // PAT / project access token
	BaseURL string // for self-managed instances (e.g. GitLab self-hosted)
}

// Target names what to enumerate (an org/group, a user, or a single repo).
type Target struct {
	Org  string
	Repo string // empty = whole org/group
}

// Platform enumerates a provider's CI/CD attack surface into the trust graph.
type Platform interface {
	// Kind reports the provider this implementation handles.
	Kind() Kind

	// Enumerate walks the target with the given credentials and adds the
	// discovered identities, repos, pipelines, runners, secrets, and OIDC
	// trust relationships to g. Implementations must be read-only.
	Enumerate(ctx context.Context, creds Credentials, t Target, g *model.Graph) error
}
