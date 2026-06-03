//go:build !yaml

package rules

import "github.com/Su1ph3r/caminus/internal/workflow"

// structuredGitHubSources is the no-op stub used in the default, dependency-free
// build. It reports ok=false so callers fall back to the line model. Build with
// `-tags yaml` to enable structural parsing (anchor/alias/flow resolution) via
// gopkg.in/yaml.v3.
func structuredGitHubSources(_ *workflow.Doc) (map[string]bool, []string, bool) {
	return nil, nil, false
}
