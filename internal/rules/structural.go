//go:build yaml

// Structural YAML parsing (opt-in, `-tags yaml`). This augments — does not
// replace — the line model: rules still report line numbers and original text
// from the line model, while the structural parser supplies alias/anchor- and
// flow-resolved facts the textual scan cannot recover. The dependency
// (gopkg.in/yaml.v3) is isolated here behind the build tag so the default
// binary stays dependency-free, mirroring the cloud-SDK isolation.
package rules

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

// structuredGitHubSources parses the workflow with a real YAML parser and
// returns the untrusted-env name set with anchors and aliases resolved — e.g.
// `TITLE: *prTitle` where the anchor `&prTitle ${{ github.event.pull_request.title }}`
// is defined elsewhere, which the line-model regex cannot connect. Triggers are
// taken from the (already alias-tolerant) line model. On a parse error it
// reports ok=false so the caller falls back to the line model rather than
// silently under-reporting.
func structuredGitHubSources(doc *workflow.Doc) (map[string]bool, []string, bool) {
	var root interface{}
	if err := yaml.Unmarshal([]byte(strings.Join(doc.Lines, "\n")), &root); err != nil {
		return nil, nil, false
	}
	names := map[string]bool{}
	walkEnvMaps(root, names)
	triggers := doc.Triggers()
	if hasAny(triggers, "pull_request", "pull_request_target") {
		names["GITHUB_HEAD_REF"] = true
	}
	return names, triggers, true
}

// walkEnvMaps recursively descends the decoded YAML (maps and sequences),
// scanning every `env:` mapping it finds at any scope (workflow, job, step).
// Decoding into interface{} resolves anchors/aliases, so an env value supplied
// by an alias is seen here with its real, dereferenced text.
func walkEnvMaps(node interface{}, names map[string]bool) {
	switch v := node.(type) {
	case map[string]interface{}:
		if env, ok := v["env"].(map[string]interface{}); ok {
			for k, val := range env {
				if s, ok := val.(string); ok && valueIsUntrusted(s) {
					names[k] = true
				}
			}
		}
		for _, val := range v {
			walkEnvMaps(val, names)
		}
	case []interface{}:
		for _, val := range v {
			walkEnvMaps(val, names)
		}
	}
}
