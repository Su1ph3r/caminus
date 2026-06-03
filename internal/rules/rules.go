// Package rules implements Caminus's static attack-surface rules over CI/CD
// pipeline definitions. Each rule encodes a known pipeline-attack primitive and
// emits findings annotated with the attack taxonomy and whether the result is
// dynamically confirmable by the exploit stage.
package rules

import (
	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// Rule is a single static detector over a pipeline document.
type Rule interface {
	ID() string
	Apply(doc *workflow.Doc) []model.Finding
}

// Default returns the built-in GitHub Actions rule set. Order is presentation
// order only; severities drive prioritization.
func Default() []Rule {
	return []Rule{
		ExpressionInjection{},
		InlineEnvInjection{},
		IndirectPPE{},
		ReusableWorkflowInjection{},
		CompositeActionInjection{},
		PwnRequest{},
		SelfHostedRunner{},
		ExcessivePermissions{},
		UnpinnedAction{},
	}
}

// Run applies every rule to a document and returns the merged findings.
func Run(doc *workflow.Doc, rs []Rule) []model.Finding {
	var out []model.Finding
	for _, r := range rs {
		out = append(out, r.Apply(doc)...)
	}
	return out
}
