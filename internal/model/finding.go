// Package model holds the core data types shared across Caminus: findings from
// the static analysis engine and the trust-graph primitives used by the
// enumeration and attack-path stages.
package model

// Severity ranks a finding. Ordering is defined by Rank so callers can filter
// by a minimum threshold without string comparisons.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank returns a numeric weight for a severity; higher is more severe. Unknown
// values rank below info so they never satisfy a minimum-severity filter.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}

// Category maps a finding to the CI/CD attack taxonomy. The values track the
// OWASP Top 10 CI/CD Security Risks (CICD-SEC-*) and the Poisoned Pipeline
// Execution (PPE) classes from the Palo Alto / Cider research, so findings line
// up with how operators reason about pipeline attacks.
type Category string

const (
	CatInjection   Category = "expression-injection"  // CICD-SEC-4: script/expression injection
	CatPwnRequest  Category = "pwn-request"           // Public-PPE: fork-triggered run with secrets
	CatPPEDirect   Category = "direct-ppe"            // attacker controls the pipeline definition
	CatPPEIndirect Category = "indirect-ppe"          // injection into an existing pipeline definition
	CatRunner      Category = "runner-exposure"       // CICD-SEC-7: self-hosted runner reachable by untrusted code
	CatPermissions Category = "excessive-permissions" // CICD-SEC-5: over-broad token scope
	CatSupplyChain Category = "unpinned-dependency"   // CICD-SEC-3: third-party action not pinned to a digest
	CatOIDC        Category = "oidc-trust"            // CICD-SEC-6: over-permissive cloud federation
	CatSecret      Category = "secret-exposure"       // CICD-SEC-6: credential surfaced to untrusted code
)

// Finding is a single result from the static analysis engine.
//
// Confirmable marks findings the `caminus exploit` stage can dynamically prove
// against a target you own — the property that separates Caminus from the
// static-only scanners: a flagged pwn-request is not just a YAML pattern, it is
// a claim that can be turned into a malicious PR and observed executing.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Evidence    string   `json:"evidence,omitempty"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Confirmable bool     `json:"confirmable"`
	References  []string `json:"references,omitempty"`
}
