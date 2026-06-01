package rules

import (
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

func scanFixture(t *testing.T, name string) []model.Finding {
	t.Helper()
	doc, err := workflow.Load(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return Run(doc, Default())
}

func TestVulnWorkflowProducesExpectedRules(t *testing.T) {
	fs := scanFixture(t, "vuln-pwn-request.yml")

	want := map[string]bool{
		"CAM-PPE-001":  false, // pwn request
		"CAM-INJ-001":  false, // expression injection
		"CAM-RUN-001":  false, // self-hosted runner
		"CAM-PERM-001": false, // write-all
		"CAM-SUP-001":  false, // unpinned action
	}
	var critical int
	for _, f := range fs {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
		if f.Severity == model.SevCritical {
			critical++
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected rule %s to fire on vuln fixture", id)
		}
	}
	if critical < 2 {
		t.Errorf("expected >=2 critical findings, got %d", critical)
	}

	var pwnConfirmable bool
	for _, f := range fs {
		if f.RuleID == "CAM-PPE-001" && f.Confirmable {
			pwnConfirmable = true
		}
	}
	if !pwnConfirmable {
		t.Error("pwn-request finding must be marked Confirmable")
	}
}

func TestSafeWorkflowIsClean(t *testing.T) {
	fs := scanFixture(t, "safe.yml")
	if len(fs) != 0 {
		for _, f := range fs {
			t.Logf("unexpected finding: %s %s:%d (%s)", f.RuleID, f.File, f.Line, f.Severity)
		}
		t.Errorf("safe.yml should produce 0 findings, got %d", len(fs))
	}
}

func TestInjectionOnlyFiresInRunContext(t *testing.T) {
	// In a run: step → Critical, confirmable.
	inRun := workflow.Parse("t.yml", []byte(
		"jobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n"))
	got := ExpressionInjection{}.Apply(inRun)
	if len(got) != 1 || got[0].Severity != model.SevCritical || !got[0].Confirmable {
		t.Fatalf("run-context injection: want 1 critical confirmable, got %+v", got)
	}

	// Routed through env: (the recommended remediation) → no finding.
	inEnv := workflow.Parse("t.yml", []byte(
		"jobs:\n  a:\n    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo \"$T\"\n"))
	if got := (ExpressionInjection{}).Apply(inEnv); len(got) != 0 {
		t.Errorf("env-routed expression should not be flagged, got %+v", got)
	}
}
