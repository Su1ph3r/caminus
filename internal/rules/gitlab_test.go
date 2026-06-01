package rules

import (
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/gitlabci"
	"github.com/Su1ph3r/caminus/internal/model"
)

func glScanFixture(t *testing.T, name string) []model.Finding {
	t.Helper()
	doc, err := gitlabci.Load(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return RunGitLab(doc)
}

func TestGitLabVulnProducesExpectedRules(t *testing.T) {
	fs := glScanFixture(t, "gitlab-vuln.gitlab-ci.yml")

	want := map[string]bool{
		"CAM-GL-INJ-001": false, // script injection
		"CAM-GL-PPE-001": false, // MR exposure
		"CAM-GL-DBG-001": false, // debug trace
		"CAM-GL-RUN-001": false, // dind
		"CAM-GL-SUP-001": false, // unpinned include
	}
	var critical, injConfirmable int
	for _, f := range fs {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
		if f.Severity == model.SevCritical {
			critical++
		}
		if f.RuleID == "CAM-GL-INJ-001" && f.Confirmable {
			injConfirmable++
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected GitLab rule %s to fire on vuln fixture", id)
		}
	}
	if critical < 2 {
		t.Errorf("expected >=2 critical findings (two script injections), got %d", critical)
	}
	if injConfirmable < 2 {
		t.Errorf("expected both script injections marked Confirmable, got %d", injConfirmable)
	}
}

func TestGitLabSafeIsClean(t *testing.T) {
	fs := glScanFixture(t, "gitlab-safe.gitlab-ci.yml")
	if len(fs) != 0 {
		for _, f := range fs {
			t.Logf("unexpected finding: %s %s:%d (%s)", f.RuleID, f.File, f.Line, f.Severity)
		}
		t.Errorf("gitlab-safe should produce 0 findings, got %d", len(fs))
	}
}

func TestGitLabParserPrimitives(t *testing.T) {
	doc := gitlabci.Parse(".gitlab-ci.yml", []byte(
		"job:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - echo \"$CI_COMMIT_MESSAGE\"\n"))
	if !doc.MergeRequestTriggered() {
		t.Error("expected MergeRequestTriggered() == true")
	}
	// the echo line (index 4) is inside script:
	if !doc.ExecContext(4) {
		t.Error("expected ExecContext(4) == true for the script command")
	}
	// the rules/if line (index 2) is NOT a script context
	if doc.ExecContext(2) {
		t.Error("expected ExecContext(2) == false for the rules: if line")
	}
}
