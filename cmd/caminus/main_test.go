package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoute(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{nil, "help"},
		{[]string{"--help"}, "help"},
		{[]string{"-v"}, "version"},
		{[]string{"version"}, "version"},
		{[]string{"scan", "x"}, "scan"},
		{[]string{"enum"}, "enum"},
		{[]string{"bogus"}, "bogus"},
	}
	for _, c := range cases {
		if got, _ := route(c.argv); got != c.want {
			t.Errorf("route(%v) = %q, want %q", c.argv, got, c.want)
		}
	}
}

func TestRunExitCodes(t *testing.T) {
	if rc := run([]string{"version"}); rc != 0 {
		t.Errorf("version rc = %d, want 0", rc)
	}
	if rc := run([]string{"help"}); rc != 0 {
		t.Errorf("help rc = %d, want 0", rc)
	}
	if rc := run([]string{"bogus"}); rc != 2 {
		t.Errorf("unknown command rc = %d, want 2", rc)
	}
}

func TestRunScanGate(t *testing.T) {
	vuln := filepath.Join("..", "..", "testdata", "vuln-pwn-request.yml")
	if rc := run([]string{"scan", vuln}); rc != 1 {
		t.Errorf("scan of vuln fixture rc = %d, want 1 (gate hit)", rc)
	}

	safe := filepath.Join("..", "..", "testdata", "safe.yml")
	if rc := run([]string{"scan", safe}); rc != 0 {
		t.Errorf("scan of safe fixture rc = %d, want 0", rc)
	}

	// --gate none must not fail even on critical findings.
	if rc := run([]string{"scan", vuln, "--gate", "none"}); rc != 0 {
		t.Errorf("scan with --gate none rc = %d, want 0", rc)
	}
}

func TestExploitArmGate(t *testing.T) {
	// Arming without ownership acknowledgment must be refused.
	if rc := run([]string{"exploit", "--arm", "--finding", "CAM-OIDC-002"}); rc != 2 {
		t.Errorf("exploit --arm without --i-own-target rc = %d, want 2", rc)
	}
	// No graph and no scan source is a usage error.
	if rc := run([]string{"exploit", "-i", filepath.Join(t.TempDir(), "absent.json")}); rc != 2 {
		t.Errorf("exploit with absent -i rc = %d, want 2", rc)
	}
}

func TestExploitGeneratesFromScan(t *testing.T) {
	dir := t.TempDir()
	scan := filepath.Join(dir, "scan.json")
	// A confirmable injection finding, as `scan --format json` would emit.
	report := `{"tool":"caminus","version":"t","findings":[
	  {"rule_id":"CAM-INJ-001","title":"Untrusted input in run:","severity":"critical",
	   "category":"expression-injection","file":".github/workflows/ci.yml","line":12,"confirmable":true}],
	  "summary":{"total":1,"critical":1}}`
	if err := os.WriteFile(scan, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "poc")
	// No -i: the default graph path is unset/absent, so the scan report is the
	// sole finding source (a non-explicit missing -i is not an error).
	rc := run([]string{"exploit", "--scan", scan, "--finding", "CAM-INJ-001", "--repo", "me/mine", "-o", out})
	if rc != 0 {
		t.Fatalf("exploit from scan rc = %d, want 0", rc)
	}
	plan := filepath.Join(out, "cam-inj-001-me_mine", "PLAN.md")
	if _, err := os.Stat(plan); err != nil {
		t.Errorf("expected generated PLAN.md at %s: %v", plan, err)
	}
}

func TestExploitCorruptDefaultGraphIsFatal(t *testing.T) {
	// A present-but-corrupt DEFAULT graph.json must be fatal (not silently treated
	// as absent). A genuinely-absent default + a scan source stays exit 0.
	dir := t.TempDir()
	t.Chdir(dir)
	scan := filepath.Join(dir, "scan.json")
	report := `{"tool":"caminus","version":"t","findings":[
	  {"rule_id":"CAM-INJ-001","title":"x","severity":"critical","category":"expression-injection",
	   "file":".github/workflows/ci.yml","line":1,"confirmable":true}],"summary":{"total":1}}`
	if err := os.WriteFile(scan, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	// Absent default graph.json + scan → exit 0 (scan-only flow).
	if rc := run([]string{"exploit", "--scan", scan, "--repo", "me/mine", "-o", filepath.Join(dir, "p1")}); rc != 0 {
		t.Errorf("absent default graph rc = %d, want 0", rc)
	}
	// Corrupt default graph.json present → exit 2 even with a valid scan source.
	if err := os.WriteFile(filepath.Join(dir, "graph.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := run([]string{"exploit", "--scan", scan, "--repo", "me/mine", "-o", filepath.Join(dir, "p2")}); rc != 2 {
		t.Errorf("corrupt default graph rc = %d, want 2", rc)
	}
}

func TestAnalyzeFilePropagatesLoadError(t *testing.T) {
	// The fix: analyzeFile now returns the load error instead of swallowing it and
	// reporting zero findings (which would let the scan gate pass over an
	// unassessed file). A directory path makes the underlying ReadFile fail.
	if _, err := analyzeFile(t.TempDir(), "github"); err == nil {
		t.Error("analyzeFile must return an error for an unreadable path, not nil")
	}
	if _, err := analyzeFile(t.TempDir(), "gitlab"); err == nil {
		t.Error("analyzeFile (gitlab) must return an error for an unreadable path")
	}
	// Backward compatibility: a normal scan of the safe fixture still exits 0.
	if rc := run([]string{"scan", filepath.Join("..", "..", "testdata", "safe.yml")}); rc != 0 {
		t.Errorf("safe fixture rc = %d, want 0", rc)
	}
}

func TestExploitArmNonArmableFallsBackToPlaybook(t *testing.T) {
	dir := t.TempDir()
	scan := filepath.Join(dir, "scan.json")
	// Injection is not auto-armable; --arm must fall back to the manual playbook
	// (no token required, exit 0) rather than erroring.
	report := `{"tool":"caminus","version":"t","findings":[
	  {"rule_id":"CAM-INJ-001","title":"x","severity":"critical","category":"expression-injection",
	   "file":".github/workflows/ci.yml","line":1,"confirmable":true}],"summary":{"total":1}}`
	if err := os.WriteFile(scan, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := run([]string{"exploit", "--scan", scan, "--finding", "CAM-INJ-001", "--repo", "me/mine",
		"-o", filepath.Join(dir, "poc"), "--arm", "--i-own-target"})
	if rc != 0 {
		t.Errorf("--arm on a non-armable finding rc = %d, want 0 (playbook fallback)", rc)
	}
}
