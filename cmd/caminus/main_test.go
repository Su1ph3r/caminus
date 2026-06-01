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
