package main

import (
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
