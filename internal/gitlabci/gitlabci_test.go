package gitlabci

import "testing"

func TestIncludesRefBeforeProject(t *testing.T) {
	// ref: written before project: (valid — YAML keys are unordered) must still
	// be captured, so a SHA-pinned include is recognized as safe.
	src := "include:\n  - ref: 0123456789abcdef0123456789abcdef01234567\n    project: 'g/p'\n    file: '/x.yml'\n"
	incs := Parse(".gitlab-ci.yml", []byte(src)).Includes()
	if len(incs) != 1 {
		t.Fatalf("want 1 include, got %d: %+v", len(incs), incs)
	}
	if incs[0].Kind != "project" {
		t.Errorf("kind = %q, want project", incs[0].Kind)
	}
	if incs[0].Ref != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("ref = %q (ref-before-project not captured)", incs[0].Ref)
	}
}

func TestIncludesProjectFileNotDoubleCounted(t *testing.T) {
	// file: is a sub-key of a project include, not a separate include.
	src := "include:\n  - project: 'g/p'\n    ref: main\n    file: '/x.yml'\n"
	incs := Parse(".gitlab-ci.yml", []byte(src)).Includes()
	if len(incs) != 1 {
		t.Fatalf("want 1 include (file: not separate), got %d: %+v", len(incs), incs)
	}
	if incs[0].Kind != "project" || incs[0].Ref != "main" {
		t.Errorf("got %+v", incs[0])
	}
}

func TestIncludesInlineSelfContained(t *testing.T) {
	incs := Parse(".gitlab-ci.yml", []byte("include: 'local.yml'\n")).Includes()
	if len(incs) != 1 || incs[0].Kind != "local" {
		t.Errorf("inline include: %+v", incs)
	}
}

func TestParseStripsBOM(t *testing.T) {
	d := Parse(".gitlab-ci.yml", []byte("\ufeffinclude:\n  - remote: 'https://example.com/x.yml'\n"))
	incs := d.Includes()
	if len(incs) != 1 || incs[0].Kind != "remote" {
		t.Errorf("leading BOM defeated include parsing: %+v", incs)
	}
}

func TestExecContextBOM(t *testing.T) {
	// A BOM before script: must not make the script body fall out of context.
	d := Parse(".gitlab-ci.yml", []byte("\ufeffjob:\n  script:\n    - echo \"$CI_COMMIT_MESSAGE\"\n"))
	if !d.ExecContext(2) { // the echo line
		t.Error("BOM before script: defeated ExecContext detection")
	}
}
