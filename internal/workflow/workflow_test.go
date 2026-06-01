package workflow

import "testing"

func TestTriggersQuotedOnKey(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"\"on\":\n  pull_request_target:\n    types: [opened]\n", "pull_request_target"},
		{"'on': push\n", "push"},
		{"\"on\": [push, pull_request]\n", "pull_request"},
	}
	for _, c := range cases {
		d := Parse("t.yml", []byte(c.src))
		if !d.HasTrigger(c.want) {
			t.Errorf("quoted on: %q → triggers %v, missing %q", c.src, d.Triggers(), c.want)
		}
	}
	// quoted child trigger name
	d := Parse("t.yml", []byte("on:\n  \"pull_request_target\":\n    types: [opened]\n"))
	if !d.HasTrigger("pull_request_target") {
		t.Errorf("quoted child key → triggers %v", d.Triggers())
	}
}

func TestParseStripsBOM(t *testing.T) {
	d := Parse("t.yml", []byte("\ufeffon: pull_request_target\n"))
	if !d.HasTrigger("pull_request_target") {
		t.Errorf("leading BOM defeated trigger detection: %v", d.Triggers())
	}
}

func TestInRunContextNotEnvValue(t *testing.T) {
	// An env: string value containing the text "run: " must NOT be treated as a
	// run step (it is data, not a shell command).
	src := "jobs:\n  a:\n    steps:\n      - env:\n          NOTE: \"please run: x\"\n        run: echo hi\n"
	d := Parse("t.yml", []byte(src))
	if d.InRunContext(4) { // the NOTE line
		t.Error("env value containing 'run: ' was wrongly detected as a run context")
	}
	if !d.InRunContext(5) { // the real run: line
		t.Error("real run: line was not detected as a run context")
	}
}

func TestTriggersUnquotedStillWorks(t *testing.T) {
	d := Parse("t.yml", []byte("on:\n  push:\n  pull_request_target:\n"))
	if !d.HasTrigger("push") || !d.HasTrigger("pull_request_target") {
		t.Errorf("unquoted on: regressed: %v", d.Triggers())
	}
}
