package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/caminus/internal/gitlabci"
	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// writeRepo lays out a fake repo under t.TempDir() from a path→content map and
// returns the root. Paths use forward slashes; parent dirs are created.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func ghFindings(t *testing.T, root string) []string {
	t.Helper()
	doc, err := workflow.Load(filepath.Join(root, ".github", "workflows", "wf.yml"))
	if err != nil {
		t.Fatalf("load workflow: %v", err)
	}
	var ids []string
	for _, f := range (IndirectPPE{}).Apply(doc) {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// wfAliasedEnv defines the untrusted value via a YAML anchor (&t) and consumes
// it through an alias (*t) in a different scope. The ALIASED entry's own line
// carries no ${{ }}, so only a structural parse can tell it is untrusted. Used
// by the build-tagged tests that contrast line-model vs structural behavior.
const wfAliasedEnv = `name: ci
on: [pull_request_target]
env:
  TITLE: &t ${{ github.event.pull_request.title }}
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ALIASED: *t
    steps:
      - run: bash ./ci/build.sh
`

const wfEnvRoutedShell = `name: ci
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - uses: actions/checkout@v4
      - run: bash ./ci/build.sh
`

func TestIndirectPPE_EnvRoutedUnsafeShell(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell,
		"ci/build.sh":              "#!/bin/bash\necho building $TITLE\n", // unquoted
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("expected CAM-PPE-002 for unquoted $TITLE in executed script, got %v", ids)
	}
}

func TestIndirectPPE_SafeWhenQuoted(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell,
		"ci/build.sh":              "#!/bin/bash\necho building \"$TITLE\"\n", // quoted — safe
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("quoted \"$TITLE\" is the recommended-safe pattern; should NOT flag, got %v", ids)
	}
}

func TestIndirectPPE_EvalIsUnsafeEvenQuoted(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell,
		"ci/build.sh":              "#!/bin/bash\neval \"$TITLE\"\n", // eval re-parses as code
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("eval of an untrusted var is unsafe regardless of quoting, got %v", ids)
	}
}

func TestIndirectPPE_CommandSubstitutionUnsafe(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell,
		"ci/build.sh":              "#!/bin/bash\nout=$(echo $TITLE | sh)\n", // unquoted inside $()
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("unquoted var inside command substitution is unsafe, got %v", ids)
	}
}

func TestIndirectPPE_NoFindingWithoutAttackerTrigger(t *testing.T) {
	wf := `name: ci
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: bash ./ci/build.sh
`
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"ci/build.sh":              "#!/bin/bash\necho $TITLE\n",
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("push-only workflow delivers no attacker input; should NOT flag, got %v", ids)
	}
}

func TestIndirectPPE_NoFindingWhenScriptAbsent(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell, // references ci/build.sh, not created
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("no on-disk script to analyze; must not speculate, got %v", ids)
	}
}

func TestIndirectPPE_HeadRefViaMakefile(t *testing.T) {
	wf := `name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make deploy
`
	// In a make recipe a shell env var is written $$VAR; GITHUB_HEAD_REF is the
	// attacker-named source branch, injected by GitHub on pull_request.
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"Makefile":                 "deploy:\n\techo $$GITHUB_HEAD_REF\n",
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("expected CAM-PPE-002 for unquoted $$GITHUB_HEAD_REF in Makefile recipe, got %v", ids)
	}
}

func TestIndirectPPE_PackageJSONScript(t *testing.T) {
	wf := `name: ci
on: [issue_comment]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BODY: ${{ github.event.comment.body }}
    steps:
      - run: npm ci
`
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"package.json":             `{"scripts": {"preinstall": "echo $BODY > /tmp/x"}}`,
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("expected CAM-PPE-002 for unquoted $BODY in package.json script, got %v", ids)
	}
}

// --- GitLab ----------------------------------------------------------------

func glIndirectFindings(t *testing.T, root string) []string {
	t.Helper()
	doc, err := gitlabci.Load(filepath.Join(root, ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("load gitlab ci: %v", err)
	}
	var ids []string
	for _, f := range (GLIndirectInjection{}).Apply(doc) {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func TestGLIndirectInjection_UnsafeShell(t *testing.T) {
	ci := `build:
  script:
    - bash ci/deploy.sh
`
	root := writeRepo(t, map[string]string{
		".gitlab-ci.yml": ci,
		"ci/deploy.sh":   "#!/bin/bash\ngit log --grep $CI_COMMIT_MESSAGE\n", // unquoted CI var
	})
	if ids := glIndirectFindings(t, root); !has(ids, "CAM-GL-INJ-002") {
		t.Fatalf("expected CAM-GL-INJ-002 for unquoted $CI_COMMIT_MESSAGE, got %v", ids)
	}
}

func TestGLIndirectInjection_SafeWhenQuoted(t *testing.T) {
	ci := `build:
  script:
    - bash ci/deploy.sh
`
	root := writeRepo(t, map[string]string{
		".gitlab-ci.yml": ci,
		"ci/deploy.sh":   "#!/bin/bash\ngit log --grep \"$CI_COMMIT_MESSAGE\"\n", // quoted
	})
	if ids := glIndirectFindings(t, root); has(ids, "CAM-GL-INJ-002") {
		t.Fatalf("quoted CI var is safe; should NOT flag, got %v", ids)
	}
}

// --- quote analyzer unit tests ---------------------------------------------

func TestShellUnsafeUse(t *testing.T) {
	names := map[string]bool{"X": true}
	cases := []struct {
		line   string
		unsafe bool
	}{
		{`echo $X`, true},
		{`echo "$X"`, false},
		{`echo '$X'`, false},
		{`echo ${X}`, true},
		{`echo "${X}"`, false},
		{`eval "$X"`, true},
		{`foo=$(echo $X)`, true},
		{"result=`echo $X`", true},
		{`foo="$(echo "$X")"`, false},  // var double-quoted inside $() — safe (no FP)
		{"echo \"\\\"$X\\\"\"", false}, // echo "\"$X\"" — escaped quotes; $X still double-quoted (no FP)
		{`echo "no var here"`, false},
		{`echo $OTHER`, false}, // not in the untrusted set
	}
	for _, c := range cases {
		_, got := shellUnsafeUse(c.line, names, false)
		if got != c.unsafe {
			t.Errorf("shellUnsafeUse(%q) = %v, want %v", c.line, got, c.unsafe)
		}
	}
}

// --- finalize-hardening regression tests ----------------------------------

func ghFinding(t *testing.T, root string) []model.Finding {
	t.Helper()
	doc, err := workflow.Load(filepath.Join(root, ".github", "workflows", "wf.yml"))
	if err != nil {
		t.Fatalf("load workflow: %v", err)
	}
	return (IndirectPPE{}).Apply(doc)
}

func TestIndirectPPE_SymlinkEscapeIsNotRead(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell, // runs bash ./ci/build.sh
	})
	outside := filepath.Join(t.TempDir(), "secret.sh")
	if err := os.WriteFile(outside, []byte("echo $TITLE\n"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ci", "build.sh")); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err) // Windows w/o privilege
	}
	// Must NOT read the out-of-tree symlink target. No finding (and no panic).
	for _, f := range ghFinding(t, root) {
		if f.Severity == model.SevCritical {
			t.Fatalf("scanner followed a symlink outside the repo root: %+v", f)
		}
	}
}

func TestIndirectPPE_UnparseablePackageJSONIsUnassessedNotClean(t *testing.T) {
	wf := `name: ci
on: [issue_comment]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BODY: ${{ github.event.comment.body }}
    steps:
      - run: npm ci
`
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"package.json":             `{"scripts": {"preinstall": "echo $BODY",}}`, // trailing comma → invalid JSON
	})
	var info bool
	for _, f := range ghFinding(t, root) {
		if f.RuleID == "CAM-PPE-002" && f.Severity == model.SevInfo {
			info = true
		}
		if f.Severity == model.SevCritical {
			t.Fatalf("unparseable package.json must not yield a confident finding: %+v", f)
		}
	}
	if !info {
		t.Fatalf("a present-but-unparseable executed file must be surfaced as Info (UNASSESSED), not silently clean")
	}
}

func TestIndirectPPE_HeredocBodyNotFlagged(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfEnvRoutedShell,
		// $TITLE appears only in heredoc DATA fed to a file — not a command position.
		"ci/build.sh": "#!/bin/bash\ncat <<EOF > out.txt\nproject $TITLE\nEOF\n",
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("heredoc body is data, not a command position; should not flag, got %v", ids)
	}
}

func TestIndirectPPE_NpmTargetScoping(t *testing.T) {
	// `npm ci` runs only lifecycle scripts; an unsafe "deploy" script it never
	// runs must NOT be flagged.
	wf := `name: ci
on: [issue_comment]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      BODY: ${{ github.event.comment.body }}
    steps:
      - run: npm ci
`
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"package.json":             `{"scripts": {"deploy": "echo $BODY", "preinstall": "echo done"}}`,
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("`npm ci` does not run the `deploy` script; should not flag it, got %v", ids)
	}
}

func TestIndirectPPE_MakeTargetScoping(t *testing.T) {
	// `make build` must not be flagged for an unsafe recipe in an unrelated target.
	wf := `name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"Makefile":                 "build:\n\techo safe\n\nrelease:\n\techo $$GITHUB_HEAD_REF\n",
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("`make build` does not run the `release` recipe; should not flag it, got %v", ids)
	}
	// But `make release` SHOULD flag it.
	wf2 := `name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make release
`
	root2 := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf2,
		"Makefile":                 "build:\n\techo safe\n\nrelease:\n\techo $$GITHUB_HEAD_REF\n",
	})
	if ids := ghFindings(t, root2); !has(ids, "CAM-PPE-002") {
		t.Fatalf("`make release` runs the unsafe recipe; expected CAM-PPE-002, got %v", ids)
	}
}

func TestIndirectPPE_FlowFormEnv(t *testing.T) {
	wf := `name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    env: { TITLE: "${{ github.event.pull_request.title }}" }
    steps:
      - run: bash ./ci/build.sh
`
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wf,
		"ci/build.sh":              "#!/bin/bash\necho $TITLE\n",
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("single-line flow-form env should be parsed by the line model, got %v", ids)
	}
}

func TestScriptRefsFrom_SkipsInlineDashC(t *testing.T) {
	lines := []string{`bash -c "echo $TITLE"`, `bash ./real.sh`}
	refs := scriptRefsFrom(lines, func(int) bool { return true })
	for _, r := range refs {
		if r.Kind == "shell" && r.Path != "./real.sh" {
			t.Errorf("expected only ./real.sh; `bash -c` inline must not be a file ref, got %q", r.Path)
		}
	}
	var sawReal bool
	for _, r := range refs {
		if r.Path == "./real.sh" {
			sawReal = true
		}
	}
	if !sawReal {
		t.Errorf("expected ./real.sh to be extracted, got %+v", refs)
	}
}

func TestNpmScriptName(t *testing.T) {
	cases := map[string]string{
		"ci":               "",
		" install":         "",
		" run build":       "build",
		" run-script lint": "lint",
		" test":            "test",
		" --silent":        "",
		"":                 "",
	}
	for in, want := range cases {
		if got := npmScriptName(in); got != want {
			t.Errorf("npmScriptName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRepoRootOf(t *testing.T) {
	cases := map[string]string{
		filepath.FromSlash("/repo/.github/workflows/ci.yml"): filepath.FromSlash("/repo"),
		filepath.FromSlash("/repo/.gitlab-ci.yml"):           filepath.FromSlash("/repo"),
		filepath.FromSlash("/x/y/.gitlab/pipe.yml"):          filepath.FromSlash("/x/y"),
	}
	for in, want := range cases {
		if got := repoRootOf(in); got != want {
			t.Errorf("repoRootOf(%q) = %q, want %q", in, got, want)
		}
	}
}
