//go:build !yaml

package rules

import "testing"

// In the default (line-model) build, an env value supplied only through a YAML
// alias cannot be connected to its anchored untrusted source, so the indirect
// rule does not see ALIASED as untrusted. This test pins that documented
// limitation; the -tags yaml build (structural_yaml_test.go) resolves the alias
// and DOES flag it.
func TestIndirectPPE_AliasedEnv_LineModelMisses(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfAliasedEnv,
		"ci/build.sh":              "#!/bin/bash\necho $ALIASED\n",
	})
	if ids := ghFindings(t, root); has(ids, "CAM-PPE-002") {
		t.Fatalf("line model cannot resolve the alias; expected no CAM-PPE-002, got %v", ids)
	}
}
