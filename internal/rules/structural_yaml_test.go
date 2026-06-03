//go:build yaml

package rules

import "testing"

// With structural parsing, the YAML alias *t is dereferenced to its anchored
// value (the untrusted ${{ github.event.pull_request.title }}), so ALIASED is
// correctly recognized as untrusted and the unquoted use in the executed script
// is flagged — a recall win over the line model (see indirect_lineonly_test.go).
func TestIndirectPPE_AliasedEnv_StructuralCatches(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".github/workflows/wf.yml": wfAliasedEnv,
		"ci/build.sh":              "#!/bin/bash\necho $ALIASED\n",
	})
	if ids := ghFindings(t, root); !has(ids, "CAM-PPE-002") {
		t.Fatalf("structural parse should resolve the alias and flag CAM-PPE-002, got %v", ids)
	}
}
