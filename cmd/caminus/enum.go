package main

import (
	"flag"
	"fmt"
	"os"
)

// runEnum is the authenticated enumeration stage (milestone M2). It will walk a
// provider (GitHub/GitLab) with a token and populate the trust graph with
// repos, workflows, runners, secret names, environments, and OIDC trust. The
// flags are wired now so the interface is stable; execution is not yet built.
func runEnum(argv []string) int {
	fs := flag.NewFlagSet("enum", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	plat := fs.String("platform", "github", "provider: github|gitlab")
	org := fs.String("org", "", "organization / group to enumerate")
	repo := fs.String("repo", "", "single repo (owner/name); empty = whole org")
	baseURL := fs.String("base-url", "", "API base URL for self-managed instances")
	_ = fs.String("token", "", "access token (or set FORNAX_TOKEN)")
	out := fs.String("o", "graph.json", "trust-graph output file")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "caminus enum — authenticated enumeration into the trust graph [milestone M2]\n\nOPTIONS\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	fmt.Fprintf(os.Stderr,
		"caminus enum is planned for milestone M2 (see DESIGN.md §Roadmap).\n"+
			"It will enumerate platform=%s org=%q repo=%q base-url=%q into %s,\n"+
			"adding runner, secret, environment, and OIDC-trust nodes to the graph.\n"+
			"Today, use `caminus scan` for token-free static analysis.\n",
		*plat, *org, *repo, *baseURL, *out)
	return 3
}
