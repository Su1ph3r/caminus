package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Su1ph3r/caminus/internal/cloud"
	"github.com/Su1ph3r/caminus/internal/reporter"
)

// runCloud enriches a trust graph with the OIDC → cloud blast radius: it reads
// IAM roles that federate to GitHub Actions OIDC and resolves which pipelines
// can assume them. Requires a binary built with `-tags cloud` and AWS
// credentials from the standard chain.
func runCloud(argv []string) int {
	fs := flag.NewFlagSet("cloud", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("i", "graph.json", "trust-graph input file (from `caminus enum`)")
	out := fs.String("o", "", "output file (default: overwrite the input)")
	region := fs.String("region", "", "AWS region (else from environment/profile)")
	profile := fs.String("profile", "", "AWS shared-config profile")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "caminus cloud — resolve OIDC→cloud blast radius (AWS; requires -tags cloud build)\n\nOPTIONS\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *out == "" {
		*out = *in
	}

	g, err := loadGraph(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "caminus cloud: %v\n", err)
		return 2
	}
	before := len(g.Findings)

	bindings, err := cloud.Enrich(context.Background(), g, cloud.Fetch, cloud.Options{Region: *region, Profile: *profile})
	if err != nil {
		if errors.Is(err, cloud.ErrNotBuilt) {
			fmt.Fprintln(os.Stderr, "caminus cloud: "+err.Error())
			return 3
		}
		fmt.Fprintf(os.Stderr, "caminus cloud: %v\n", err)
		return 2
	}

	if err := writeGraph(*out, g); err != nil {
		fmt.Fprintf(os.Stderr, "caminus cloud: %v\n", err)
		return 2
	}

	roles := 0
	for _, n := range g.Nodes {
		if n.Kind == "cloud-role" {
			roles++
		}
	}
	fmt.Fprintf(os.Stderr, "cloud enrichment: %d assumable role binding(s), %d cloud role(s) → %s\n", bindings, roles, *out)

	if newFindings := g.Findings[before:]; len(newFindings) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d cloud finding(s):\n", len(newFindings))
		reporter.Text(os.Stderr, newFindings)
	}
	return 0
}
