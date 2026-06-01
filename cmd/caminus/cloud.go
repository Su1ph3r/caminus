package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/Su1ph3r/caminus/internal/cloud"
	"github.com/Su1ph3r/caminus/internal/reporter"
	"github.com/Su1ph3r/caminus/internal/vcr"
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
	replay := fs.String("replay", "", "replay IAM responses from a cassette (no AWS creds needed)")
	record := fs.String("record", "", "record IAM responses to a cassette")
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

	// Optional record/replay transport for the AWS SDK.
	var transport http.RoundTripper
	var anonymous bool
	var recorder *vcr.Transport
	switch {
	case *replay != "":
		rt, err := vcr.Replay(*replay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "caminus cloud: %v\n", err)
			return 2
		}
		transport, anonymous = rt, true
	case *record != "":
		recorder = vcr.Record(*record, nil)
		transport = recorder
	}

	g, err := loadGraph(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "caminus cloud: %v\n", err)
		return 2
	}
	before := len(g.Findings)

	opts := cloud.Options{Region: *region, Profile: *profile, Transport: transport, Anonymous: anonymous}
	bindings, err := cloud.Enrich(context.Background(), g, cloud.Fetch, opts)
	if err != nil {
		if errors.Is(err, cloud.ErrNotBuilt) {
			fmt.Fprintln(os.Stderr, "caminus cloud: "+err.Error())
			return 3
		}
		fmt.Fprintf(os.Stderr, "caminus cloud: %v\n", err)
		return 2
	}
	if recorder != nil {
		if err := recorder.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "caminus cloud: save cassette: %v\n", err)
		}
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
