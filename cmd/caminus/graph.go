package main

import (
	"flag"
	"fmt"
	"os"
)

// runGraph is the attack-path synthesis stage (milestone M2). It will load a
// trust graph (from `enum`, optionally merged with `scan` findings and a
// Nubicustos cloud export) and walk edges to produce ranked attack paths from
// attacker-controllable triggers to high-value assets, exportable to Ariadne.
func runGraph(argv []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("i", "graph.json", "trust-graph input file (from `caminus enum`)")
	scan := fs.String("scan", "", "optional scan JSON to seed pipeline findings")
	cloud := fs.String("cloud", "", "optional Nubicustos cloud export for OIDC blast-radius")
	format := fs.String("format", "text", "output: text|json|ariadne")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "caminus graph — synthesize attack paths from the trust graph [milestone M2]\n\nOPTIONS\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	fmt.Fprintf(os.Stderr,
		"caminus graph is planned for milestone M2 (see DESIGN.md §Roadmap).\n"+
			"It will read %s (+scan=%q +cloud=%q) and emit %s attack paths:\n"+
			"  trigger → pipeline → runner/secret → OIDC trust → cloud role → resource.\n",
		*in, *scan, *cloud, *format)
	return 3
}
