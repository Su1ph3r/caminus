package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Su1ph3r/caminus/internal/graph"
	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/reporter"
)

// runGraph loads a trust graph (from `enum`), optionally merges `scan` findings
// to mark additional entry points, synthesizes ranked attack paths, and prints
// them. The `--cloud` blast-radius merge arrives in Task 4.
func runGraph(argv []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("i", "graph.json", "trust-graph input file (from `caminus enum`)")
	scan := fs.String("scan", "", "optional scan JSON (caminus scan --format json) to mark entry points")
	cloud := fs.String("cloud", "", "cloud export for OIDC blast-radius [Task 4]")
	format := fs.String("format", "text", "output: text|json")
	minSev := fs.String("min-severity", "info", "report paths at or above: critical|high|medium|low|info")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "caminus graph — synthesize ranked attack paths from the trust graph\n\nOPTIONS\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *cloud != "" {
		fmt.Fprintln(os.Stderr, "caminus graph: --cloud blast-radius merge lands in Task 4; ignoring for now")
	}

	min, ok := parseSeverity(*minSev)
	if !ok {
		fmt.Fprintf(os.Stderr, "caminus graph: invalid --min-severity %q\n", *minSev)
		return 2
	}

	g, err := loadGraph(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "caminus graph: %v\n", err)
		return 2
	}
	if *scan != "" {
		if err := mergeScanEntryPoints(g, *scan); err != nil {
			fmt.Fprintf(os.Stderr, "caminus graph: %v\n", err)
			return 2
		}
	}

	paths := graph.Synthesize(g)
	var kept []model.AttackPath
	for _, p := range paths {
		if p.Severity.Rank() >= min.Rank() {
			kept = append(kept, p)
		}
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(kept); err != nil {
			fmt.Fprintf(os.Stderr, "caminus graph: %v\n", err)
			return 2
		}
	case "text":
		printPaths(kept)
	default:
		fmt.Fprintf(os.Stderr, "caminus graph: invalid --format %q\n", *format)
		return 2
	}
	return 0
}

func loadGraph(path string) (*model.Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g model.Graph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse trust graph %s: %w", path, err)
	}
	if g.Nodes == nil {
		g.Nodes = map[string]*model.Node{}
	}
	return &g, nil
}

// mergeScanEntryPoints marks pipeline nodes as entry points when a confirmable
// finding in the scan report matches the pipeline's workflow path.
func mergeScanEntryPoints(g *model.Graph, scanPath string) error {
	data, err := os.ReadFile(scanPath)
	if err != nil {
		return err
	}
	var rep reporter.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("parse scan report %s: %w", scanPath, err)
	}
	confirmable := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Confirmable {
			confirmable[strings.ReplaceAll(f.File, "\\", "/")] = true
		}
	}
	for _, n := range g.Nodes {
		if n.Kind != model.NodePipeline {
			continue
		}
		p := n.Attrs["path"]
		for file := range confirmable {
			if p != "" && (strings.HasSuffix(file, p) || strings.HasSuffix(p, file)) {
				if n.Attrs == nil {
					n.Attrs = map[string]string{}
				}
				n.Attrs["entrypoint"] = "true"
			}
		}
	}
	return nil
}

func printPaths(paths []model.AttackPath) {
	if len(paths) == 0 {
		fmt.Println("No attack paths found.")
		return
	}
	for i, p := range paths {
		fmt.Printf("[%s] %d. %s\n", strings.ToUpper(string(p.Severity)), i+1, p.Title)
		for _, s := range p.Steps {
			mitre := ""
			if s.MITRE != "" {
				mitre = "  (" + s.MITRE + ")"
			}
			tech := s.Technique
			if tech == "" {
				tech = "·"
			}
			fmt.Printf("    → %s%s  [%s]\n", tech, mitre, s.NodeID)
		}
		fmt.Println()
	}
	fmt.Printf("%d attack path(s).\n", len(paths))
}
