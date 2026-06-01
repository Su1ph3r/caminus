package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/platform"
	gh "github.com/Su1ph3r/caminus/internal/platform/github"
	"github.com/Su1ph3r/caminus/internal/reporter"
	"github.com/Su1ph3r/caminus/internal/vcr"
)

// runEnum performs read-only authenticated enumeration of a provider into the
// trust graph (M2, Task 1: GitHub). It emits a graph.json the `graph` stage
// consumes.
func runEnum(argv []string) int {
	fs := flag.NewFlagSet("enum", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	plat := fs.String("platform", "github", "provider: github (gitlab in M2.5)")
	org := fs.String("org", "", "organization / owner to enumerate")
	repo := fs.String("repo", "", "single repo: \"owner/name\" or just \"name\" with --org")
	baseURL := fs.String("base-url", "", "API base URL for GitHub Enterprise (…/api/v3)")
	token := fs.String("token", "", "access token (or set CAMINUS_TOKEN)")
	out := fs.String("o", "graph.json", "trust-graph output file (\"-\" for stdout)")
	replay := fs.String("replay", "", "replay API responses from a cassette (no token needed)")
	record := fs.String("record", "", "record API responses to a cassette")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "caminus enum — read-only enumeration into the trust graph\n\nOPTIONS\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	if *plat == "gitlab" {
		fmt.Fprintln(os.Stderr, "caminus enum: GitLab enumeration arrives in M2.5; use --platform github")
		return 3
	}
	if *plat != "github" {
		fmt.Fprintf(os.Stderr, "caminus enum: unknown platform %q\n", *plat)
		return 2
	}

	owner, name := *org, *repo
	if strings.Contains(*repo, "/") {
		parts := strings.SplitN(*repo, "/", 2)
		owner, name = parts[0], parts[1]
	}
	if owner == "" {
		fmt.Fprintln(os.Stderr, "caminus enum: --org (owner) is required")
		return 2
	}

	tok := *token
	if tok == "" {
		tok = os.Getenv("CAMINUS_TOKEN")
	}

	// Build the HTTP client: replay (no token), record (token + capture), or live.
	var hc *http.Client
	var recorder *vcr.Transport
	switch {
	case *replay != "":
		rt, err := vcr.Replay(*replay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "caminus enum: %v\n", err)
			return 2
		}
		hc = &http.Client{Transport: rt}
	case *record != "":
		if tok == "" {
			fmt.Fprintln(os.Stderr, "caminus enum: --record requires a token (--token or CAMINUS_TOKEN)")
			return 2
		}
		recorder = vcr.Record(*record, nil)
		hc = &http.Client{Transport: recorder}
	default:
		if tok == "" {
			fmt.Fprintln(os.Stderr, "caminus enum: a token is required (--token or CAMINUS_TOKEN), or use --replay")
			return 2
		}
		hc = &http.Client{}
	}

	creds := platform.Credentials{Token: tok, BaseURL: *baseURL}
	client := gh.NewClient(creds, hc)
	enum := gh.New(client)
	enum.Logf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, "  "+format+"\n", a...) }

	g := model.NewGraph()
	if err := enum.Enumerate(context.Background(), creds, platform.Target{Org: owner, Repo: name}, g); err != nil {
		fmt.Fprintf(os.Stderr, "caminus enum: %v\n", err)
		return 2
	}

	if recorder != nil {
		if err := recorder.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "caminus enum: save cassette: %v\n", err)
		}
	}

	if err := writeGraph(*out, g); err != nil {
		fmt.Fprintf(os.Stderr, "caminus enum: %v\n", err)
		return 2
	}
	printGraphSummary(os.Stderr, g, *out)
	if len(g.Findings) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d enumeration finding(s):\n", len(g.Findings))
		reporter.Text(os.Stderr, g.Findings)
	}
	return 0
}

func writeGraph(path string, g *model.Graph) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func printGraphSummary(w *os.File, g *model.Graph, out string) {
	byKind := map[model.NodeKind]int{}
	entry := 0
	for _, n := range g.Nodes {
		byKind[n.Kind]++
		if n.Kind == model.NodePipeline && n.Attrs["entrypoint"] == "true" {
			entry++
		}
	}
	fmt.Fprintf(w, "\ntrust graph: %d nodes, %d edges", len(g.Nodes), len(g.Edges))
	if out != "-" {
		fmt.Fprintf(w, " → %s", out)
	}
	fmt.Fprintf(w, "\n  repos=%d pipelines=%d runners=%d secrets=%d oidc=%d  | entry-point pipelines: %d\n",
		byKind[model.NodeRepo], byKind[model.NodePipeline], byKind[model.NodeRunner],
		byKind[model.NodeSecret], byKind[model.NodeOIDCTrust], entry)
}
