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
	gl "github.com/Su1ph3r/caminus/internal/platform/gitlab"
	"github.com/Su1ph3r/caminus/internal/reporter"
	"github.com/Su1ph3r/caminus/internal/vcr"
)

// enumProvider is the read-only enumeration contract both platform clients
// satisfy, letting the command dispatch over GitHub and GitLab uniformly.
type enumProvider interface {
	Enumerate(context.Context, platform.Credentials, platform.Target, *model.Graph) error
}

// buildProvider constructs the platform enumerator and the target to walk. On a
// usage error it prints a message and returns a nil provider plus the exit code.
func buildProvider(plat, org, repo string, creds platform.Credentials, hc *http.Client, logf func(string, ...any)) (enumProvider, platform.Target, int) {
	switch plat {
	case "github":
		owner, name := org, repo
		if strings.Contains(repo, "/") {
			parts := strings.SplitN(repo, "/", 2)
			owner, name = parts[0], parts[1]
		}
		if owner == "" {
			fmt.Fprintln(os.Stderr, "caminus enum: --org (owner) is required for github")
			return nil, platform.Target{}, 2
		}
		e := gh.New(gh.NewClient(creds, hc))
		e.Logf = logf
		return e, platform.Target{Org: owner, Repo: name}, 0
	case "gitlab":
		group, project := org, repo
		// A bare project name with --group is qualified into a full path; an
		// explicit "group/project" in --repo is used as-is.
		if project != "" && !strings.Contains(project, "/") && group != "" {
			project = group + "/" + project
		}
		if group == "" && project == "" {
			fmt.Fprintln(os.Stderr, "caminus enum: --org (group) or --repo (group/project) is required for gitlab")
			return nil, platform.Target{}, 2
		}
		e := gl.New(gl.NewClient(creds, hc))
		e.Logf = logf
		// A single project target leaves Org empty so enumeration scopes to it;
		// otherwise enumerate the whole group.
		if project != "" {
			return e, platform.Target{Repo: project}, 0
		}
		return e, platform.Target{Org: group}, 0
	}
	fmt.Fprintf(os.Stderr, "caminus enum: unknown platform %q\n", plat)
	return nil, platform.Target{}, 2
}

// runEnum performs read-only authenticated enumeration of a provider into the
// trust graph (M2, Task 1: GitHub). It emits a graph.json the `graph` stage
// consumes.
func runEnum(argv []string) int {
	fs := flag.NewFlagSet("enum", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	plat := fs.String("platform", "github", "provider: github or gitlab")
	org := fs.String("org", "", "GitHub org/owner, or GitLab group, to enumerate")
	repo := fs.String("repo", "", "single repo/project: \"owner/name\" (or \"name\" with --org)")
	baseURL := fs.String("base-url", "", "API base URL for self-managed (GHE …/api/v3, GitLab host root)")
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

	if *plat != "github" && *plat != "gitlab" {
		fmt.Fprintf(os.Stderr, "caminus enum: unknown platform %q (want github or gitlab)\n", *plat)
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
		hc = newHTTPClient(rt)
	case *record != "":
		if tok == "" {
			fmt.Fprintln(os.Stderr, "caminus enum: --record requires a token (--token or CAMINUS_TOKEN)")
			return 2
		}
		recorder = vcr.Record(*record, nil)
		hc = newHTTPClient(recorder)
	default:
		if tok == "" {
			fmt.Fprintln(os.Stderr, "caminus enum: a token is required (--token or CAMINUS_TOKEN), or use --replay")
			return 2
		}
		hc = newHTTPClient(nil)
	}

	creds := platform.Credentials{Token: tok, BaseURL: *baseURL}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "  "+format+"\n", a...) }

	prov, target, code := buildProvider(*plat, *org, *repo, creds, hc, logf)
	if prov == nil {
		return code
	}

	g := model.NewGraph()
	if err := prov.Enumerate(context.Background(), creds, target, g); err != nil {
		fmt.Fprintf(os.Stderr, "caminus enum: %v\n", err)
		return 2
	}

	if recorder != nil {
		if err := recorder.Save(); err != nil {
			// The whole point of --record is to produce a reusable cassette; a
			// failed write must not report success.
			fmt.Fprintf(os.Stderr, "caminus enum: save cassette: %v\n", err)
			return 2
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

// newHTTPClient builds the enumeration HTTP client. CheckRedirect refuses
// cross-host redirects so a hostile API response cannot bounce an authenticated
// request to an unintended (e.g. internal/metadata) host.
func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
			}
			return nil
		},
	}
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
	// 0o600: the graph captures a recon inventory (repo/runner/secret names,
	// OIDC config) of the target; keep it owner-readable only.
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func printGraphSummary(w *os.File, g *model.Graph, out string) {
	byKind := map[model.NodeKind]int{}
	entry, unassessed, incomplete := 0, 0, 0
	for _, n := range g.Nodes {
		byKind[n.Kind]++
		if n.Attrs["enum_incomplete"] != "" {
			incomplete++
		}
		if n.Kind == model.NodePipeline {
			if n.Attrs["entrypoint"] == "true" {
				entry++
			}
			if n.Attrs["content_unavailable"] == "true" {
				unassessed++
			}
		}
	}
	fmt.Fprintf(w, "\ntrust graph: %d nodes, %d edges", len(g.Nodes), len(g.Edges))
	if out != "-" {
		fmt.Fprintf(w, " → %s", out)
	}
	fmt.Fprintf(w, "\n  repos=%d pipelines=%d runners=%d secrets=%d oidc=%d  | entry-point pipelines: %d\n",
		byKind[model.NodeRepo], byKind[model.NodePipeline], byKind[model.NodeRunner],
		byKind[model.NodeSecret], byKind[model.NodeOIDCTrust], entry)
	if unassessed > 0 {
		fmt.Fprintf(w, "  warning: %d workflow(s) UNASSESSED — content unreadable (token may lack `contents` scope); not necessarily benign\n", unassessed)
	}
	if incomplete > 0 {
		fmt.Fprintf(w, "  warning: trust graph is PARTIAL — %d node(s) had resources that could not be read (see enum_incomplete attrs)\n", incomplete)
	}
}
