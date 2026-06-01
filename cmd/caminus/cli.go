package main

import (
	"fmt"
	"os"
)

// run dispatches argv to a subcommand and returns the process exit code. It is
// separated from main (which only calls os.Exit) so the router is testable.
//
// Exit codes:
//
//	0  clean / informational
//	1  findings at or above the scan gate threshold (default: high)
//	2  usage or runtime error
//	3  capability not yet implemented in this build
func run(argv []string) int {
	name, rest := route(argv)
	switch name {
	case "version":
		fmt.Printf("caminus v%s\n", version)
		return 0
	case "help":
		printUsage(os.Stdout)
		return 0
	case "scan":
		return runScan(rest)
	case "enum":
		return runEnum(rest)
	case "graph":
		return runGraph(rest)
	case "exploit":
		return runExploit(rest)
	default:
		fmt.Fprintf(os.Stderr, "caminus: unknown command %q\n\n", name)
		printUsage(os.Stderr)
		return 2
	}
}

// route maps argv to a subcommand name and the remaining args. With no
// recognized subcommand, it returns "help".
func route(argv []string) (string, []string) {
	if len(argv) == 0 {
		return "help", nil
	}
	switch argv[0] {
	case "-h", "--help", "help":
		return "help", argv[1:]
	case "-v", "--version", "version":
		return "version", argv[1:]
	case "scan", "enum", "graph", "exploit":
		return argv[0], argv[1:]
	default:
		return argv[0], argv[1:] // unknown; run() reports it
	}
}

func printUsage(w *os.File) {
	fmt.Fprint(w, `caminus — multi-platform CI/CD pipeline attack framework

USAGE
  caminus <command> [options]

COMMANDS
  scan      Static attack-surface analysis of pipeline definitions (no token)
  enum      Read-only enumeration into the trust graph (GitHub; GitLab [M2.5])
  graph     Synthesize ranked attack paths from the trust graph
  exploit   Generate/confirm an attack primitive against a target you own  [M3]
  version   Print version
  help      Print this help

EXAMPLES
  caminus scan                         # scan ./ for GitHub + GitLab pipelines
  caminus scan .github/workflows/
  caminus scan .gitlab-ci.yml
  caminus scan . --format sarif        # SARIF 2.1.0 for code scanning
  caminus scan . --min-severity high

  caminus enum --org acme --token $CAMINUS_TOKEN   # build the trust graph
  caminus enum --org acme --repo acme/widgets -o graph.json
  caminus graph -i graph.json                      # ranked attack paths
  caminus graph -i graph.json --min-severity high --format json

Run "caminus <command> -h" for command-specific options.
`)
}
