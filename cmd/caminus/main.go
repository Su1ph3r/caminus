// Command caminus is a multi-platform CI/CD pipeline attack framework.
//
// Where static scanners (poutine, Raven) stop at flagging YAML patterns and
// gato-x covers only GitHub, Caminus models a pipeline compromise as a trust
// graph from an attacker-controllable trigger to its blast radius — secrets,
// self-hosted runners, and (via OIDC) cloud roles and the resources behind
// them — and is built to dynamically confirm the primitives it finds.
//
// Subcommands:
//
//	scan      static attack-surface analysis of pipeline definitions (no token)
//	enum      authenticated enumeration of a provider into the trust graph  [M2]
//	graph     synthesize attack paths from the trust graph                  [M2]
//	exploit   generate / confirm an attack primitive against a target you own [M3]
//	version   print version
//	help      print usage
package main

import "os"

// version is overridden at release time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}
