package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Su1ph3r/caminus/internal/gitlabci"
	"github.com/Su1ph3r/caminus/internal/model"
	"github.com/Su1ph3r/caminus/internal/reporter"
	"github.com/Su1ph3r/caminus/internal/rules"
	"github.com/Su1ph3r/caminus/internal/workflow"
)

// runScan performs static attack-surface analysis of pipeline definitions across
// GitHub Actions and GitLab CI.
func runScan(argv []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "output format: text|json")
	minSev := fs.String("min-severity", "info", "report findings at or above: critical|high|medium|low|info")
	gate := fs.String("gate", "high", "exit non-zero if any finding at or above this severity is reported (use 'none' to disable)")
	platform := fs.String("platform", "auto", "pipeline platform: auto|github|gitlab")
	failIncomplete := fs.Bool("fail-on-incomplete", false, "exit non-zero if any targeted file could not be analyzed")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `caminus scan — static attack-surface analysis of CI/CD pipeline definitions

USAGE
  caminus scan [path ...] [options]

  path   File or directory to scan. Directories are searched for GitHub
         Actions workflows (.github/workflows/*.{yml,yaml}) and GitLab CI files
         (.gitlab-ci.yml, .gitlab/**). Defaults to ".".

OPTIONS
`)
		fs.PrintDefaults()
	}
	// Parse flags and positionals in any order: flag.Parse stops at the first
	// non-flag token, so loop — consume leading flags, grab the positional,
	// repeat with the remainder. All scan flags are valued (no bools), so this
	// is unambiguous.
	var paths []string
	rest := argv
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		paths = append(paths, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	min, ok := parseSeverity(*minSev)
	if !ok {
		fmt.Fprintf(os.Stderr, "caminus scan: invalid --min-severity %q\n", *minSev)
		return 2
	}
	gateSev, gateOn := parseSeverity(*gate)
	if !gateOn && *gate != "none" {
		fmt.Fprintf(os.Stderr, "caminus scan: invalid --gate %q\n", *gate)
		return 2
	}
	gateEnabled := *gate != "none"

	switch *platform {
	case "auto", "github", "gitlab":
	default:
		fmt.Fprintf(os.Stderr, "caminus scan: invalid --platform %q\n", *platform)
		return 2
	}

	if len(paths) == 0 {
		paths = []string{"."}
	}

	var files []string
	for _, p := range paths {
		found, warnings, err := discoverPipelines(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "caminus scan: %v\n", err)
			return 2
		}
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "caminus scan: warning: skipped unreadable path %s\n", w)
		}
		files = append(files, found...)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "caminus scan: no pipeline files found")
		return 2
	}

	var findings []model.Finding
	unreadable := 0
	for _, f := range files {
		fnds, err := analyzeFile(f, *platform)
		if err != nil {
			// A file that was discovered but could not be parsed/read is UNASSESSED,
			// not clean — count it so the gate can't silently pass over the gap.
			fmt.Fprintf(os.Stderr, "caminus scan: %s: %v\n", f, err)
			unreadable++
			continue
		}
		for _, fnd := range fnds {
			if fnd.Severity.Rank() >= min.Rank() {
				findings = append(findings, fnd)
			}
		}
	}

	switch *format {
	case "json":
		if err := reporter.JSON(os.Stdout, version, findings); err != nil {
			fmt.Fprintf(os.Stderr, "caminus scan: %v\n", err)
			return 2
		}
	case "sarif":
		if err := reporter.SARIF(os.Stdout, version, findings); err != nil {
			fmt.Fprintf(os.Stderr, "caminus scan: %v\n", err)
			return 2
		}
	case "text":
		reporter.Text(os.Stdout, findings)
	default:
		fmt.Fprintf(os.Stderr, "caminus scan: invalid --format %q\n", *format)
		return 2
	}

	gateHit := false
	if gateEnabled {
		for _, f := range findings {
			if f.Severity.Rank() >= gateSev.Rank() {
				gateHit = true
				break
			}
		}
	}
	if unreadable > 0 {
		fmt.Fprintf(os.Stderr,
			"caminus scan: warning: %d file(s) UNASSESSED (could not be analyzed) — scan is INCOMPLETE, not necessarily clean\n",
			unreadable)
	}
	if gateHit {
		return 1
	}
	// Default stays exit 0 on an incomplete-but-ungated scan (backward compatible);
	// opt in to a hard failure for CI with --fail-on-incomplete.
	if *failIncomplete && unreadable > 0 {
		return 2
	}
	return 0
}

// analyzeFile loads a single pipeline file with the right parser and runs the
// matching rule set, dispatching on the detected (or forced) platform.
func analyzeFile(path, override string) ([]model.Finding, error) {
	switch detectPlatform(path, override) {
	case "gitlab":
		doc, err := gitlabci.Load(path)
		if err != nil {
			return nil, err
		}
		return rules.RunGitLab(doc), nil
	default:
		doc, err := workflow.Load(path)
		if err != nil {
			return nil, err
		}
		return rules.Run(doc, rules.Default()), nil
	}
}

// detectPlatform decides which parser/ruleset a file gets. An explicit
// --platform (github|gitlab) wins; otherwise it is inferred from the path.
func detectPlatform(path, override string) string {
	if override == "github" || override == "gitlab" {
		return override
	}
	if isGitLabCI(path) {
		return "gitlab"
	}
	return "github"
}

// parseSeverity maps a string to a Severity; the bool is false for unknown
// values (with "none" handled by callers).
func parseSeverity(s string) (model.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return model.SevCritical, true
	case "high":
		return model.SevHigh, true
	case "medium", "med":
		return model.SevMedium, true
	case "low":
		return model.SevLow, true
	case "info", "informational":
		return model.SevInfo, true
	default:
		return model.SevInfo, false
	}
}

// discoverPipelines resolves a path to pipeline files. A file is returned as-is;
// a directory is searched for recognized GitHub Actions and GitLab CI files. If
// none are recognized by location, it falls back to all YAML (so pointing
// directly at a non-standard workflow directory still works).
//
// It also returns any directory-walk errors (e.g. an unreadable subtree) as
// warnings rather than swallowing them: a security scanner must not report a
// tree "clean" when part of it could not be read.
func discoverPipelines(root string) (files []string, warnings []string, err error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil, nil
	}
	var recognized, anyYAML []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", p, walkErr))
			if d != nil && d.IsDir() {
				return filepath.SkipDir // skip the unreadable subtree, but record it
			}
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isYAML(p) {
			return nil
		}
		if isGitHubWorkflow(p) || isGitLabCI(p) {
			recognized = append(recognized, p)
		}
		anyYAML = append(anyYAML, p)
		return nil
	})
	if len(recognized) > 0 {
		return recognized, warnings, nil
	}
	return anyYAML, warnings, nil
}

// skipDir prunes noisy directories from the walk (but never .github/.gitlab).
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".terraform", "dist", "bin":
		return true
	}
	return false
}

func isYAML(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}

func isGitHubWorkflow(p string) bool {
	return strings.Contains(filepath.ToSlash(p), "/workflows/") && isYAML(p)
}

func isGitLabCI(p string) bool {
	base := filepath.Base(p)
	if base == ".gitlab-ci.yml" || strings.HasSuffix(base, ".gitlab-ci.yml") {
		return true
	}
	return strings.Contains(filepath.ToSlash(p), "/.gitlab/") && isYAML(p)
}
