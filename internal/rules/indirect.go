package rules

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Indirect-PPE detection (CICD-SEC-4 / Indirect Poisoned Pipeline Execution).
//
// The direct injection rules (CAM-INJ-001 / CAM-GL-INJ-001) fire only on
// untrusted input interpolated *straight into* a run:/script: shell, and they
// deliberately treat env-routing as the recommended-safe pattern. But routing
// is only safe if the value is then *used* safely. When a pipeline hands
// execution to a local repo file — a shell script, a Makefile recipe, a
// package.json lifecycle script — that file becomes part of the trusted
// execution surface, and an attacker-controlled value reaching it unquoted (or
// via eval / command substitution) is a real shell injection the YAML-only
// scanner cannot see.
//
// This is the dataflow CAM-INJ-001 documented as a later milestone, realized
// one file-hop out. It reads the referenced file from disk relative to the
// repository root. A file that is ABSENT yields no finding (no speculative
// false positives); a file that is PRESENT but cannot be read or parsed is
// surfaced as UNASSESSED rather than silently scored clean — a scanner must not
// report "no finding" on a path it failed to analyze.

// scriptRef is a reference, from a run:/script: step, to a local file the
// pipeline executes.
type scriptRef struct {
	Line   int    // 1-based line of the invocation in the pipeline file
	Path   string // raw path token as written (repo-relative); fixed file for make/npm
	Kind   string // shell | make | npm
	Target string // make target / npm script name ("" = default / install lifecycle)
	Raw    string // the invocation line (evidence)
}

var (
	// reInterpShell matches a shell interpreter (or the `.`/`source` builtins)
	// invoking a path argument: bash X, sh X, source X, . X. Group 1 captures any
	// leading flags (so a `-c` inline script can be distinguished); group 2 is the
	// first non-flag token (the candidate path).
	reInterpShell = regexp.MustCompile(`(?:^|[\s;&|(])(?:bash|sh|zsh|ksh|dash|source|\.)\s+((?:-\S+\s+)*)([^\s;&|<>()]+)`)
	// reDirectExec matches a directly-executed local path: ./build.sh, ./ci/x.
	reDirectExec = regexp.MustCompile(`(?:^|[\s;&|(])(\.\/[^\s;&|<>()]+)`)
	// reMake matches `make [flags] [target]`, capturing the first non-flag token
	// as the target (which scopes the recipe analyzed). A bare `make` runs the
	// default goal (Target == "").
	reMake = regexp.MustCompile(`(?:^|[\s;&|(])make\b((?:\s+-\S+)*)(?:\s+([A-Za-z0-9_][\w./-]*))?`)
	// reNPM matches npm/yarn/pnpm and the tokens after it, so the executed script
	// can be scoped (run <name>, a bare script alias, or install lifecycle).
	reNPM = regexp.MustCompile(`(?:^|[\s;&|(])(?:npm|yarn|pnpm)\b([^;&|]*)`)
)

// scriptRefsFrom extracts local-file execution references from the lines that
// are in a shell-execution context (isExec reports that for a line index). The
// same extractor serves GitHub run: and GitLab script: blocks.
func scriptRefsFrom(lines []string, isExec func(int) bool) []scriptRef {
	var out []scriptRef
	seen := map[string]bool{}
	add := func(ref scriptRef) {
		key := ref.Kind + "|" + ref.Path + "|" + ref.Target
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ref)
	}
	for i, line := range lines {
		if !isExec(i) {
			continue
		}
		for _, m := range reInterpShell.FindAllStringSubmatch(line, -1) {
			flags, path := m[1], m[2]
			// `bash -c '<script>'` / `sh -c …` runs an inline script, not a file.
			if strings.Contains(flags, "-c") {
				continue
			}
			path = strings.Trim(strings.TrimSpace(path), `"'`)
			if looksLocalPath(path) {
				add(scriptRef{Line: i + 1, Path: path, Kind: "shell", Raw: strings.TrimSpace(line)})
			}
		}
		for _, m := range reDirectExec.FindAllStringSubmatch(line, -1) {
			path := strings.Trim(strings.TrimSpace(m[1]), `"'`)
			if looksLocalPath(path) {
				add(scriptRef{Line: i + 1, Path: path, Kind: "shell", Raw: strings.TrimSpace(line)})
			}
		}
		if m := reMake.FindStringSubmatch(line); m != nil {
			add(scriptRef{Line: i + 1, Path: "Makefile", Kind: "make", Target: m[2], Raw: strings.TrimSpace(line)})
		}
		if m := reNPM.FindStringSubmatch(line); m != nil {
			add(scriptRef{Line: i + 1, Path: "package.json", Kind: "npm", Target: npmScriptName(m[1]), Raw: strings.TrimSpace(line)})
		}
	}
	return out
}

// npmScriptName parses the tokens after npm/yarn/pnpm and returns the script
// name the invocation runs, or "" for an install/lifecycle invocation (or when
// only flags are present). `run <name>` / `run-script <name>` → <name>; a bare
// subcommand that is not an install verb (e.g. `npm test`, `yarn build`) → that
// name (yarn/pnpm run scripts directly; npm aliases test/start/etc.).
func npmScriptName(rest string) string {
	toks := strings.Fields(rest)
	// Drop leading flags.
	for len(toks) > 0 && strings.HasPrefix(toks[0], "-") {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return "" // bare `npm`/`yarn`/`pnpm` or flags only — install lifecycle
	}
	switch toks[0] {
	case "install", "i", "ci", "it", "isntall", "clean-install", "add", "install-test":
		return "" // install lifecycle
	case "run", "run-script":
		if len(toks) > 1 && !strings.HasPrefix(toks[1], "-") {
			return toks[1]
		}
		return ""
	default:
		if strings.HasPrefix(toks[0], "-") {
			return ""
		}
		return toks[0]
	}
}

// looksLocalPath filters interpreter/direct-exec arguments down to plausible
// repo-local SHELL files: not a flag, not a URL, not an absolute path, not a
// shell variable, not a glob, and carrying a shell extension (.sh/.bash/.zsh/
// .ksh) or no extension. Non-shell scripts (.py/.rb/.js/.ps1/…) are excluded:
// the analyzer reasons about shell `$VAR` semantics, which do not transfer to
// other languages, so analyzing them as shell would be wrong. This also keeps
// precision high — we never chase `bash -c`, `python -m`, or a $PATH binary.
func looksLocalPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "-") {
		return false
	}
	if strings.HasPrefix(p, "$") || strings.Contains(p, "://") {
		return false
	}
	if strings.HasPrefix(p, "/") { // absolute — outside the repo tree
		return false
	}
	if strings.ContainsAny(p, "*?{}") { // a glob, not a single file
		return false
	}
	switch strings.ToLower(filepath.Ext(p)) {
	case ".sh", ".bash", ".zsh", ".ksh", "": // shell script or extensionless
		return true
	}
	return false
}

// repoRootOf derives the repository root for a pipeline file so referenced
// scripts resolve correctly. GitHub workflows live at <root>/.github/workflows;
// GitLab CI at <root>/.gitlab-ci.yml or <root>/.gitlab/**. For any other layout
// it falls back to the file's own directory.
func repoRootOf(path string) string {
	s := filepath.ToSlash(path)
	if i := strings.Index(s, "/.github/"); i >= 0 {
		return filepath.FromSlash(s[:i])
	}
	if i := strings.Index(s, "/.gitlab/"); i >= 0 {
		return filepath.FromSlash(s[:i])
	}
	if strings.HasPrefix(s, ".github/") || strings.HasPrefix(s, ".gitlab/") {
		return "."
	}
	return filepath.Dir(path)
}

// resolveInRoot joins a repo-relative reference to root and confines it to the
// tree by the path string: a reference that escapes the root via `..` or is
// absolute is rejected (empty result). Symlink confinement is handled separately
// in readConfined (which resolves the real path before reading).
func resolveInRoot(root, ref string) string {
	clean := filepath.Clean(filepath.FromSlash(ref))
	if filepath.IsAbs(clean) {
		return ""
	}
	full := filepath.Join(root, clean)
	if !withinRoot(root, full) {
		return ""
	}
	return full
}

// withinRoot reports whether path is inside root (or equal to it).
func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

const maxRefFileSize = 5 << 20 // 5 MiB cap on a referenced (attacker-named) file

// readFile reads a referenced file, size-capped to bound a malicious repo that
// ships a huge script/Makefile/package.json. It is a package var so behavior is
// centralized; tests use real files via the rule entry points.
var readFile = func(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxRefFileSize))
}

// readStatus distinguishes the three outcomes a referenced-file read must keep
// separate: a present, readable file; an absent file (intended silence); and a
// present-but-unreadable file (must be surfaced, never scored clean).
type readStatus int

const (
	rsOK readStatus = iota
	rsAbsent
	rsUnreadable
)

// readConfined resolves a repo-relative reference under root, enforces both
// string-level (`..`/absolute) and symlink-level confinement (the real path,
// after resolving symlinks, must still be inside root), and reads it size-
// capped. A symlink that escapes the tree — or any non-regular file (directory,
// device) — is treated as absent so the scanner never reads outside the scanned
// repository (a malicious pipeline could otherwise point a "script" at
// /etc/passwd via a symlink). It returns the real path read for evidence.
func readConfined(root, ref string) (data []byte, realPath string, status readStatus) {
	full := resolveInRoot(root, ref)
	if full == "" {
		return nil, "", rsAbsent
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", rsAbsent
		}
		return nil, full, rsUnreadable
	}
	// A symlink (or path component) that resolves outside root: do not read it.
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		rootReal = root
	}
	if !withinRoot(rootReal, real) {
		return nil, "", rsAbsent
	}
	info, err := os.Lstat(real)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", rsAbsent
		}
		return nil, real, rsUnreadable
	}
	if !info.Mode().IsRegular() { // directory, device, fifo — not a script file
		return nil, "", rsAbsent
	}
	data, err = readFile(real)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", rsAbsent
		}
		return nil, real, rsUnreadable
	}
	return data, real, rsOK
}

// makefileCandidates are the conventional GNU make filenames, tried in order.
var makefileCandidates = []string{"Makefile", "makefile", "GNUmakefile"}

// unsafeSite is the result of analyzing a referenced file: either a confirmed
// unsafe use of an untrusted variable (Unassessed == false) or a notice that
// the file was present but could not be analyzed (Unassessed == true).
type unsafeSite struct {
	File       string
	Line       int // 1-based within the referenced file (0 if not line-addressable)
	Name       string
	Code       string // the offending line / reason, trimmed for evidence
	Unassessed bool
}

// analyzeRef reads the file a scriptRef points at and returns the first unsafe
// use of any untrusted name in it. It returns nil when the referenced file is
// absent or clean, and an Unassessed site when a present file could not be read
// or parsed. names are bare identifiers (e.g. "TITLE", "CI_COMMIT_MESSAGE").
func analyzeRef(root string, ref scriptRef, names map[string]bool) *unsafeSite {
	if len(names) == 0 {
		return nil
	}
	switch ref.Kind {
	case "make":
		var unreadable *unsafeSite
		for _, name := range makefileCandidates {
			data, real, st := readConfined(root, name)
			switch st {
			case rsOK:
				return scanMakefile(real, data, names, ref.Target)
			case rsUnreadable:
				if unreadable == nil {
					unreadable = unassessed(real, "Makefile present but could not be read")
				}
			}
		}
		return unreadable
	case "npm":
		data, real, st := readConfined(root, ref.Path)
		switch st {
		case rsAbsent:
			return nil
		case rsUnreadable:
			return unassessed(real, "package.json present but could not be read")
		}
		return scanPackageJSON(real, data, names, ref.Target)
	default: // shell
		data, real, st := readConfined(root, ref.Path)
		switch st {
		case rsAbsent:
			return nil
		case rsUnreadable:
			return unassessed(real, "referenced script present but could not be read")
		}
		return scanShell(real, data, names)
	}
}

func unassessed(file, reason string) *unsafeSite {
	return &unsafeSite{File: file, Unassessed: true, Code: reason}
}

// scanShell finds the first unsafe use of an untrusted variable in a shell
// script. It folds backslash line-continuations into one logical line and skips
// heredoc bodies (which are data, not command positions) so neither construct
// confuses the single-line quote analyzer.
func scanShell(file string, data []byte, names map[string]bool) *unsafeSite {
	return scanShellLines(file, indexLines(splitLines(data)), names, false)
}

// scanMakefile scans only the recipe of the invoked target (or the default goal
// when Target == ""). Recipe lines run a shell; a shell environment variable is
// written `$$VAR` in a recipe (make escapes `$` as `$$`), so the analyzer runs
// in make mode. Scoping to the invoked target avoids flagging an unsafe use in
// an unrelated target the invocation never runs.
func scanMakefile(file string, data []byte, names map[string]bool, target string) *unsafeSite {
	recipe := makefileRecipe(splitLines(data), target)
	return scanShellLines(file, recipe, names, true)
}

// scanPackageJSON parses the scripts map and analyzes the script(s) the
// invocation actually runs (a named `run` script and its pre/post hooks, or the
// install lifecycle scripts for a bare install). A malformed package.json is
// surfaced as unassessed — the file exists and is executed, so silently scoring
// it clean would hide a real sink.
func scanPackageJSON(file string, data []byte, names map[string]bool, target string) *unsafeSite {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return unassessed(file, "package.json present but could not be parsed: "+err.Error())
	}
	for _, k := range npmTargetScripts(target, pkg.Scripts) {
		script, ok := pkg.Scripts[k]
		if !ok {
			continue
		}
		if name, found := shellUnsafeUse(script, names, false); found {
			return &unsafeSite{File: file, Line: 0, Name: name, Code: "scripts." + k + ": " + trim(script)}
		}
	}
	return nil
}

// npmInstallLifecycle are the scripts npm/yarn/pnpm run on a bare install.
var npmInstallLifecycle = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}

// npmTargetScripts returns the sorted set of script keys (present in scripts)
// that the invocation runs: the install lifecycle for target == "", else the
// named script plus its pre/post hooks.
func npmTargetScripts(target string, scripts map[string]string) []string {
	var want []string
	if target == "" {
		want = npmInstallLifecycle
	} else {
		want = []string{"pre" + target, target, "post" + target}
	}
	var out []string
	for _, k := range want {
		if _, ok := scripts[k]; ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// makefileRecipe returns the recipe lines (tab-indented) of the named target,
// or of the first non-special target (the default goal) when target == "". If
// the named target is not found, no lines are returned (analyze nothing rather
// than fall back to scanning unrelated recipes).
func makefileRecipe(lines []string, target string) []physLine {
	var out []physLine
	inTarget := false
	for i, line := range lines {
		if strings.HasPrefix(line, "\t") { // recipe line
			if inTarget {
				out = append(out, physLine{idx: i, text: line})
			}
			continue
		}
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		name, isTarget := makeTargetName(line)
		if !isTarget {
			inTarget = false // a variable assignment / directive ends any recipe
			continue
		}
		if inTarget && len(out) > 0 {
			break // we have collected the wanted recipe and hit the next target
		}
		switch {
		case target == "" && !strings.HasPrefix(name, "."):
			inTarget = true // first real target = default goal
		case target != "" && matchesTarget(name, target):
			inTarget = true
		default:
			inTarget = false
		}
	}
	return out
}

// reMakeTarget matches a target rule line `name [name...]: [prereqs]` (not a
// variable assignment, which contains `=` before any `:`).
var reMakeTarget = regexp.MustCompile(`^([A-Za-z0-9_./%$()-][^:=]*):[^=]?`)

func makeTargetName(line string) (string, bool) {
	m := reMakeTarget.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

// matchesTarget reports whether a (possibly multi-target) rule head names target.
func matchesTarget(head, target string) bool {
	for _, n := range strings.Fields(head) {
		if n == target {
			return true
		}
	}
	return false
}

type physLine struct {
	idx  int // 0-based index in the file
	text string
}

func indexLines(lines []string) []physLine {
	out := make([]physLine, len(lines))
	for i, l := range lines {
		out[i] = physLine{idx: i, text: l}
	}
	return out
}

// reHeredoc matches a heredoc opener and captures the delimiter word.
var reHeredoc = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)

// scanShellLines runs the quote analyzer over a slice of physical lines and
// returns the first unsafe use, or nil. See scanShellSites for the shared logic.
func scanShellLines(file string, lines []physLine, names map[string]bool, makeMode bool) *unsafeSite {
	if sites := scanShellSites(file, lines, names, makeMode); len(sites) > 0 {
		return sites[0]
	}
	return nil
}

// scanShellSites runs the quote analyzer over a slice of physical lines, folding
// backslash continuations into one logical line and skipping heredoc bodies, and
// returns every unsafe use (one per offending logical line). Hits are reported
// at the starting physical line. makeMode expects `$$VAR`. The single-hit
// scanShellLines is used for referenced files (first finding is enough); the
// all-hits form is used for inline run: blocks (report each unsafe line).
func scanShellSites(file string, lines []physLine, names map[string]bool, makeMode bool) []*unsafeSite {
	var out []*unsafeSite
	for i := 0; i < len(lines); i++ {
		startIdx := lines[i].idx   // physical (file) line number for evidence
		startText := lines[i].text // first physical line of this logical line
		logical := startText
		// Fold backslash line-continuations.
		for endsWithContinuation(logical) && i+1 < len(lines) {
			logical = strings.TrimSuffix(logical, "\\") + lines[i+1].text
			i++
		}
		t := strings.TrimSpace(logical)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// A heredoc body is data, not a command position: skip it to the closing
		// delimiter (prevents both false positives on interpolated data and being
		// misled by quoting inside the body). The opener line is still analyzed.
		if m := reHeredoc.FindStringSubmatch(logical); m != nil {
			delim := m[1]
			for i+1 < len(lines) {
				if strings.TrimSpace(lines[i+1].text) == delim {
					i++
					break
				}
				i++
			}
		}
		if name, ok := shellUnsafeUse(logical, names, makeMode); ok {
			out = append(out, &unsafeSite{File: file, Line: startIdx + 1, Name: name, Code: trim(startText)})
		}
	}
	return out
}

// endsWithContinuation reports a trailing odd-count backslash (a real line
// continuation; `\\` at end is an escaped backslash, not a continuation).
func endsWithContinuation(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// reVarRef matches a shell variable reference: $NAME or ${NAME}. reVarRefMake
// matches the make-escaped form $$NAME / $${NAME}.
var (
	reVarRef     = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	reVarRefMake = regexp.MustCompile(`\$\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
)

// shellUnsafeUse reports whether an untrusted variable is used unsafely on a
// shell line. A use is unsafe if the line evaluates the value (eval / backticks
// / command substitution containing the var) or the reference is unquoted
// (subject to word-splitting, globbing, and metacharacter injection). A use
// wholly inside double or single quotes — the recommended pattern "$VAR" — is
// treated as safe. makeMode expects the `$$VAR` escaping used in Makefile
// recipes.
func shellUnsafeUse(line string, names map[string]bool, makeMode bool) (string, bool) {
	rx := reVarRef
	if makeMode {
		rx = reVarRefMake
	}
	// `eval` anywhere on a line that references an untrusted var is unsafe: eval
	// re-parses its argument as code regardless of quoting.
	hasEval := reEval.MatchString(line)
	for _, loc := range rx.FindAllStringSubmatchIndex(line, -1) {
		name := line[loc[2]:loc[3]]
		if !names[name] {
			continue
		}
		if hasEval {
			return name, true
		}
		switch quoteStateAt(line, loc[0]) {
		case quoteNone:
			return name, true // unquoted expansion
		case quoteCommandSub:
			return name, true // inside $(...) or backticks — executed
		}
		// quoteDouble / quoteSingle: the value is a quoted argument — safe.
	}
	return "", false
}

var reEval = regexp.MustCompile(`(?:^|[\s;&|(])eval(?:\s|$)`)

type quoteState int

const (
	quoteNone quoteState = iota
	quoteSingle
	quoteDouble
	quoteCommandSub // inside $( ... ) or backticks (the command word position)
)

// quoteStateAt returns the shell-quoting context at byte position pos on a line.
// It is a pragmatic single-line scanner that tracks a stack of nesting contexts:
// single quotes (no expansion), double quotes (expansion, but the value is a
// quoted argument), $(...) command substitution, and backticks. Backslash
// escapes the next byte outside single quotes (so an escaped quote does not open
// or close a region). The classify is the innermost (top-of-stack) context, so
// `"$(echo "$X")"` correctly resolves $X as double-quoted (safe), while
// `$(echo $X)` resolves it as a command-substitution command position
// (executed → unsafe).
func quoteStateAt(line string, pos int) quoteState {
	const (
		ctxSingle   = 'S'
		ctxDouble   = 'D'
		ctxCmdSub   = 'C' // $( ... )
		ctxBacktick = '`'
	)
	var stack []rune
	top := func() rune {
		if len(stack) == 0 {
			return 0
		}
		return stack[len(stack)-1]
	}
	pop := func() {
		if len(stack) > 0 {
			stack = stack[:len(stack)-1]
		}
	}
	for i := 0; i < pos && i < len(line); i++ {
		c := rune(line[i])
		if top() == ctxSingle {
			if c == '\'' {
				pop()
			}
			continue
		}
		// Outside single quotes, a backslash escapes the next byte.
		if c == '\\' {
			i++
			continue
		}
		switch c {
		case '\'':
			if top() != ctxDouble { // a single quote inside "" is literal
				stack = append(stack, ctxSingle)
			}
		case '"':
			if top() == ctxDouble {
				pop()
			} else {
				stack = append(stack, ctxDouble)
			}
		case '`':
			if top() == ctxBacktick {
				pop()
			} else {
				stack = append(stack, ctxBacktick)
			}
		case '$':
			if i+1 < len(line) && line[i+1] == '(' {
				stack = append(stack, ctxCmdSub)
				i++
			}
		case ')':
			if top() == ctxCmdSub {
				pop()
			}
		}
	}
	switch top() {
	case ctxSingle:
		return quoteSingle
	case ctxDouble:
		return quoteDouble
	case ctxCmdSub, ctxBacktick:
		return quoteCommandSub
	default:
		return quoteNone
	}
}

// splitLines normalizes CRLF and strips a leading UTF-8 BOM (Windows editors),
// matching the pipeline-file loaders so first-line handling is consistent.
func splitLines(data []byte) []string {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	s = strings.TrimPrefix(s, string([]byte{0xEF, 0xBB, 0xBF})) // strip a leading UTF-8 BOM
	return strings.Split(s, "\n")
}

// relPath reports the path of full relative to root (for readable evidence).
func relPath(root, full string) (string, error) {
	return filepath.Rel(root, full)
}
