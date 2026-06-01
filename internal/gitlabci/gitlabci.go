// Package gitlabci provides a dependency-free, line-oriented model of a GitLab
// CI pipeline (.gitlab-ci.yml).
//
// GitLab CI differs from GitHub Actions enough to warrant its own model rather
// than a forced shared abstraction: shell execution lives in
// script/before_script/after_script (not run:), variable interpolation uses
// $VAR / ${VAR} (not ${{ }}), triggers are expressed through rules:/workflow:/
// only:, and supply-chain entry points come in via include:. Like the rest of
// Caminus this stays zero-dependency and textual, preserving exact line numbers
// and original text for evidence.
package gitlabci

import (
	"os"
	"regexp"
	"strings"
)

// Doc is a loaded .gitlab-ci.yml as an indexed slice of lines.
type Doc struct {
	Path  string
	Lines []string
}

// Load reads a pipeline file from disk.
func Load(path string) (*Doc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data), nil
}

// Parse builds a Doc from raw bytes, normalizing CRLF and stripping a leading
// UTF-8 BOM so first-line key detection (script:/include:) is not defeated.
func Parse(path string, data []byte) *Doc {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	return &Doc{Path: path, Lines: strings.Split(text, "\n")}
}

var (
	reExecKey    = regexp.MustCompile(`^(?:script|before_script|after_script):\s*([|>].*)?$`)
	reExecInline = regexp.MustCompile(`(?:^|\s)(?:script|before_script|after_script):\s+[^|>\s]`)
	rePipeSource = regexp.MustCompile(`CI_PIPELINE_SOURCE\s*[=!]=\s*["']?([a-z_]+)["']?`)
	reOnlyExcept = regexp.MustCompile(`^\s*(?:only|except):\s*(.*?)\s*$`)
	reListItem   = regexp.MustCompile(`^\s*-\s*["']?([a-z_]+)["']?\s*$`)
)

func indentOf(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
			continue
		}
		break
	}
	return n
}

// ExecContext reports whether the line at idx is part of a script,
// before_script, or after_script block — GitLab's shell-execution surface.
func (d *Doc) ExecContext(idx int) bool {
	if idx < 0 || idx >= len(d.Lines) {
		return false
	}
	if reExecInline.MatchString(d.Lines[idx]) {
		return true
	}
	base := indentOf(d.Lines[idx])
	for i := idx - 1; i >= 0; i-- {
		t := strings.TrimSpace(d.Lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentOf(d.Lines[i])
		if ind < base {
			if reExecKey.MatchString(t) {
				return true
			}
			base = ind
			if base == 0 {
				return false
			}
		}
	}
	return false
}

// Sources returns the pipeline trigger sources referenced in the file: the
// values compared against CI_PIPELINE_SOURCE in rules:/workflow: `if:` clauses,
// plus only:/except: keywords (merge_requests, external_pull_requests, …).
func (d *Doc) Sources() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	for i, line := range d.Lines {
		for _, m := range rePipeSource.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
		if m := reOnlyExcept.FindStringSubmatch(line); m != nil {
			rest := m[1]
			switch {
			case rest == "":
				// Block list form: collect following list items at one indent.
				for j := i + 1; j < len(d.Lines); j++ {
					t := strings.TrimSpace(d.Lines[j])
					if t == "" || strings.HasPrefix(t, "#") {
						continue
					}
					if im := reListItem.FindStringSubmatch(d.Lines[j]); im != nil {
						add(im[1])
						continue
					}
					break
				}
			case strings.HasPrefix(rest, "["):
				for _, p := range strings.Split(strings.Trim(rest, "[]"), ",") {
					add(strings.Trim(strings.TrimSpace(p), `"'`))
				}
			default:
				add(strings.Trim(rest, `"'`))
			}
		}
	}
	return out
}

// HasSource reports whether any of the named sources is referenced.
func (d *Doc) HasSource(names ...string) bool {
	have := map[string]bool{}
	for _, s := range d.Sources() {
		have[s] = true
	}
	for _, n := range names {
		if have[n] {
			return true
		}
	}
	return false
}

// MergeRequestTriggered reports whether the pipeline runs on merge-request or
// external-PR events — the GitLab equivalent of a fork-influenced trigger.
func (d *Doc) MergeRequestTriggered() bool {
	return d.HasSource("merge_request_event", "merge_requests", "external_pull_request_event", "external_pull_requests")
}

// Include describes one entry under the top-level include: key.
type Include struct {
	Line int
	Kind string // local | remote | project | template | file | unknown
	Ref  string // for project includes: the ref: value, if present nearby
	Raw  string
}

var (
	reIncludeKind = regexp.MustCompile(`^\s*(?:-\s*)?(local|remote|project|template|file):\s*(.*?)\s*$`)
	reRefVal      = regexp.MustCompile(`^\s*(?:-\s+)?ref:\s*["']?([^"'\s]+)["']?`)
)

// Includes parses the top-level include: stanza. It handles the inline scalar
// form (include: 'file.yml') and the block-list form, grouping the block into
// list items and parsing each item as a unit. Parsing per item — rather than
// line-by-line — means a project include's ref: is found regardless of whether
// it precedes or follows the project: key, and that file: (a sub-key of a
// project include) is not mistaken for a separate include.
func (d *Doc) Includes() []Include {
	var out []Include
	for i := 0; i < len(d.Lines); i++ {
		t := strings.TrimSpace(d.Lines[i])
		if !strings.HasPrefix(t, "include:") {
			continue
		}
		includeIndent := indentOf(d.Lines[i])
		// Inline scalar form is self-contained — no block children to scan.
		if v := strings.TrimSpace(strings.TrimPrefix(t, "include:")); v != "" {
			out = append(out, Include{Line: i + 1, Kind: classifyInline(v), Raw: v})
			break
		}
		// Block form: split following entries into list items and parse each.
		itemStart := -1
		flush := func(end int) {
			if itemStart >= 0 {
				if inc := d.parseIncludeItem(itemStart, end); inc != nil {
					out = append(out, *inc)
				}
			}
		}
		j := i + 1
		for ; j < len(d.Lines); j++ {
			lt := strings.TrimSpace(d.Lines[j])
			if lt == "" || strings.HasPrefix(lt, "#") {
				continue
			}
			if indentOf(d.Lines[j]) <= includeIndent {
				break // dedented out of the include: block
			}
			if strings.HasPrefix(lt, "-") {
				flush(j)
				itemStart = j
			}
		}
		flush(j)
		break // include: is a single top-level key
	}
	return out
}

// parseIncludeItem parses one include list item (lines [start,end)). It picks
// the identifying kind (project/remote/local/template preferred over file,
// which is a project sub-key) and any ref:, in either order.
func (d *Doc) parseIncludeItem(start, end int) *Include {
	kind, raw, ref := "", "", ""
	for j := start; j < end && j < len(d.Lines); j++ {
		if ref == "" {
			if rm := reRefVal.FindStringSubmatch(d.Lines[j]); rm != nil {
				ref = rm[1]
			}
		}
		if m := reIncludeKind.FindStringSubmatch(d.Lines[j]); m != nil {
			if kind == "" || (kind == "file" && m[1] != "file") {
				kind, raw = m[1], m[2]
			}
		}
	}
	if kind == "" {
		return nil
	}
	return &Include{Line: start + 1, Kind: kind, Raw: raw, Ref: ref}
}

func classifyInline(v string) string {
	v = strings.Trim(v, `"'`)
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return "remote"
	}
	return "local"
}

// FindLines returns the indices of lines matching rx.
func (d *Doc) FindLines(rx *regexp.Regexp) []int {
	var out []int
	for i, l := range d.Lines {
		if rx.MatchString(l) {
			out = append(out, i)
		}
	}
	return out
}
