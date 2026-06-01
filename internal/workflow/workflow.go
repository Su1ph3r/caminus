// Package workflow provides a dependency-free, line-oriented model of a CI/CD
// pipeline definition (currently GitHub Actions YAML).
//
// Caminus deliberately avoids a full YAML parser at this layer. The static
// attack rules reason about *textual* patterns — an untrusted expression
// interpolated inside a `run:` shell, a dangerous trigger, an unpinned action —
// and need exact line numbers and the original text for evidence and for the
// later exploit-PoC stage. A structural parse (planned, behind a build tag)
// will augment this, not replace it. Keeping the core zero-dependency matches
// the rest of the Caminus/Vallum/Vercelsior single-binary house style.
package workflow

import (
	"os"
	"regexp"
	"strings"
)

// Doc is a loaded pipeline file as an indexed slice of lines.
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

// Parse builds a Doc from raw bytes. CRLF is normalized and a leading UTF-8 BOM
// is stripped (common from Windows editors — and this project is developed on
// Windows) so that first-line top-level key detection is not defeated.
func Parse(path string, data []byte) *Doc {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	return &Doc{Path: path, Lines: strings.Split(text, "\n")}
}

var (
	// reOnKey tolerates a quoted top-level key ("on":/'on':), the YAML idiom
	// used to avoid `on` being coerced to the boolean true.
	reOnKey = regexp.MustCompile(`^["']?on["']?\s*:\s*(.*?)\s*$`)
	// reChildKey also tolerates a quoted child key ("pull_request_target":).
	reChildKey = regexp.MustCompile(`^\s*["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*:`)
	reRunKey   = regexp.MustCompile(`^run:\s*([|>].*)?$`)
	// reRunInline is anchored to a YAML key position (line start, optionally a
	// list-item dash) so that the substring "run: " inside a quoted value
	// (e.g. an env: string "please run: ...") is not mistaken for a run step.
	reRunInline = regexp.MustCompile(`^\s*(?:-\s+)?run:\s+[^|>\s]`)
)

// indentOf returns the number of leading spaces on a line (tabs count as one).
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

// Triggers returns the event names under the top-level `on:` key, covering the
// three YAML forms:
//
//	on: push
//	on: [push, pull_request]
//	on:
//	  pull_request_target:
//	    types: [opened]
//
// Only direct children of `on:` are treated as triggers; nested keys such as
// `types:` or `branches:` are ignored.
func (d *Doc) Triggers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		t = strings.TrimSpace(t)
		t = strings.Trim(t, `"'`)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}

	for i := 0; i < len(d.Lines); i++ {
		m := reOnKey.FindStringSubmatch(d.Lines[i])
		if m == nil {
			continue
		}
		rest := m[1]
		switch {
		case rest == "":
			// Block form: collect first-level child keys.
			firstIndent := -1
			for j := i + 1; j < len(d.Lines); j++ {
				t := strings.TrimSpace(d.Lines[j])
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				ind := indentOf(d.Lines[j])
				if ind == 0 {
					break // back to top level; `on:` block is done
				}
				if firstIndent == -1 {
					firstIndent = ind
				}
				if ind == firstIndent {
					if km := reChildKey.FindStringSubmatch(d.Lines[j]); km != nil {
						add(km[1])
					}
				}
			}
		case strings.HasPrefix(rest, "["):
			for _, p := range strings.Split(strings.Trim(rest, "[]"), ",") {
				add(p)
			}
		default:
			add(rest)
		}
	}
	return out
}

// HasTrigger reports whether any of the named triggers is present.
func (d *Doc) HasTrigger(names ...string) bool {
	have := map[string]bool{}
	for _, t := range d.Triggers() {
		have[t] = true
	}
	for _, n := range names {
		if have[n] {
			return true
		}
	}
	return false
}

// InRunContext reports whether the line at idx is part of a `run:` script —
// either inline (`run: echo ...`) or inside a `run: |` block scalar. This is
// what lets the injection rule distinguish a benign expression in an `if:` from
// an attacker-controlled string reaching a shell.
func (d *Doc) InRunContext(idx int) bool {
	if idx < 0 || idx >= len(d.Lines) {
		return false
	}
	if reRunInline.MatchString(d.Lines[idx]) {
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
			if reRunKey.MatchString(t) {
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
