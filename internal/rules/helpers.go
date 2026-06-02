package rules

import (
	"strings"
	"unicode/utf8"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

// trim normalizes a line for use as finding evidence: collapse surrounding
// whitespace and cap length so reports stay readable. The cap is applied on a
// UTF-8 rune boundary — CI YAML can contain multibyte runes (accented author
// names, emoji in commit messages), and slicing mid-rune would emit invalid
// UTF-8 into the JSON/SARIF reports.
func trim(s string) string {
	s = strings.TrimSpace(s)
	const max = 160
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// firstLineMatching returns the index of the first line satisfying pred, or -1.
func firstLineMatching(doc *workflow.Doc, pred func(string) bool) int {
	for i, l := range doc.Lines {
		if pred(l) {
			return i
		}
	}
	return -1
}

// evidenceAt returns trimmed evidence for a line index, or "" if out of range.
func evidenceAt(doc *workflow.Doc, idx int) string {
	if idx < 0 || idx >= len(doc.Lines) {
		return ""
	}
	return trim(doc.Lines[idx])
}
