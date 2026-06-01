package rules

import (
	"strings"

	"github.com/Su1ph3r/caminus/internal/workflow"
)

// trim normalizes a line for use as finding evidence: collapse surrounding
// whitespace and cap length so reports stay readable.
func trim(s string) string {
	s = strings.TrimSpace(s)
	const max = 160
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
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
