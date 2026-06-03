// Package benchmark is the Caminus precision/recall harness. It scans a labeled
// corpus of CI/CD pipelines (manifest.jsonl + corpus/) with the real built
// binary and scores Caminus per rule class. Run it with:
//
//	go test ./benchmark/ -run Benchmark -v
//
// The corpus encodes KNOWN pipeline-attack patterns as ground truth — including
// patterns Caminus does not yet detect (known_gap), so the scorecard is an honest
// statement of coverage, not a victory lap. See README.md for methodology.
package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type caseSpec struct {
	ID       string   `json:"id"`
	Dir      string   `json:"dir"`
	Platform string   `json:"platform"`
	Polarity string   `json:"polarity"` // vuln | safe
	Expect   []string `json:"expect"`   // rules that SHOULD fire (vuln)
	Forbid   []string `json:"forbid"`   // rules that must NOT fire (safe)
	KnownGap bool     `json:"known_gap"`
	Source   string   `json:"source"`
	Note     string   `json:"note"`
}

var caminusBin string

// row is one line of the printed scorecard.
type row struct{ id, verdict, detail string }

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "caminus-bench")
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench: mktemp:", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "caminus")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "../cmd/caminus")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: build caminus: %v\n%s", err, out)
		os.Exit(1)
	}
	caminusBin = bin
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// rulesFired runs the real binary over a corpus case and returns the set of rule
// IDs reported. --gate none keeps the exit code 0; --min-severity info captures
// everything, including Info-level UNASSESSED notices.
func rulesFired(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out, err := exec.Command(caminusBin, "scan", filepath.Join("corpus", dir),
		"--format", "json", "--gate", "none", "--min-severity", "info").Output()
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	var rep struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("scan %s: parse json: %v", dir, err)
	}
	set := map[string]bool{}
	for _, f := range rep.Findings {
		set[f.RuleID] = true
	}
	return set
}

func loadManifest(t *testing.T) []caseSpec {
	t.Helper()
	data, err := os.ReadFile("manifest.jsonl")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var cases []caseSpec
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c caseSpec
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("manifest line %d: %v", i+1, err)
		}
		cases = append(cases, c)
	}
	return cases
}

func TestBenchmark(t *testing.T) {
	cases := loadManifest(t)

	var tp, fn, fp, tn, gapCaught, gapMissed int
	var covered, safes, gaps []row

	for _, c := range cases {
		fired := rulesFired(t, c.Dir)

		switch {
		case c.Polarity == "vuln" && c.KnownGap:
			if anyFired(fired, c.Expect) {
				gapCaught++
				gaps = append(gaps, row{c.ID, "NOW-COVERED", "expected " + strings.Join(c.Expect, ",") + " — relabel known_gap=false"})
				t.Errorf("[%s] labeled known_gap but Caminus now detects it — update manifest", c.ID)
			} else {
				gapMissed++
				gaps = append(gaps, row{c.ID, "gap (miss)", c.Note})
			}

		case c.Polarity == "vuln":
			if anyFired(fired, c.Expect) {
				tp++
				covered = append(covered, row{c.ID, "TP", "fired " + strings.Join(c.Expect, ",")})
			} else {
				fn++
				covered = append(covered, row{c.ID, "FN (MISS)", "expected " + strings.Join(c.Expect, ",") + " got " + firedList(fired)})
				t.Errorf("[%s] FALSE NEGATIVE: expected %v, fired %v", c.ID, c.Expect, firedList(fired))
			}

		case c.Polarity == "safe":
			if bad := intersect(fired, c.Forbid); len(bad) > 0 {
				fp++
				safes = append(safes, row{c.ID, "FP", "wrongly fired " + strings.Join(bad, ",")})
				t.Errorf("[%s] FALSE POSITIVE: forbidden rule(s) fired: %v", c.ID, bad)
			} else {
				tn++
				safes = append(safes, row{c.ID, "TN", "clean on " + strings.Join(c.Forbid, ",")})
			}
		}
	}

	// Scorecard (always printed; -v to see it).
	var b strings.Builder
	fmt.Fprintf(&b, "\n================ Caminus benchmark scorecard ================\n")
	fmt.Fprintf(&b, "corpus: %d cases  (%d covered-vuln, %d safe, %d known-gap)\n\n",
		len(cases), tp+fn, fp+tn, gapCaught+gapMissed)

	fmt.Fprintf(&b, "-- covered vulnerabilities (recall) --\n")
	printRows(&b, covered)
	fmt.Fprintf(&b, "-- safe / near-miss pipelines (precision) --\n")
	printRows(&b, safes)
	fmt.Fprintf(&b, "-- known coverage gaps (honest frontier) --\n")
	printRows(&b, gaps)

	recall := ratio(tp, tp+fn)
	precision := ratio(tp, tp+fp)
	fmt.Fprintf(&b, "\nTP=%d  FN=%d  FP=%d  TN=%d   (gaps: %d missed, %d now-covered)\n", tp, fn, fp, tn, gapMissed, gapCaught)
	fmt.Fprintf(&b, "precision = TP/(TP+FP) = %.1f%%\n", 100*precision)
	fmt.Fprintf(&b, "recall    = TP/(TP+FN) = %.1f%%   (over covered classes; gaps excluded by design)\n", 100*recall)
	fmt.Fprintf(&b, "============================================================\n")
	t.Log(b.String())
}

func anyFired(fired map[string]bool, want []string) bool {
	for _, w := range want {
		if fired[w] {
			return true
		}
	}
	return false
}

func intersect(fired map[string]bool, forbid []string) []string {
	var out []string
	for _, f := range forbid {
		if fired[f] {
			out = append(out, f)
		}
	}
	return out
}

func firedList(fired map[string]bool) string {
	if len(fired) == 0 {
		return "(none)"
	}
	var out []string
	for k := range fired {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

func printRows(b *strings.Builder, rows []row) {
	for _, r := range rows {
		fmt.Fprintf(b, "  %-28s %-12s %s\n", r.id, r.verdict, r.detail)
	}
	if len(rows) == 0 {
		fmt.Fprintf(b, "  (none)\n")
	}
}
