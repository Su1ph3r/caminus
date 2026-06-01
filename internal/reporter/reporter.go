// Package reporter renders findings for humans and for downstream tools.
//
// Pipeline integration is a first-class Caminus goal: the JSON shape here is the
// seam by which Caminus findings flow into Vinculum (correlation) and onward to
// Ariadne (attack-path synthesis) and Nubicustos (cloud blast-radius), making
// Caminus the missing CI/CD node in that toolchain.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/Su1ph3r/caminus/internal/model"
)

// Report is the top-level JSON document Caminus emits.
type Report struct {
	Tool     string          `json:"tool"`
	Version  string          `json:"version"`
	Findings []model.Finding `json:"findings"`
	Summary  Summary         `json:"summary"`
}

// Summary holds finding counts by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Summarize tallies findings by severity.
func Summarize(fs []model.Finding) Summary {
	s := Summary{Total: len(fs)}
	for _, f := range fs {
		switch f.Severity {
		case model.SevCritical:
			s.Critical++
		case model.SevHigh:
			s.High++
		case model.SevMedium:
			s.Medium++
		case model.SevLow:
			s.Low++
		case model.SevInfo:
			s.Info++
		}
	}
	return s
}

// sortFindings orders by severity (desc), then file, then line — stable and
// deterministic for diffable output.
func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, version string, fs []model.Finding) error {
	sortFindings(fs)
	rep := Report{Tool: "caminus", Version: version, Findings: fs, Summary: Summarize(fs)}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// Text writes a colorized-free, terminal-friendly report.
func Text(w io.Writer, fs []model.Finding) {
	sortFindings(fs)
	if len(fs) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}
	for _, f := range fs {
		conf := ""
		if f.Confirmable {
			conf = "  [confirmable]"
		}
		fmt.Fprintf(w, "[%s] %s%s\n", sevLabel(f.Severity), f.Title, conf)
		fmt.Fprintf(w, "  %s  %s:%d  (%s)\n", f.RuleID, f.File, f.Line, f.Category)
		if f.Evidence != "" {
			fmt.Fprintf(w, "  > %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "  fix: %s\n", f.Remediation)
		}
		fmt.Fprintln(w)
	}
	s := Summarize(fs)
	fmt.Fprintf(w, "%d finding(s): %d critical, %d high, %d medium, %d low, %d info\n",
		s.Total, s.Critical, s.High, s.Medium, s.Low, s.Info)
}

func sevLabel(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "CRIT"
	case model.SevHigh:
		return "HIGH"
	case model.SevMedium:
		return "MED "
	case model.SevLow:
		return "LOW "
	default:
		return "INFO"
	}
}
