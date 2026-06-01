package reporter

import (
	"encoding/json"
	"io"
	"path/filepath"
	"sort"

	"github.com/Su1ph3r/caminus/internal/model"
)

// SARIF 2.1.0 output. Enables GitHub code scanning, CI gating, and any
// SARIF-aware viewer (including the offline viewers shipped by sibling tools).
// Only the subset of the schema Caminus populates is modeled here.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	Properties       sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Category string `json:"category,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifLevel maps Caminus severities onto the three SARIF levels.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes findings as a SARIF 2.1.0 document. The rules array is derived
// from the distinct rules that actually fired, with the highest severity seen
// for each used as its default configuration level.
func SARIF(w io.Writer, version string, fs []model.Finding) error {
	sortFindings(fs)

	type ruleAgg struct {
		rule  sarifRule
		level int
	}
	ruleByID := map[string]*ruleAgg{}
	var order []string
	results := make([]sarifResult, 0, len(fs))

	for _, f := range fs {
		if _, ok := ruleByID[f.RuleID]; !ok {
			help := ""
			if len(f.References) > 0 {
				help = f.References[0]
			}
			ruleByID[f.RuleID] = &ruleAgg{
				rule: sarifRule{
					ID:               f.RuleID,
					Name:             f.RuleID,
					ShortDescription: sarifText{Text: f.Title},
					HelpURI:          help,
					DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
					Properties:       sarifRuleProps{Category: string(f.Category)},
				},
				level: f.Severity.Rank(),
			}
			order = append(order, f.RuleID)
		} else if agg := ruleByID[f.RuleID]; f.Severity.Rank() > agg.level {
			agg.level = f.Severity.Rank()
			agg.rule.DefaultConfig.Level = sarifLevel(f.Severity)
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(f.File)},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(order))
	sort.Strings(order)
	for _, id := range order {
		rules = append(rules, ruleByID[id].rule)
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "caminus",
				Version:        version,
				InformationURI: "https://github.com/Su1ph3r/caminus",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
