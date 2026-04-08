package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SARIF structures for parsing CodeQL output
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name  string      `json:"name"`
	Rules []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription SARIFMessage         `json:"shortDescription"`
	FullDescription  SARIFMessage         `json:"fullDescription"`
	DefaultConfig    SARIFDefaultConfig   `json:"defaultConfiguration"`
	Properties       SARIFRuleProperties  `json:"properties"`
}

type SARIFDefaultConfig struct {
	Level string `json:"level"` // error, warning, note
}

type SARIFRuleProperties struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"security-severity"`
	Problem  struct {
		Severity string `json:"severity"`
	} `json:"problem"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID              string              `json:"ruleId"`
	RuleIndex           int                 `json:"ruleIndex"`
	Message             SARIFMessage        `json:"message"`
	Locations           []SARIFLocation     `json:"locations"`
	CodeFlows           []SARIFCodeFlow     `json:"codeFlows"`
	PartialFingerprints map[string]string   `json:"partialFingerprints"`
	Level               string              `json:"level"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
	ContextRegion    *SARIFRegion          `json:"contextRegion,omitempty"`
}

type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type SARIFRegion struct {
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
	Snippet     *SARIFSnippet `json:"snippet,omitempty"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
	Message  *SARIFMessage `json:"message,omitempty"`
}

// ParsedVulnerability represents a vulnerability parsed from SARIF
type ParsedVulnerability struct {
	RuleID      string      `json:"rule_id"`
	RuleName    string      `json:"rule_name"`
	Severity    string      `json:"severity"`
	FilePath    string      `json:"file_path"`
	StartLine   int         `json:"start_line"`
	EndLine     int         `json:"end_line"`
	CodeSnippet string      `json:"code_snippet"`
	Message     string      `json:"message"`
	DataFlow    []FlowStep  `json:"data_flow"`
	Fingerprint string      `json:"fingerprint"`
}

type FlowStep struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	Message   string `json:"message"`
	Snippet   string `json:"snippet"`
}

// ParseSARIF reads and parses a SARIF file into structured vulnerabilities
func ParseSARIF(filePath string) ([]ParsedVulnerability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SARIF file: %w", err)
	}

	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	var vulns []ParsedVulnerability

	for _, run := range report.Runs {
		// Build a rule lookup map
		ruleMap := buildRuleMap(run.Tool.Driver.Rules)

		for _, result := range run.Results {
			vuln := ParsedVulnerability{
				RuleID:  result.RuleID,
				Message: result.Message.Text,
			}

			// Get rule details
			if rule, ok := ruleMap[result.RuleID]; ok {
				vuln.RuleName = rule.ShortDescription.Text
				vuln.Severity = mapSeverity(rule, result.Level)
			} else {
				vuln.Severity = mapLevelToSeverity(result.Level)
			}

			// Primary location
			if len(result.Locations) > 0 {
				loc := result.Locations[0].PhysicalLocation
				vuln.FilePath = loc.ArtifactLocation.URI
				vuln.StartLine = loc.Region.StartLine
				vuln.EndLine = loc.Region.EndLine
				if vuln.EndLine == 0 {
					vuln.EndLine = vuln.StartLine
				}
				if loc.ContextRegion != nil && loc.ContextRegion.Snippet != nil {
					vuln.CodeSnippet = loc.ContextRegion.Snippet.Text
				} else if loc.Region.Snippet != nil {
					vuln.CodeSnippet = loc.Region.Snippet.Text
				}
			}

			// Data flow (code flows / taint tracking path)
			vuln.DataFlow = extractDataFlow(result.CodeFlows)

			// Fingerprint for deduplication
			if fp, ok := result.PartialFingerprints["primaryLocationLineHash"]; ok {
				vuln.Fingerprint = fp
			} else {
				// Generate a simple fingerprint
				vuln.Fingerprint = fmt.Sprintf("%s:%s:%d", result.RuleID, vuln.FilePath, vuln.StartLine)
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func buildRuleMap(rules []SARIFRule) map[string]SARIFRule {
	m := make(map[string]SARIFRule, len(rules))
	for _, r := range rules {
		m[r.ID] = r
	}
	return m
}

func mapSeverity(rule SARIFRule, level string) string {
	// Try security-severity score first
	if rule.Properties.Severity != "" {
		return securityScoreToSeverity(rule.Properties.Severity)
	}
	return mapLevelToSeverity(level)
}

func securityScoreToSeverity(score string) string {
	// Parse float from string
	var s float64
	fmt.Sscanf(score, "%f", &s)
	switch {
	case s >= 9.0:
		return "critical"
	case s >= 7.0:
		return "high"
	case s >= 4.0:
		return "medium"
	case s >= 0.1:
		return "low"
	default:
		return "info"
	}
}

func mapLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "info"
	}
}

func extractDataFlow(codeFlows []SARIFCodeFlow) []FlowStep {
	var steps []FlowStep
	for _, cf := range codeFlows {
		for _, tf := range cf.ThreadFlows {
			for _, loc := range tf.Locations {
				step := FlowStep{
					FilePath:  loc.Location.PhysicalLocation.ArtifactLocation.URI,
					StartLine: loc.Location.PhysicalLocation.Region.StartLine,
				}
				if loc.Message != nil {
					step.Message = loc.Message.Text
				}
				if loc.Location.PhysicalLocation.Region.Snippet != nil {
					step.Snippet = loc.Location.PhysicalLocation.Region.Snippet.Text
				}
				steps = append(steps, step)
			}
		}
	}
	return steps
}
