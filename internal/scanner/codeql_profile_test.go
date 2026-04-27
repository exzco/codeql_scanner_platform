package scanner

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/codeql-platform/internal/config"
)

func TestResolveAnalyzeTargets_ProfileAndOverride(t *testing.T) {
	runner := &CodeQLRunner{
		queriesPath:    "/opt/codeql-repo",
		defaultProfile: "baseline",
		profiles: map[string]config.ScannerRuleProfile{
			"baseline": {
				IncludeDefault: true,
				Targets: []string{
					"custom/cve/go-cve-hot.qls",
				},
			},
		},
	}

	targets := runner.resolveAnalyzeTargets("go", "custom/manual.qls, custom/cve/go-cve-hot.qls", "")

	expected := []string{
		filepath.Join("/opt/codeql-repo", "go\\ql\\src\\codeql-suites\\go-security-extended.qls"),
		filepath.Join("/opt/codeql-repo", "custom/cve/go-cve-hot.qls"),
		filepath.Join("/opt/codeql-repo", "custom/manual.qls"),
	}

	if !reflect.DeepEqual(targets, expected) {
		t.Fatalf("unexpected targets:\nwant: %#v\n got: %#v", expected, targets)
	}
}

func TestResolveAnalyzeTargets_ProfileOnlyNoDefault(t *testing.T) {
	runner := &CodeQLRunner{
		queriesPath: "/opt/codeql-repo",
		profiles: map[string]config.ScannerRuleProfile{
			"zero_day_only": {
				IncludeDefault: false,
				Targets: []string{
					"custom/0day/go-0day.qls",
				},
			},
		},
	}

	targets := runner.resolveAnalyzeTargets("go", "", "zero_day_only")
	expected := []string{filepath.Join("/opt/codeql-repo", "custom/0day/go-0day.qls")}

	if !reflect.DeepEqual(targets, expected) {
		t.Fatalf("unexpected targets:\nwant: %#v\n got: %#v", expected, targets)
	}
}
