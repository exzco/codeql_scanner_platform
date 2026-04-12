package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/codeql-platform/internal/config"
)

type GitManager struct {
	workDir string
}

func NewGitManager(workDir string) *GitManager {
	return &GitManager{workDir: workDir}
}

func (g *GitManager) CloneRepo(ctx context.Context, repoURL, branch, taskID string, authType, authSecret string) (string, error) {
	destDir := filepath.Join(g.workDir, taskID, "src")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	cloneURL := repoURL

	args := []string{"clone", "--depth", "1"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, cloneURL, destDir)
	
	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
	}

	return destDir, nil
}

func (g *GitManager) GetLatestCommit(ctx context.Context, repoDir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = repoDir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get commit: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

type CodeQLRunner struct {
	codeqlPath  string
	queriesPath string
	workDir     string
}

func NewCodeQLRunner(cfg *config.ScannerConfig) *CodeQLRunner {
	return &CodeQLRunner{
		codeqlPath:  cfg.CodeQLPath,
		queriesPath: cfg.CodeQLQueries,
		workDir:     cfg.WorkDir,
	}
}

func (c *CodeQLRunner) CreateDatabase(ctx context.Context, taskID, sourceDir, language string, buildCommand string) (string, error) {
	dbDir := filepath.Join(c.workDir, taskID, "db")

	args := []string{
		"database", "create",
		dbDir,
		"--language=" + language,
		"--source-root=" + sourceDir,
		"--threads=0",
		"--overwrite",
	}

	if buildCommand != "" {
		args = append(args, "--command="+buildCommand)
	}

	cmd := exec.CommandContext(ctx, c.codeqlPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codeql database create failed: %w\noutput: %s", err, string(output))
	}

	return dbDir, nil
}

// Analyze runs CodeQL analysis on the database
func (c *CodeQLRunner) Analyze(ctx context.Context, taskID, dbDir, language, querySuite string) (string, error) {
	outputFile := filepath.Join(c.workDir, taskID, "results.sarif")

	// Determine query suite
	if querySuite == "" {
		querySuite = c.getDefaultQuerySuite(language)
	}

	if !filepath.IsAbs(querySuite) &&
		(strings.HasSuffix(querySuite, ".ql") || strings.HasSuffix(querySuite, ".qls") ||
			strings.Contains(querySuite, "\\") || strings.Contains(querySuite, "/")) {
		querySuite = filepath.Join(c.queriesPath, querySuite)
	}

	args := []string{
		"database", "analyze",
		dbDir,
		querySuite,
		"--format=sarif-latest",
		"--output=" + outputFile,
		"--threads=0",
		"--search-path=" + c.queriesPath,
	}

	cmd := exec.CommandContext(ctx, c.codeqlPath, args...)
	log.Printf("[CodeQL] %s %v", c.codeqlPath, args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codeql database analyze failed: %w\noutput: %s", err, string(output))
	}
	log.Printf("[Task %s] CodeQL 分析完成，结果文件: %s", taskID, outputFile)

	return outputFile, nil
}

// getDefaultQuerySuite returns the default query suite path for a language
func (c *CodeQLRunner) getDefaultQuerySuite(language string) string {
	// Map language to CodeQL query suite
	suiteMap := map[string]string{
		"go":         "go\\ql\\src\\codeql-suites\\go-security-extended.qls",
		"java":       "java\\ql\\src\\codeql-suites\\java-security-extended.qls",
		"javascript": "javascript\\ql\\src\\codeql-suites\\javascript-security-extended.qls",
		"python":     "python\\ql\\src\\codeql-suites\\python-security-extended.qls",
	}
	if suite, ok := suiteMap[language]; ok {
		return suite
	}
	return language + "-security-extended"
}

// Cleanup removes the working directory for a task
func (c *CodeQLRunner) Cleanup(taskID string) error {
	taskDir := filepath.Join(c.workDir, taskID)
	return os.RemoveAll(taskDir)
}

// GetWorkDir returns the work directory path for a task
func (c *CodeQLRunner) GetWorkDir(taskID string) string {
	return filepath.Join(c.workDir, taskID)
}
