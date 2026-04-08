package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/codeql-platform/internal/config"
)

// GitManager handles git operations
type GitManager struct {
	workDir string
}

func NewGitManager(workDir string) *GitManager {
	return &GitManager{workDir: workDir}
}

// CloneRepo clones a repository to a local directory
func (g *GitManager) CloneRepo(ctx context.Context, repoURL, branch, taskID string, authType, authSecret string) (string, error) {
	destDir := filepath.Join(g.workDir, taskID, "src")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Build the authenticated URL if needed
	cloneURL := repoURL
	if authType == "token" && authSecret != "" {
		// Insert token into HTTPS URL: https://token@github.com/...
		cloneURL = strings.Replace(repoURL, "https://", fmt.Sprintf("https://%s@", authSecret), 1)
	}

	args := []string{"clone", "--depth", "1", "--branch", branch, cloneURL, destDir}
	cmd := exec.CommandContext(ctx, "git", args...)

	// For SSH auth, set the GIT_SSH_COMMAND
	if authType == "ssh_key" && authSecret != "" {
		keyFile := filepath.Join(g.workDir, taskID, "ssh_key")
		if err := os.WriteFile(keyFile, []byte(authSecret), 0600); err != nil {
			return "", fmt.Errorf("failed to write SSH key: %w", err)
		}
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", keyFile),
		)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
	}

	return destDir, nil
}

// GetLatestCommit returns the latest commit SHA in the repo
func (g *GitManager) GetLatestCommit(ctx context.Context, repoDir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = repoDir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get commit: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// CodeQLRunner wraps CodeQL CLI operations
type CodeQLRunner struct {
	codeqlPath    string
	queriesPath   string
	workDir       string
}

func NewCodeQLRunner(cfg *config.ScannerConfig) *CodeQLRunner {
	return &CodeQLRunner{
		codeqlPath:  cfg.CodeQLPath,
		queriesPath: cfg.CodeQLQueries,
		workDir:     cfg.WorkDir,
	}
}

// CreateDatabase creates a CodeQL database for the given source code
func (c *CodeQLRunner) CreateDatabase(ctx context.Context, taskID, sourceDir, language string, buildCommand string) (string, error) {
	dbDir := filepath.Join(c.workDir, taskID, "db")

	args := []string{
		"database", "create",
		dbDir,
		"--language=" + language,
		"--source-root=" + sourceDir,
		"--threads=0", // use all available threads
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

	args := []string{
		"database", "analyze",
		dbDir,
		querySuite,
		"--format=sarif-latest",
		"--output=" + outputFile,
		"--threads=0",
	}

	cmd := exec.CommandContext(ctx, c.codeqlPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codeql database analyze failed: %w\noutput: %s", err, string(output))
	}

	return outputFile, nil
}

// getDefaultQuerySuite returns the default query suite path for a language
func (c *CodeQLRunner) getDefaultQuerySuite(language string) string {
	// Map language to CodeQL query suite
	suiteMap := map[string]string{
		"go":         "codeql/go-queries:codeql-suites/go-security-extended.qls",
		"java":       "codeql/java-queries:codeql-suites/java-security-extended.qls",
		"javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
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
