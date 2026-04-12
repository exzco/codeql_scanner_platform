package scanner

import (
	"context"
	"fmt"
	"log"
	"github.com/codeql-platform/internal/config"
	"github.com/codeql-platform/internal/model"
)

type ScanWorker struct {
	git    *GitManager
	codeql *CodeQLRunner
}

func NewScanWorker(cfg *config.ScannerConfig) *ScanWorker {
	return &ScanWorker{
		git:    NewGitManager(cfg.WorkDir),
		codeql: NewCodeQLRunner(cfg),
	}
}

// RunScan 从代码拉取到生成 SARIF 的流程合在一起
func (w *ScanWorker) RunScan(ctx context.Context, task *model.ScanTask, repo *model.Repository) ([]ParsedVulnerability, string, error) {
	taskID := fmt.Sprintf("%d", task.ID)

	// 1. git Clone 代码
	log.Printf("[Task %d] 正在拉取代码...", task.ID)
	srcDir, err := w.git.CloneRepo(ctx, repo.URL, task.Branch, taskID, repo.AuthType, "") // Token 暂时空
	if err != nil {
		return nil, "", err
	}

	// 2. 创建数据库
	log.Printf("[Task %d] 正在创建 CodeQL 数据库...", task.ID)
	dbDir, err := w.codeql.CreateDatabase(ctx, taskID, srcDir, repo.Language, "")
	if err != nil {
		return nil, "", err
	}

	// 3. 执行分析
	log.Printf("[Task %d] 正在运行 codeql 查询分析...", task.ID)
	sarifFile, err := w.codeql.Analyze(ctx, taskID, dbDir, repo.Language, task.QuerySuite)
	if err != nil {
		return nil, "", err
	}

	// 4. 解析 SARIF
	vulns, err := ParseSARIF(sarifFile)
	return vulns, sarifFile, err
}
