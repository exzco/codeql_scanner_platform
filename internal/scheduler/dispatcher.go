package scheduler

import (
	"context"
	"log"
	"fmt"
	"encoding/json"
	"time"

	"github.com/hibiken/asynq"
	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/scanner"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

type TaskDispatcher struct {
    db     *gorm.DB
    worker *scanner.ScanWorker
}

func NewTaskDispatcher(db *gorm.DB, worker *scanner.ScanWorker) *TaskDispatcher {
    return &TaskDispatcher{db: db, worker: worker}
}

func (d *TaskDispatcher) ProcessTask(ctx context.Context, t *asynq.Task) error {
    switch t.Type() {
    case TypeScanRepo:
        return d.handleScanRepo(ctx, t)
    // case TypeAIReview:
    //     return d.handleAIReview(ctx, t)
    default:
        return fmt.Errorf("未知任务类型: %s", t.Type())
    }
}

func (d *TaskDispatcher) handleScanRepo(ctx context.Context, t *asynq.Task) error {

	var payload ScanRepoPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("反序列化载荷失败: %w", err)
	}

	log.Printf("[Asynq] 开始处理扫描任务: repo_id=%d, task_id=%d", payload.RepoID, payload.TaskID)

	var repo model.Repository
	if err := d.db.First(&repo, payload.RepoID).Error; err != nil {
		return fmt.Errorf("找不到仓库 %d: %w", payload.RepoID, err)
	}

	var task model.ScanTask
	if err := d.db.First(&task, payload.TaskID).Error; err != nil {
		return fmt.Errorf("找不到任务 %d: %w", payload.TaskID, err)
	}

	now := time.Now()
	d.db.Model(&task).Updates(map[string]interface{}{
		"status":     model.TaskStatusRunning,
		"started_at": now,
	})

	vulns, sarifPath, err := d.worker.RunScan(ctx, &task, &repo, repo.AuthSecret)
	finished := time.Now()
	duration := finished.Sub(now).Milliseconds()

	if err != nil {
		d.db.Model(&task).Updates(map[string]interface{}{
			"status":      model.TaskStatusFailed,
			"finished_at": finished,
			"duration_ms": duration,
			"error_msg":   err.Error(),
		})
		return fmt.Errorf("扫描失败: %w", err) 
	}

	d.saveResults(payload.RepoID, payload.TaskID, vulns)

	d.db.Model(&task).Updates(map[string]interface{}{
		"status":      model.TaskStatusSuccess,
		"finished_at": finished,
		"duration_ms": duration,
		"sarif_path":  sarifPath,
		"vuln_count":  len(vulns),
	})

	log.Printf("[Asynq] 任务 %d 完成，耗时 %dms", payload.TaskID, duration)
	return nil
}

// 这里写的有点乱了，因为 service 也有这个方法，
// 然后我的 TaskDispatcher 结构体中没有引入 ScanService 结构体，没法复用这个方法，只能复制过来改个名用
func (d *TaskDispatcher) saveResults(repoID, taskID uint, results []scanner.ParsedVulnerability) {
	for _, p := range results {
		dataFlowJSON, _ := json.Marshal(p.DataFlow)

		vuln := &model.Vulnerability{
			ScanTaskID:  taskID,
			RepoID:      repoID,
			Fingerprint: p.Fingerprint,
		}

		d.db.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
			Assign(map[string]interface{}{
				"scan_task_id": taskID,
				"file_path":    p.FilePath,
				"start_line":   p.StartLine,
				"end_line":     p.EndLine,
				"message":      p.Message,
				"severity":     p.Severity,
				"rule_id":      p.RuleID,
				"rule_name":    p.RuleName,
				"code_snippet": p.CodeSnippet,
				"fingerprint":  p.Fingerprint,
				"data_flow":    datatypes.JSON(dataFlowJSON),
				"status":       model.VulnStatusNew,
			}).
			FirstOrCreate(vuln)
	}
}

// 后面看看能不能接个我写的 agent ,然后分配审核任务
// func (d *TaskDispatcher) handleAIReview(ctx context.Context, t *asynq.Task) error {
//     
// }
