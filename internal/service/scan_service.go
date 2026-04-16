package service

import (
	"encoding/json"
	"fmt"
	"math"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/scanner"
)

type ScanService struct {
	db     *gorm.DB
	worker *scanner.ScanWorker
}

func NewScanService(db *gorm.DB, worker *scanner.ScanWorker) *ScanService {
	return &ScanService{db: db, worker: worker}
}

func (s *ScanService) CreateTask(repoID uint, triggerType, branch, language string, ) (*model.ScanTask, error) {
	task := &model.ScanTask{
		RepoID:      repoID,
		TriggerType: triggerType,
		Branch:      branch,
		Language:    language,
		Status:      model.TaskStatusPending,
	}

	if err := s.db.Create(task).Error; err != nil {
		return nil, err
	}
	return task, nil
}

func (s *ScanService) GetTask(id uint) (*model.ScanTask, error) {
	var task model.ScanTask
	if err := s.db.Preload("Repository").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *ScanService) ListTasks(query *model.ScanTaskQuery) (*model.PaginatedResponse, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PerPage < 1 || query.PerPage > 100 {
		query.PerPage = 20
	}

	db := s.db.Model(&model.ScanTask{})
	if query.RepoID > 0 {
		db = db.Where("repo_id = ?", query.RepoID)
	}
	if query.Status != "" {
		db = db.Where("status = ?", query.Status)
	}

	var total int64
	db.Count(&total)

	var tasks []model.ScanTask
	offset := (query.Page - 1) * query.PerPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(query.PerPage).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return &model.PaginatedResponse{
		Data:       tasks,
		Total:      total,
		Page:       query.Page,
		PerPage:    query.PerPage,
		TotalPages: int(math.Ceil(float64(total) / float64(query.PerPage))),
	}, nil
}

func (s *ScanService) UpdateTaskStatus(taskID uint, status string, updates map[string]interface{}) error {
	if updates == nil {
		updates = map[string]interface{}{}
	}
	updates["status"] = status
	return s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (s *ScanService) SaveVulnerabilities(taskID, repoID uint, parsed []scanner.ParsedVulnerability) (int, error) {
	saved := 0
	for _, p := range parsed {

		dataFlowJSON, _ := json.Marshal(p.DataFlow)

		vuln := &model.Vulnerability{
			ScanTaskID:  taskID,
			RepoID:      repoID,
			RuleID:      p.RuleID,
			RuleName:    p.RuleName,
			Severity:    p.Severity,
			Status:      model.VulnStatusNew,
			FilePath:    p.FilePath,
			StartLine:   p.StartLine,
			EndLine:     p.EndLine,
			CodeSnippet: p.CodeSnippet,
			Message:     p.Message,
			DataFlow:    datatypes.JSON(dataFlowJSON),
			Fingerprint: p.Fingerprint,
		}

		result := s.db.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
			Assign(map[string]interface{}{
				"scan_task_id": taskID,
				"code_snippet": p.CodeSnippet,
				"message":      p.Message,
				"data_flow":    datatypes.JSON(dataFlowJSON),
			}).
			FirstOrCreate(vuln)

		if result.Error != nil {
			return saved, fmt.Errorf("failed to save vulnerability: %w", result.Error)
		}
		saved++
	}

	s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).Update("vuln_count", saved)

	return saved, nil
}

func (s *ScanService) ListVulnerabilities(query *model.VulnQuery) (*model.PaginatedResponse, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PerPage < 1 || query.PerPage > 100 {
		query.PerPage = 20
	}

	db := s.db.Model(&model.Vulnerability{})
	if query.RepoID > 0 {
		db = db.Where("repo_id = ?", query.RepoID)
	}
	if query.TaskID > 0 {
		db = db.Where("scan_task_id = ?", query.TaskID)
	}
	if query.Severity != "" {
		db = db.Where("severity = ?", query.Severity)
	}
	if query.Status != "" {
		db = db.Where("status = ?", query.Status)
	}
	if query.RuleID != "" {
		db = db.Where("rule_id = ?", query.RuleID)
	}

	var total int64
	db.Count(&total)

	var vulns []model.Vulnerability
	offset := (query.Page - 1) * query.PerPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(query.PerPage).Find(&vulns).Error; err != nil {
		return nil, err
	}

	return &model.PaginatedResponse{
		Data:       vulns,
		Total:      total,
		Page:       query.Page,
		PerPage:    query.PerPage,
		TotalPages: int(math.Ceil(float64(total) / float64(query.PerPage))),
	}, nil
}


func (s *ScanService) GetVulnerability(id uint) (*model.Vulnerability, error) {
	var vuln model.Vulnerability
	if err := s.db.Preload("Repository").Preload("ScanTask").Preload("Assignee").First(&vuln, id).Error; err != nil {
		return nil, err
	}
	return &vuln, nil
}

func (s *ScanService) UpdateVulnStatus(vulnID, operatorID uint, req *model.UpdateVulnStatusRequest) error {
	vuln, err := s.GetVulnerability(vulnID)
	if err != nil {
		return err
	}

	oldStatus := vuln.Status
	if err := s.db.Model(vuln).Update("status", req.Status).Error; err != nil {
		return err
	}
	log := &model.AuditLog{
		VulnerabilityID: vulnID,
		OperatorID:      operatorID,
		Action:          "status_change",
		OldStatus:       oldStatus,
		NewStatus:       req.Status,
		Comment:         req.Comment,
	}
	return s.db.Create(log).Error
}

// IsDuplicateTask checks if a scan for the same repo+commit is already running/pending
func (s *ScanService) IsDuplicateTask(repoID uint, commitSHA string) bool {
	if commitSHA == "" {
		return false
	}
	var count int64
	s.db.Model(&model.ScanTask{}).
		Where("repo_id = ? AND commit_sha = ? AND status IN ?", repoID, commitSHA, []string{model.TaskStatusPending, model.TaskStatusRunning}).
		Count(&count)
	return count > 0
}

func (s *ScanService) SaveScanResults(repoID, taskID uint, results []scanner.ParsedVulnerability) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, p := range results {
			vuln := &model.Vulnerability{
				ScanTaskID:  taskID,
				RepoID:      repoID,
				Fingerprint: p.Fingerprint,
			}

			result := tx.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
				Assign(map[string]interface{}{
					"repo_id":      repoID,
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
					"status":       model.VulnStatusNew,
				}).
				FirstOrCreate(vuln)

			if result.Error != nil {
				return fmt.Errorf("保存漏洞失败(rule=%s, file=%s, line=%d): %w", p.RuleID, p.FilePath, p.StartLine, result.Error)
			}
		}
		return nil
	})
}

// asynq 任务队列替换原先的同步执行
// func (s *ScanService) RunFullScan(repoID uint) {
// 	// 1. 获取仓库信息
// 	var repo model.Repository
// 	if err := s.db.First(&repo, repoID).Error; err != nil {
// 		log.Printf("错误：找不到仓库 %d", repoID)
// 		return
// 	}
// 	// 2. 创建一个任务记录
// 	task := &model.ScanTask{
// 		RepoID:   repo.ID,
// 		Status:   "running",
// 		Branch:   repo.Branch,
// 		Language: repo.Language,
// 	}
// 	s.db.Create(task)
// 	// 3. 调用 Worker 开启真实流水线
// 	vulns, sarifPath, err := s.worker.RunScan(context.Background(), task, &repo)

// 	// 4. 更新任务状态与结果
// 	if err != nil {
// 		s.db.Model(task).Updates(map[string]interface{}{
// 			"status":    "failed",
// 			"error_msg": err.Error(),
// 		})
// 		return
// 	}
// 	err = s.SaveScanResults(repo.ID, task.ID, vulns)
// 	if err != nil {
// 		log.Printf("保存结果失败: %v", err)
// 		s.db.Model(task).Updates(map[string]interface{}{
// 			"status":    "failed",
// 			"error_msg": err.Error(),
// 		})
// 		return
// 	}

// 	s.db.Model(task).Updates(map[string]interface{}{
// 		"status":     "success",
// 		"sarif_path": sarifPath,
// 		"vuln_count": len(vulns),
// 	})

// 	log.Printf("任务 %d 扫描成功，发现 %d 个漏洞", task.ID, len(vulns))
// }
