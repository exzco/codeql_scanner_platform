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
	db *gorm.DB
}

func NewScanService(db *gorm.DB) *ScanService {
	return &ScanService{db: db}
}

// CreateTask creates a new scan task record
func (s *ScanService) CreateTask(repoID uint, triggerType, branch, language, querySuite string) (*model.ScanTask, error) {
	task := &model.ScanTask{
		RepoID:      repoID,
		TriggerType: triggerType,
		Branch:      branch,
		Language:    language,
		QuerySuite:  querySuite,
		Status:      model.TaskStatusPending,
	}

	if err := s.db.Create(task).Error; err != nil {
		return nil, err
	}
	return task, nil
}

// GetTask returns a scan task with its related repository
func (s *ScanService) GetTask(id uint) (*model.ScanTask, error) {
	var task model.ScanTask
	if err := s.db.Preload("Repository").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

// ListTasks returns paginated scan tasks
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

// UpdateTaskStatus updates the status of a scan task
func (s *ScanService) UpdateTaskStatus(taskID uint, status string, updates map[string]interface{}) error {
	if updates == nil {
		updates = map[string]interface{}{}
	}
	updates["status"] = status
	return s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

// SaveVulnerabilities saves parsed vulnerabilities for a scan task
func (s *ScanService) SaveVulnerabilities(taskID, repoID uint, parsed []scanner.ParsedVulnerability) (int, error) {
	saved := 0
	for _, p := range parsed {
		// Convert data flow to JSON
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

		// Upsert: if same repo + fingerprint exists, update; otherwise create
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

	// Update vuln count on the task
	s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).Update("vuln_count", saved)

	return saved, nil
}

// ListVulnerabilities returns paginated vulnerabilities
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

// GetVulnerability returns a vulnerability by ID
func (s *ScanService) GetVulnerability(id uint) (*model.Vulnerability, error) {
	var vuln model.Vulnerability
	if err := s.db.Preload("Repository").Preload("ScanTask").Preload("Assignee").First(&vuln, id).Error; err != nil {
		return nil, err
	}
	return &vuln, nil
}

// UpdateVulnStatus updates the status of a vulnerability and logs the audit
func (s *ScanService) UpdateVulnStatus(vulnID, operatorID uint, req *model.UpdateVulnStatusRequest) error {
	vuln, err := s.GetVulnerability(vulnID)
	if err != nil {
		return err
	}

	oldStatus := vuln.Status

	// Update the vulnerability status
	if err := s.db.Model(vuln).Update("status", req.Status).Error; err != nil {
		return err
	}

	// Create audit log
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
