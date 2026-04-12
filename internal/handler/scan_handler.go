package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"

	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/scanner"
	"github.com/codeql-platform/internal/scheduler"
	"github.com/codeql-platform/internal/service"
)

type ScanHandler struct {
	scanSvc     *service.ScanService
	asynqClient *asynq.Client
}

func NewScanHandler(svc *service.ScanService, client *asynq.Client) *ScanHandler {
	return &ScanHandler{scanSvc: svc, asynqClient: client}
}

func (h *ScanHandler) CreateTask(c *gin.Context) {
	var req model.CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := h.scanSvc.CreateTask(req.RepoID, model.TriggerTypeManual, req.Branch, req.Language)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan task: " + err.Error()})
		return
	}

	asynqTask, err := scheduler.NewScanRepoTask(req.RepoID, task.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build async task: " + err.Error()})
		return
	}

	info, err := h.asynqClient.Enqueue(asynqTask)
	if err != nil {
		h.scanSvc.UpdateTaskStatus(task.ID, model.TaskStatusFailed, map[string]interface{}{
			"error_msg": "failed to enqueue task: " + err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue task: " + err.Error()})
		return
	}

	log.Printf("[API] scan task enqueued id=%s, queue=%s", info.ID, info.Queue)

	c.JSON(http.StatusOK, gin.H{
		"message": "scan task submitted",
		"data": gin.H{
			"task_id":  task.ID,
			"queue_id": info.ID,
			"queue":    info.Queue,
		},
	})
}

func (h *ScanHandler) ListTasks(c *gin.Context) {
	var query model.ScanTaskQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.scanSvc.ListTasks(&query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "scan tasks fetched", "data": result})
}

func (h *ScanHandler) ListVulnerabilities(c *gin.Context) {
	var query model.VulnQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if taskIDStr := c.Query("task_id"); taskIDStr != "" {
		taskID, err := strconv.ParseUint(taskIDStr, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
			return
		}
		query.TaskID = uint(taskID)
	}

	result, err := h.scanSvc.ListVulnerabilities(&query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "vulnerabilities fetched", "data": result})
}

// ExportSARIF 导出指定任务的 SARIF 结果文件
func (h *ScanHandler) ExportSARIF(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if task.SARIFPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "sarif file not generated yet"})
		return
	}
	if _, err := os.Stat(task.SARIFPath); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "sarif file not found on disk"})
		return
	}

	filename := fmt.Sprintf("task_%d_results.sarif", task.ID)
	c.FileAttachment(task.SARIFPath, filename)
}

// GetSARIFSummary 获取指定任务的 SARIF 结果摘要
func (h *ScanHandler) GetSARIFSummary(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if task.SARIFPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "sarif file not generated yet"})
		return
	}

	data, err := os.ReadFile(task.SARIFPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read sarif file: " + err.Error()})
		return
	}

	var report scanner.SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse sarif json: " + err.Error()})
		return
	}

	parsed, err := scanner.ParseSARIF(task.SARIFPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to normalize sarif: " + err.Error()})
		return
	}

	totalRules := 0
	totalResults := 0
	for _, run := range report.Runs {
		totalRules += len(run.Tool.Driver.Rules)
		totalResults += len(run.Results)
	}

	type ruleHit struct {
		RuleID string `json:"rule_id"`
		Count  int    `json:"count"`
	}
	hitMap := make(map[string]int)
	for _, v := range parsed {
		hitMap[v.RuleID]++
	}
	hits := make([]ruleHit, 0, len(hitMap))
	for id, cnt := range hitMap {
		hits = append(hits, ruleHit{RuleID: id, Count: cnt})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Count == hits[j].Count {
			return hits[i].RuleID < hits[j].RuleID
		}
		return hits[i].Count > hits[j].Count
	})
	if len(hits) > 10 {
		hits = hits[:10]
	}

	type vulnSample struct {
		RuleID        string `json:"rule_id"`
		RuleName      string `json:"rule_name"`
		Severity      string `json:"severity"`
		FilePath      string `json:"file_path"`
		StartLine     int    `json:"start_line"`
		Message       string `json:"message"`
		DataFlowSteps int    `json:"data_flow_steps"`
	}
	samples := make([]vulnSample, 0, 5)
	for i, v := range parsed {
		if i >= 5 {
			break
		}
		samples = append(samples, vulnSample{
			RuleID:        v.RuleID,
			RuleName:      v.RuleName,
			Severity:      v.Severity,
			FilePath:      v.FilePath,
			StartLine:     v.StartLine,
			Message:       v.Message,
			DataFlowSteps: len(v.DataFlow),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "sarif summary",
		"data": gin.H{
			"task_id":            task.ID,
			"sarif_path":         task.SARIFPath,
			"schema":             report.Schema,
			"version":            report.Version,
			"runs_count":         len(report.Runs),
			"rules_count":        totalRules,
			"results_count":      totalResults,
			"vuln_count":         len(parsed),
			"top_rule_hits":      hits,
			"vuln_samples":       samples,
			"parse_entrypoint":   "internal/scanner/sarif.go::ParseSARIF",
			"analyze_cmd_origin": "internal/scanner/codeql.go::Analyze",
		},
	})
}

func parseTaskIDParam(c *gin.Context) (uint, bool) {
	taskID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return 0, false
	}
	return uint(taskID), true
}
