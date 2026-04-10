package handler

import (
	"net/http"
	"strconv"

	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/service"
	"github.com/gin-gonic/gin"
)

type ScanHandler struct {
	scanSvc *service.ScanService
}

func NewScanHandler(svc *service.ScanService) *ScanHandler {
	return &ScanHandler{scanSvc: svc}
}

func (h *ScanHandler) CreateTask(c *gin.Context) {
	var req model.CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	go h.scanSvc.RunFullScan(req.RepoID)

	c.JSON(http.StatusOK, gin.H{"message": "扫描任务已启动，分析完成后可在扫描任务页查看结果"})
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

	c.JSON(http.StatusOK, gin.H{"message": "扫描任务列表获取成功", "data": result})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "task_id 参数非法"})
			return
		}
		query.TaskID = uint(taskID)
	}

	result, err := h.scanSvc.ListVulnerabilities(&query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "漏洞列表获取成功", "data": result})
}
