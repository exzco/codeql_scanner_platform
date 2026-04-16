package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/scheduler"
	"github.com/codeql-platform/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
)

type WebhookHandler struct {
	repoSvc     *service.RepoService
	scanSvc     *service.ScanService
	asynqClient *asynq.Client
}

func NewWebhookHandler(repoSvc *service.RepoService, scanSvc *service.ScanService, client *asynq.Client) *WebhookHandler {
	return &WebhookHandler{
		repoSvc:     repoSvc,
		scanSvc:     scanSvc,
		asynqClient: client,
	}
}

// GitHub pushes payload structure
type PushPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
	HeadCommit struct {
		Id      string `json:"id"`
		Message string `json:"message"`
	} `json:"head_commit"`
}

func (h *WebhookHandler) HandleGitHubWebhook(c *gin.Context) {
	event := c.GetHeader("X-GitHub-Event")
	if event != "push" {
		c.JSON(http.StatusOK, gin.H{"message": "ignored event", "event": event})
		return
	}

	repoIDStr := c.Param("repo_id")
	var repoID uint
	if _, err := fmt.Sscan(repoIDStr, &repoID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo id in url"})
		return
	}

	repo, err := h.repoSvc.GetByID(repoID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "repo not found"})
		return
	}

	if !repo.IsActive {
		c.JSON(http.StatusOK, gin.H{"message": "repo is inactive"})
		return
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read body"})
		return
	}

	if repo.WebhookSecret != "" {
		signature := c.GetHeader("X-Hub-Signature-256")
		if signature == "" || !verifySignature(signature, bodyBytes, []byte(repo.WebhookSecret)) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
			return
		}
	}

	var payload PushPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to unmarshal JSON"})
		return
	}

	// 提取分支名 (refs/heads/main -> main)
	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")

	// 判断是否只扫描指定分支
	if repo.Branch != "" && repo.Branch != branch {
		log.Printf("[Webhook] ignored push to branch %s, expected %s", branch, repo.Branch)
		c.JSON(http.StatusOK, gin.H{"message": "ignored branch"})
		return
	}

	// 删除前导零并比较 (Github 发送如果是 deleted branch 的话, after 全是零)
	if strings.Trim(payload.After, "0") == "" {
		log.Printf("[Webhook] ignored branch deletion %s", branch)
		c.JSON(http.StatusOK, gin.H{"message": "ignored branch deletion"})
		return
	}
	
	// Create Task
	commitSHA := payload.After
	if h.scanSvc.IsDuplicateTask(repo.ID, commitSHA) {
		log.Printf("[Webhook] task for commit %s is already pending or running", commitSHA)
		c.JSON(http.StatusOK, gin.H{"message": "task already pending/running for this commit"})
		return
	}

	task, err := h.scanSvc.CreateTask(repo.ID, model.TriggerTypeWebhook, branch, repo.Language)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan task: " + err.Error()})
		return
	}
	
	// Update task with the received commit SHA
	if commitSHA != "" {
		h.scanSvc.UpdateTaskStatus(task.ID, task.Status, map[string]interface{}{
			"commit_sha": commitSHA,
		})
	}

	asynqTask, err := scheduler.NewScanRepoTask(repo.ID, task.ID)
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

	log.Printf("[Webhook] scan task enqueued id=%s, queue=%s for repo %s commit %s", info.ID, info.Queue, repo.Name, commitSHA)
	c.JSON(http.StatusOK, gin.H{"message": "webhook handled, task enqueued", "task_id": task.ID})
}

func verifySignature(signature string, payload, secret []byte) bool {
	// signature looks like sha256=123456...
	parts := strings.SplitN(signature, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	actualMAC, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	return hmac.Equal(actualMAC, expectedMAC)
}
