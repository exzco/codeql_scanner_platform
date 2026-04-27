package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/codeql-platform/internal/config"
	"github.com/codeql-platform/internal/handler"
	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/scheduler"
	"github.com/codeql-platform/internal/service"
	_ "github.com/codeql-platform/internal/webhook"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// 配置加载：优先读取环境变量 CONFIG_FILE，否则使用默认本地配置
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		configPath = "configs/config.local.yaml"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
	log.Printf("Using config file: %s", configPath)

	// 数据库初始化
	db, err := model.InitDB(&cfg.Database)
	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}

	// 依赖注入
	repoSvc := service.NewRepoService(db)

	asynqClient := scheduler.NewClient(&cfg.Redis)
	defer asynqClient.Close()

	scanSvc := service.NewScanService(db, nil)
	repoHandler := handler.NewRepoHandler(repoSvc)
	scanHandler := handler.NewScanHandler(scanSvc, asynqClient)

	// webhookHandler := webhook.NewWebhookHandler(repoSvc, scanSvc, asynqClient)

	log.Println("[Cron] 定时自动扫描功能已关闭，仅保留手动触发扫描")

	go scheduler.StartWorker(cfg, db)

	r := gin.Default()
	r.Use(cors.Default())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 静态前端文件服务，使用构建产物目录 ./web/dist
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/favicon.svg", "./web/dist/favicon.svg")
	r.StaticFile("/icons.svg", "./web/dist/icons.svg")

	// 非 API 路由全部返回 index.html，由、 Vue Router 处理
	r.NoRoute(func(c *gin.Context) {
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.File("./web/dist/index.html")
	})

	v1 := r.Group("/api/v1")
	{
		// 仓库管理 API
		v1.POST("/repos", repoHandler.CreateRepos)
		v1.GET("/repos/list", repoHandler.ListRepos)
		v1.POST("/repos/update/:id", repoHandler.UpdateRepos)
		v1.POST("/repos/delete/:id", repoHandler.DeleteRepos)
		v1.POST("/repos/batch-delete", repoHandler.BatchDeleteRepos)

		// 扫描任务 API
		v1.POST("/scan/tasks", scanHandler.CreateTask)
		v1.POST("/scan/tasks/delete/:id", scanHandler.DeleteTask)
		v1.GET("/scan/ListTasks", scanHandler.ListTasks)
		v1.GET("/scan/vulnerabilities", scanHandler.ListVulnerabilities)
		v1.GET("/scan/tasks/:id/logs", scanHandler.GetTaskLogs)
		v1.GET("/scan/tasks/:id/sarif", scanHandler.ExportSARIF)
		v1.GET("/scan/tasks/:id/sarif/summary", scanHandler.GetSARIFSummary)

		// // Webhook API 暂时废弃（无公网 ip）
		// v1.POST("/webhook/github/:repo_id", webhookHandler.HandleGitHubWebhook)
	}

	log.Printf("Server starting on: http://localhost:%d", cfg.Server.Port)
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
