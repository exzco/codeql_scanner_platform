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
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// 配置加载
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
	repoHandler := handler.NewRepoHandler(repoSvc)

	asynqClient := scheduler.NewClient(&cfg.Redis)
	defer asynqClient.Close()

	scanSvc := service.NewScanService(db, nil)
	scanHandler := handler.NewScanHandler(scanSvc, asynqClient)
	go scheduler.StartWorker(cfg, db)

	r := gin.Default()
	r.Use(cors.Default())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		// 仓库管理 API
		v1.POST("/repos", repoHandler.CreateRepos)
		v1.GET("/repos/list", repoHandler.ListRepos)
		v1.POST("/repos/update/:id", repoHandler.UpdateRepos)
		v1.POST("/repos/delete/:id", repoHandler.DeleteRepos)

		// 扫描任务 API
		v1.POST("/scan/tasks", scanHandler.CreateTask)
		v1.GET("/scan/ListTasks", scanHandler.ListTasks)
		v1.GET("/scan/vulnerabilities", scanHandler.ListVulnerabilities)
		v1.GET("/scan/tasks/:id/sarif", scanHandler.ExportSARIF)
		v1.GET("/scan/tasks/:id/sarif/summary", scanHandler.GetSARIFSummary)
	}

	log.Printf("Server starting on: http://localhost:%d", cfg.Server.Port)
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
