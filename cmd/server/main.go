package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/codeql-platform/internal/config"
	"github.com/codeql-platform/internal/handler"
	"github.com/codeql-platform/internal/model"
	"github.com/codeql-platform/internal/scanner"
	"github.com/codeql-platform/internal/service"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/cors"
)

func main() {
	// 配置加载
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	// initialize database
	db, err := model.InitDB(&cfg.Database)
	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}

	// 依赖注入
	repoSvc := service.NewRepoService(db)
	repoHandler := handler.NewRepoHandler(repoSvc)

	scanWorker := scanner.NewScanWorker(&cfg.Scanner)
	scanSvc := service.NewScanService(db, scanWorker) // 这里假设 Service 接收了 Worker
	scanHandler := handler.NewScanHandler(scanSvc)

	// 路由
	r := gin.Default()
	r.Use(cors.Default())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		// 仓库管理 api
		v1.POST("/repos", repoHandler.CreateRepos)
		v1.GET("/repos/list", repoHandler.ListRepos)          // 列表
		v1.POST("/repos/update/:id", repoHandler.UpdateRepos) // 更新
		v1.POST("/repos/delete/:id", repoHandler.DeleteRepos) // 删除

		// 扫描任务 api
		v1.POST("/scan/tasks", scanHandler.CreateTask)
		v1.GET("/scan/ListTasks", scanHandler.ListTasks)
		v1.GET("/scan/vulnerabilities", scanHandler.ListVulnerabilities)
	}

	log.Printf("Server starting on:http://localhost:%d", cfg.Server.Port)
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
