package scheduler

import (
	"log"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"github.com/codeql-platform/internal/config"
	"github.com/codeql-platform/internal/scanner"
)

func StartWorker(cfg *config.Config, db *gorm.DB) {
	srv := asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		},
		asynq.Config{
			Concurrency: cfg.Scanner.MaxConcurrent,
			Queues: map[string]int{
				"scans":   6, 
				"default": 3, 
			},
		},
	)
	// scanWorker := scanner.NewScanWorker(&cfg.Scanner)
	// taskHandler := NewScanTaskHandler(db, scanWorker)
	dispatcher := NewTaskDispatcher(db, scanner.NewScanWorker(&cfg.Scanner))

	mux := asynq.NewServeMux()
	mux.Handle(TypeScanRepo, dispatcher)
	// mux.Handle(TypeScanRepo, taskHandler)


	log.Println("[Asynq Worker] 启动，等待任务...")
	if err := srv.Run(mux); err != nil {
		log.Fatalf("[Asynq Worker] 启动失败: %v", err)
	}
}

func NewClient(cfg *config.RedisConfig) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}
