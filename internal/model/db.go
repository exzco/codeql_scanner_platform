package model

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/codeql-platform/internal/config"
)

func InitDB(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&User{},
		&Repository{},
		&ScanTask{},
		&Vulnerability{},
		&AuditLog{},
	); err != nil {
		return nil, err
	}

	return db, nil
}
