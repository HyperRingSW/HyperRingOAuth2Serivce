package repository

import (
	"fmt"
	"gorm.io/gorm/logger"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"oauth2-server/internal/config"
)

type PostgresDB struct {
	db *gorm.DB
}

func New(cfg config.DatabaseConfig, autoMigrate bool) (*PostgresDB, error) {

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed db connect: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("can`t db connection: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed db connect: %w", err)
	}

	log.Print("DB connected")

	// Миграции
	if autoMigrate {
		log.Println("DB migrations...")
		if err := RunMigrations(db); err != nil {
			return nil, fmt.Errorf("migration error: %w", err)
		}
		log.Println("Migrations done")
	} else {
		log.Println("AutoMigrate disabled")
	}

	return &PostgresDB{db: db}, nil
}

// DB retrieve DB
func (p *PostgresDB) DB() *gorm.DB {
	return p.db
}
