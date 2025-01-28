package repository

import (
	"fmt"
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

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к базе данных: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить информацию о подключении: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("не удалось подключиться к базе данных: %w", err)
	}

	log.Printf("Подключение к базе данных установлено: %s:%d/%s", cfg.Host, cfg.Port, cfg.Name)

	// Миграции
	if autoMigrate {
		log.Println("Выполняются миграции...")
		if err := RunMigrations(db); err != nil {
			return nil, fmt.Errorf("ошибка миграции: %w", err)
		}
		log.Println("Миграции успешно завершены.")
	} else {
		log.Println("Автоматическая миграция отключена.")
	}

	return &PostgresDB{db: db}, nil
}

// DB retrieve DB
func (p *PostgresDB) DB() *gorm.DB {
	return p.db
}
