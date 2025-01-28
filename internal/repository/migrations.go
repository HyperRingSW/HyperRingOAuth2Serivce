package repository

import (
	"fmt"

	"gorm.io/gorm"
	"oauth2-server/internal/models"
)

func RunMigrations(db *gorm.DB) error {
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return fmt.Errorf("ошибка при создании расширения uuid-ossp: %w", err)
	}

	// Выполняем миграции
	if err := db.AutoMigrate(&models.UserAuth{}, &models.Token{}); err != nil {
		return fmt.Errorf("ошибка миграции: %w", err)
	}

	return nil
}
