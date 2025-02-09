package repository

import (
	"fmt"

	"gorm.io/gorm"
	"oauth2-server/internal/models"
)

func RunMigrations(db *gorm.DB) error {
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		return fmt.Errorf("failed install uuid-ossp: %w", err)
	}

	if err := db.AutoMigrate(
		&models.UserAuth{},
		&models.Token{},
		&models.Ring{},
		&models.DeviceDescription{},
		&models.RingBatch{},
		&models.UserRing{},
		&models.RingService{},
	); err != nil {
		return fmt.Errorf("ошибка миграции: %w", err)
	}

	if db.Migrator().HasColumn(&models.Ring{}, "services") {
		if err := db.Exec(`
			INSERT INTO ring_services (ring_id, service)
			SELECT id, services
			FROM rings
			WHERE services IS NOT NULL
		`).Error; err != nil {
			return fmt.Errorf("ошибка переноса данных из колонки services: %w", err)
		}

		if err := db.Migrator().DropColumn(&models.Ring{}, "services"); err != nil {
			return fmt.Errorf("ошибка удаления колонки services: %w", err)
		}
	}

	return nil
}
