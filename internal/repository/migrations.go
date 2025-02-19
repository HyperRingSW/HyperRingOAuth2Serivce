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
			return fmt.Errorf("failed transfer data from services: %w", err)
		}

		if err := db.Migrator().DropColumn(&models.Ring{}, "services"); err != nil {
			return fmt.Errorf("failed drop column services: %w", err)
		}
	}

	if db.Migrator().HasColumn(&models.DeviceDescription{}, "image_url") {
		if err := db.Migrator().DropColumn(&models.DeviceDescription{}, "image_url"); err != nil {
			return fmt.Errorf("failed drop column image_url: %w", err)
		}
	}

	if db.Migrator().HasColumn(&models.DeviceDescription{}, "site_url") {
		if err := db.Migrator().DropColumn(&models.DeviceDescription{}, "site_url"); err != nil {
			return fmt.Errorf("failed drop column site_url: %w", err)
		}
	}

	if !db.Migrator().HasColumn(&models.Token{}, "device_uuid") {
		addColumnQuery := fmt.Sprintf(`
			ALTER TABLE tokens
			ADD COLUMN device_uuid VARCHAR(255) DEFAULT '%s'
		`, models.DefaultUUID)
		if err := db.Exec(addColumnQuery).Error; err != nil {
			return fmt.Errorf("failed to add column device_uuid in tokens table: %w", err)
		}
	}

	updateQuery := fmt.Sprintf(`
			UPDATE tokens
			SET device_uuid = '%s'
			WHERE device_uuid IS NULL OR device_uuid = '%s'
		`, models.DefaultUUID, models.DefaultUUID)
	if err := db.Exec(updateQuery).Error; err != nil {
		return fmt.Errorf("failed to update device_uuid for existing tokens: %w", err)
	}

	alterColumnQuery := `
			ALTER TABLE tokens
			ALTER COLUMN device_uuid SET NOT NULL
		`
	if err := db.Exec(alterColumnQuery).Error; err != nil {
		return fmt.Errorf("failed to set NOT NULL on device_uuid in tokens table: %w", err)
	}

	return nil
}
