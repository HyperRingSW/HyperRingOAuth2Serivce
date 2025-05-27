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
		&models.JwtDevice{},
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

	if db.Migrator().HasColumn(&models.Ring{}, "image_url") || db.Migrator().HasColumn(&models.Ring{}, "site_url") {
		updateQuery := `
			UPDATE device_descriptions d
			SET image_url = r.image_url,
				site_url = r.site_url
			FROM rings r
			WHERE d.ring_id = r.id
			  AND (r.image_url IS NOT NULL OR r.site_url IS NOT NULL)
		`
		if err := db.Exec(updateQuery).Error; err != nil {
			return fmt.Errorf("failed to update device_descriptions from rings: %w", err)
		}

		insertQuery := `
			INSERT INTO device_descriptions (ring_id, image_url, site_url)
			SELECT r.id, r.image_url, r.site_url
			FROM rings r
			WHERE (r.image_url IS NOT NULL OR r.site_url IS NOT NULL)
			  AND NOT EXISTS (
				SELECT 1 FROM device_descriptions d WHERE d.ring_id = r.id
			)
		`
		if err := db.Exec(insertQuery).Error; err != nil {
			return fmt.Errorf("failed to insert into device_descriptions from rings: %w", err)
		}

		/*if db.Migrator().HasColumn(&models.Ring{}, "image_url") {
			if err := db.Migrator().DropColumn(&models.Ring{}, "image_url"); err != nil {
				return fmt.Errorf("failed drop column image_url from rings: %w", err)
			}
		}
		if db.Migrator().HasColumn(&models.Ring{}, "site_url") {
			if err := db.Migrator().DropColumn(&models.Ring{}, "site_url"); err != nil {
				return fmt.Errorf("failed drop column site_url from rings: %w", err)
			}
		}*/
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

	updateTokenQuery := fmt.Sprintf(`
			UPDATE tokens
			SET device_uuid = '%s'
			WHERE device_uuid IS NULL OR device_uuid = '%s'
		`, models.DefaultUUID, models.DefaultUUID)
	if err := db.Exec(updateTokenQuery).Error; err != nil {
		return fmt.Errorf("failed to update device_uuid for existing tokens: %w", err)
	}

	alterColumnQuery := `
			ALTER TABLE tokens
			ALTER COLUMN device_uuid SET NOT NULL
		`
	if err := db.Exec(alterColumnQuery).Error; err != nil {
		return fmt.Errorf("failed to set NOT NULL on device_uuid in tokens table: %w", err)
	}

	if err := db.Exec(`DELETE FROM ring_services WHERE ring_id NOT IN (SELECT ring_id FROM user_rings);`).Error; err != nil {
		return fmt.Errorf("failed DELETE FROM ring_services: %w", err)
	}

	if err := db.Exec(`DELETE FROM device_descriptions WHERE ring_id NOT IN (SELECT ring_id FROM user_rings);`).Error; err != nil {
		return fmt.Errorf("failed DELETE FROM device_descriptions: %w", err)
	}

	if err := db.Exec(`DELETE FROM ring_batches WHERE device_description_id IN (SELECT id FROM device_descriptions WHERE ring_id NOT IN (SELECT ring_id FROM user_rings));`).Error; err != nil {
		return fmt.Errorf("failed DELETE FROM ring_batches: %w", err)
	}

	if err := db.Exec(`DELETE FROM rings WHERE id NOT IN (SELECT ring_id FROM user_rings);`).Error; err != nil {
		return fmt.Errorf("failed DELETE FROM rings: %w", err)
	}

	if err := db.Exec(`DELETE FROM user_rings WHERE ring_id NOT IN (SELECT id FROM rings)`).Error; err != nil {
		return fmt.Errorf("failed DELETE FROM user_rings: %w", err)
	}
	return nil
}
