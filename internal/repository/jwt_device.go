package repository

import (
	"errors"
	"fmt"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
)

type jwtDeviceRepository struct {
	*PostgresDB
}

func (repo *PostgresDB) JwtDeviceRepository() dependency.JwtDeviceRepository {
	return &jwtDeviceRepository{
		PostgresDB: repo,
	}
}

func (repo *PostgresDB) GetJwtDevice(jwt string) (*models.JwtDevice, error) {
	var jwtD models.JwtDevice
	result := repo.db.Where("jwt = ? and (status IS NULL or status = true)", jwt).First(&jwtD)
	if result.RowsAffected == 0 {
		return nil, errors.New("jwt device not found")
	}
	return &jwtD, nil
}

func (repo *PostgresDB) FindJwt(jwt string) (*models.JwtDevice, error) {
	var jwtD models.JwtDevice
	result := repo.db.Where("jwt = ? ", jwt).First(&jwtD)
	if result.RowsAffected == 0 {
		return nil, errors.New("jwt device not found")
	}
	return &jwtD, nil
}

func (repo *PostgresDB) SaveJwtDevice(jwtDevice *models.JwtDevice) (*models.JwtDevice, error) {
	var existingJwtDevice models.JwtDevice
	result := repo.db.Where("jwt = ?", jwtDevice.JWT).FirstOrCreate(&existingJwtDevice, jwtDevice)

	if result.Error != nil {
		err := fmt.Errorf("create user auth failed: %w", result.Error)
		return nil, err
	}

	return &existingJwtDevice, nil
}

func (repo *PostgresDB) DeleteJwtDevice(jwt string) error {
	/*if mode {
		updates := map[string]interface{}{
			"status": false,
		}

		err := repo.db.Model(&models.JwtDevice{}).Where("jwt = ?", jwt).Updates(updates).Error
		if err != nil {
			return err
		}

		return nil
	}

	if err := repo.db.Where("jwt = ?", jwt).Delete(&models.JwtDevice{}).Error; err != nil {
		return errors.New("delete user auth failed: " + err.Error())
	}
	return nil*/

	updates := map[string]interface{}{
		"status": false,
	}

	err := repo.db.Model(&models.JwtDevice{}).Where("jwt = ?", jwt).Updates(updates).Error
	if err != nil {
		return err
	}

	return nil
}

func (repo *PostgresDB) DisableJwtDevice(jwt string) error {
	updates := map[string]interface{}{
		"status": false,
	}

	err := repo.db.Model(&models.JwtDevice{}).Where("jwt = ?", jwt).Updates(updates).Error
	if err != nil {
		return err
	}

	return nil
}
