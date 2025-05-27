package repository

import (
	"errors"
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
	result := repo.db.Where("jwt = ?", jwt).First(&jwtD)
	if result.RowsAffected == 0 {
		return nil, errors.New("jwt device not found")
	}
	return &jwtD, nil
}
func (repo *PostgresDB) SaveJwtDevice(jwtDevice *models.JwtDevice) (*models.JwtDevice, error) {
	if err := repo.db.Create(&jwtDevice).Error; err != nil {
		err = errors.New("create user auth failed: " + err.Error())
		return nil, err
	}

	return jwtDevice, nil
}

func (repo *PostgresDB) DeleteJwtDevice(jwt string) error {
	if err := repo.db.Where("jwt = ?", jwt).Delete(&models.JwtDevice{}).Error; err != nil {
		return errors.New("delete user auth failed: " + err.Error())
	}
	return nil
}
