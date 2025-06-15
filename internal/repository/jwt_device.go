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

	if repo.TokenRepository().FindRefreshToken(jwtD.RefreshToken) == nil {
		return nil, errors.New("jwt device not found by refresh token")
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

func (repo *PostgresDB) SaveJwtDevice(userID uint, provider string, jwtDevice *models.JwtDevice) (*models.JwtDevice, error) {
	var existingJwtDevice models.JwtDevice

	if jwtDevice.RefreshToken == "" {
		token := repo.TokenRepository().UserToken(userID, provider, jwtDevice.DeviceUUID)
		if token == nil {
			err := fmt.Errorf("user token not found SaveJwtDevice")
			return nil, err
		}
		jwtDevice.RefreshToken = token.RefreshToken
	}

	result := repo.db.Where("jwt = ?", jwtDevice.JWT).FirstOrCreate(&existingJwtDevice, jwtDevice)

	if result.Error != nil {
		err := fmt.Errorf("create user auth failed: %w", result.Error)
		return nil, err
	}

	return &existingJwtDevice, nil
}

func (repo *PostgresDB) AddRefreshTokenJwtDevice(jwt string, refreshToken string) error {
	updates := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	return repo.db.Model(&models.JwtDevice{}).Where("jwt = ?", jwt).Updates(updates).Error
}

func (repo *PostgresDB) DeleteJwtDevice(jwt string) error {

	updates := map[string]interface{}{
		"status": false,
	}

	result := repo.db.Model(&models.JwtDevice{}).Where("jwt = ?", jwt).Updates(updates)
	if result.Error != nil {
		return result.Error
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
