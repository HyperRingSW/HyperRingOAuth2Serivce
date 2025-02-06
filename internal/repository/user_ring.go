package repository

import (
	"errors"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
)

type userRingRepository struct {
	*PostgresDB
}

func (repo *PostgresDB) UserRingRepository() dependency.UserRingRepository {
	return &userRingRepository{
		PostgresDB: repo,
	}
}

func (repo *PostgresDB) SaveUserRing(ur *models.UserRing) error {
	save := models.UserRing{}
	result := repo.db.Where("ring_id = ? AND user_id = ?", ur.RingID, ur.UserID).First(&save)
	if result.RowsAffected == 0 {
		if err := repo.db.Create(&ur).Error; err != nil {
			return errors.New("error save ring: " + err.Error())
		}
	}

	return nil
}

func (repo *PostgresDB) DeleteUserRing(userId uint, ringId string) error {
	if err := repo.db.Delete(&models.UserRing{}, "user_id = ? AND ring_id = ?", userId, ringId).Error; err != nil {
		return err
	}
	return nil
}

func (repo *userRingRepository) GetUserRing(userID uint) ([]models.UserRing, error) {
	rings := make([]models.UserRing, 0)
	if err := repo.db.Where("user_id = ?", userID).Find(&rings).Error; err != nil {
		return nil, err
	}
	return rings, nil
}

func (repo *userRingRepository) CheckUserRing(userID uint, ringId string) (*models.UserRing, error) {
	ring := models.UserRing{}

	result := repo.db.Where("user_id = ? AND ring_id = ?", userID, ringId).First(&ring)
	if result.RowsAffected == 0 {
		return nil, errors.New("user ring not found")
	}

	return &ring, nil
}
