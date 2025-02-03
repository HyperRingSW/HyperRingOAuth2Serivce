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
	return &userRingRepository{PostgresDB: repo}
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

func (repo *PostgresDB) DeleteUserRing(ur *models.UserRing) error {
	if err := repo.db.Delete(ur).Error; err != nil {
		return err
	}
	return nil
}
