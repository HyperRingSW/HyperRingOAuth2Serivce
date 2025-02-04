package repository

import (
	"errors"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
)

type ringRepository struct {
	*PostgresDB
}

func (repo *PostgresDB) RingRepository() dependency.RingRepository {
	return &ringRepository{PostgresDB: repo}
}

func (repo *PostgresDB) SaveRing(ring *models.Ring) (*models.Ring, error) {
	savedRing := models.Ring{}
	result := repo.db.Where("id = ?", ring.Id).First(&savedRing)
	if result.RowsAffected == 0 {
		if err := repo.db.Create(&ring).Error; err != nil {
			return nil, errors.New("error save ring: " + err.Error())
		}
	}

	return &savedRing, nil
}

func (repo *ringRepository) GetRing(id string) (*models.Ring, error) {
	var ring models.Ring
	if err := repo.db.
		Preload("DeviceDescription").
		Preload("DeviceDescription.Batch").
		Where("id = ?", id).First(&ring).Error; err != nil {
		return nil, errors.New("error get ring: " + err.Error())
	}
	return &ring, nil
}
