package repository

import (
	"errors"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
	"strings"
)

type ringRepository struct {
	*PostgresDB
}

func (repo *PostgresDB) RingRepository() dependency.RingRepository {
	return &ringRepository{
		PostgresDB: repo,
	}
}

func (repo *PostgresDB) SaveRing(ring *models.Ring) (*models.Ring, error) {

	if ring.DeviceDescription.CIN != "" {
		enc, err := util.Encrypt(ring.DeviceDescription.CIN)
		if err != nil {
			return nil, err
		}
		ring.DeviceDescription.CIN = enc
	}

	if ring.DeviceDescription.IIN != "" {
		enc, err := util.Encrypt(ring.DeviceDescription.IIN)
		if err != nil {
			return nil, err
		}
		ring.DeviceDescription.IIN = enc
	}

	savedRing := models.Ring{}
	result := repo.db.Where("id = ?", ring.Id).First(&savedRing)
	if result.RowsAffected == 0 {
		if err := repo.db.Create(&ring).Error; err != nil {
			return nil, errors.New("error save ring: " + err.Error())
		}
	} else {
		return nil, errors.New("ring already exists")
	}

	return &savedRing, nil
}

func (repo *PostgresDB) UpdateRingName(ringId string, userNamed string) error {
	userNamed = strings.TrimSpace(userNamed)
	userNamed, err := util.Encrypt(userNamed)
	if err != nil {
		return err
	}
	updates := map[string]interface{}{
		"user_named": userNamed,
	}

	if err := repo.db.Model(&models.Ring{}).Where("id = ?", ringId).Updates(updates).Error; err != nil {
		return err
	}

	return nil
}

func (repo *ringRepository) GetRing(id string) (*models.Ring, error) {
	var ring models.Ring
	if err := repo.db.
		Preload("DeviceDescription").
		Preload("DeviceDescription.Batch").
		Preload("Services").
		Where("id = ?", id).First(&ring).Error; err != nil {
		return nil, errors.New("error get ring: " + err.Error())
	}
	dec, err := util.Decrypt(ring.DeviceDescription.CIN)
	if err != nil {
		return nil, err
	}
	ring.DeviceDescription.CIN = dec

	dec, err = util.Decrypt(ring.DeviceDescription.IIN)
	if err != nil {
		return nil, err
	}
	ring.DeviceDescription.IIN = dec

	if ring.UserNamed != "" {
		dec, err = util.Decrypt(ring.UserNamed)
		if err != nil {
			return nil, err
		}
		ring.UserNamed = dec
	}

	return &ring, nil
}

func (repo *ringRepository) DeleteRing(ringId string) error {
	if err := repo.db.
		Preload("DeviceDescription").
		Preload("DeviceDescription.Batch").
		Preload("Services").
		Delete(&models.Ring{}, "id = ?", ringId).Error; err != nil {
		return err
	}
	return nil
}
