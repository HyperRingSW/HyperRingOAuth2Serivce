package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
	"time"
)

type userRepository struct {
	*PostgresDB
}

func (repo *PostgresDB) UserRepository() dependency.UserRepository {
	return &userRepository{
		PostgresDB: repo,
	}
}

// CreateOrUpdateUser
func (repo *PostgresDB) CreateOrUpdateUser(userAuth models.UserAuth) (*models.UserAuth, error) {
	emailEncrypt, err := util.EncryptString(userAuth.Email)
	if err != nil {
		return nil, err
	}

	result := repo.db.Where("email = ?", emailEncrypt).First(&userAuth)
	if result.RowsAffected == 0 {
		userAuth.Email = emailEncrypt

		if userAuth.Name != "" {
			nameEncrypt, err := util.EncryptString(userAuth.Name)
			if err != nil {
				return nil, err
			}
			userAuth.Name = nameEncrypt
		}

		userAuth.Data = "{}"

		if err := repo.db.Create(&userAuth).Error; err != nil {
			err = errors.New("create user auth failed: " + err.Error())
			return nil, err
		}
	} else {
		updates := map[string]interface{}{
			"email":      userAuth.Email,
			"name":       userAuth.Name,
			"updated_at": time.Now(),
		}
		if err := repo.db.Model(&userAuth).Updates(updates).Error; err != nil {
			err = errors.New("update user auth failed: " + err.Error())
			return nil, err
		}
	}

	return &userAuth, nil
}

// FindUserByEmail
func (repo *PostgresDB) FindUserByEmail(email string) *models.UserAuth {
	var user models.UserAuth
	result := repo.db.Where("email = ?", email).First(&user)
	if result.RowsAffected == 0 {
		return nil
	}
	return &user
}

// GetUserByID
func (repo *PostgresDB) GetUserByID(userID uint) *models.UserAuth {
	var user models.UserAuth
	result := repo.db.First(&user, userID)
	if result.RowsAffected == 0 {
		return nil
	}

	if user.Name != "" {
		name, err := util.DecryptString(user.Name)
		if err != nil {
			return nil
		}
		user.Name = name
	}

	if user.Email != "" {
		email, err := util.DecryptString(user.Email)
		if err != nil {
			return nil
		}
		user.Email = email
	}

	return &user
}

// UpdateUser
func (repo *PostgresDB) UpdateUser(userID uint, updates map[string]interface{}) error {
	return repo.db.Model(&models.UserAuth{}).Where("id = ?", userID).Updates(updates).Error
}

// DeleteUser
func (repo *PostgresDB) DeleteUser(userID uint) error {
	tx := repo.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	ur, err := repo.UserRingRepository().GetUserRing(userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, u := range ur {
		err = repo.RingRepository().DeleteRing(u.RingID)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	if err := tx.Where("user_id = ?", userID).Delete(&models.Token{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Where("user_id = ?", userID).Delete(&models.UserRing{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Delete(&models.UserAuth{}, userID).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (repo *PostgresDB) AnonymizeUserData(phrase string, userID uint) error {
	tx := repo.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	ur, err := repo.UserRingRepository().GetUserRing(userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, u := range ur {
		hashCIN := util.GetHash(phrase, u.RingID+"_cin")
		hashIIN := util.GetHash(phrase, u.RingID+"_iin")
		hashDDName := util.GetHash(phrase, u.RingID+"_device_name")
		hashDDDescription := util.GetHash(phrase, u.RingID+"_device_description")
		hashDDImageURL := util.GetHash(phrase, u.RingID+"_device_image_url")
		hashDDSiteURL := util.GetHash(phrase, u.RingID+"_device_site_url")

		if err := tx.Model(&models.DeviceDescription{}).
			Where("ring_id = ?", u.RingID).
			Updates(map[string]interface{}{
				"cin":         hashCIN,
				"iin":         hashIIN,
				"name":        hashDDName,
				"description": hashDDDescription,
				"image_url":   hashDDImageURL,
				"site_url":    hashDDSiteURL,
			}).Error; err != nil {
			tx.Rollback()
			return err
		}

		var deviceDesc models.DeviceDescription
		if err := tx.Where("ring_id = ?", u.RingID).First(&deviceDesc).Error; err == nil {
			newDeviceDescription := util.GetHash(phrase, fmt.Sprintf("%d_isUserName", deviceDesc.ID))
			if err := tx.Model(&models.RingBatch{}).
				Where("device_description_id = ?", deviceDesc.ID).
				Updates(map[string]interface{}{
					"is_user_name": newDeviceDescription,
				}).Error; err != nil {
				tx.Rollback()
				return err
			}
		}

		hashName := util.GetHash(phrase, u.RingID+"_name")
		hashUserNamed := util.GetHash(phrase, u.RingID+"_userNamed")
		hashDescription := util.GetHash(phrase, u.RingID+"_description")

		if err := tx.Model(&models.Ring{}).
			Where("id = ?", u.RingID).
			Updates(map[string]interface{}{
				"name":        hashName,
				"user_named":  hashUserNamed,
				"description": hashDescription,
			}).Error; err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Model(&models.Ring{}).
			Where("id = ?", u.RingID).
			Updates(map[string]interface{}{
				"id": util.GetHash(phrase, fmt.Sprintf("%d_ring_id", u.RingID)),
			}).Error; err != nil {
			tx.Rollback()
			return err
		}

		var UserRing models.UserRing
		if err := tx.Where("id = ?", u.ID).First(&UserRing).Error; err == nil {

			if err := tx.Model(&models.UserRing{}).
				Where("id = ?", u.ID).
				Updates(map[string]interface{}{
					//"user_id": util.GetHash(phrase, fmt.Sprintf("%d_user_id", userID)),
					"ring_id": util.GetHash(phrase, fmt.Sprintf("%d_ring_id", u.RingID)),
				}).Error; err != nil {
				tx.Rollback()
				return err
			}
		}
	}

	var tokens []models.Token
	if err := tx.Where("user_id = ?", userID).Find(&tokens).Error; err != nil {
		tx.Rollback()
		return err
	}
	for _, token := range tokens {
		newAccessToken := util.GetHash(phrase, fmt.Sprintf("%d_accessToken", token.ID))
		newRefreshToken := util.GetHash(phrase, fmt.Sprintf("%d_refreshToken", token.ID))
		newIDToken := util.GetHash(phrase, fmt.Sprintf("%d_idToken", token.ID))
		newData := util.GetHash(phrase, fmt.Sprintf("%d_data", token.ID))
		if err := tx.Model(&models.Token{}).
			Where("id = ?", token.ID).
			Updates(map[string]interface{}{
				"access_token":  newAccessToken,
				"refresh_token": newRefreshToken,
				"id_token":      newIDToken,
				"data":          newData,
			}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	newEmail := util.GetHash(phrase, fmt.Sprintf("%d_email", userID))
	newName := util.GetHash(phrase, fmt.Sprintf("%d_name", userID))
	newUserData := util.GetHash(phrase, fmt.Sprintf("%d_data", userID))

	encodedUserData, err := json.Marshal(newUserData)
	if err != nil {
		return err
	}

	if err := tx.Model(&models.UserAuth{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"email": newEmail,
			"name":  newName,
			"data":  string(encodedUserData),
		}).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
