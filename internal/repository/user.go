package repository

import (
	"errors"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
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
	result := repo.db.Where("email = ?", userAuth.Email).First(&userAuth)
	if result.RowsAffected == 0 {
		if err := repo.db.Create(&userAuth).Error; err != nil {
			err = errors.New("create user auth failed: " + err.Error())
			return nil, err
		}
	} else {
		updates := map[string]interface{}{
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
	return &user
}

// UpdateUser
func (repo *PostgresDB) UpdateUser(userID uint, updates map[string]interface{}) error {
	return repo.db.Model(&models.UserAuth{}).Where("id = ?", userID).Updates(updates).Error
}

// DeleteUser
func (repo *PostgresDB) DeleteUser(userID uint) error {
	return repo.db.Delete(&models.UserAuth{}, userID).Error
}
