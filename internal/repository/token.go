package repository

import (
	"errors"
	"oauth2-server/internal/dependency"
	"oauth2-server/internal/models"
	"oauth2-server/internal/util"
	"time"
)

type tokenRepository struct {
	*PostgresDB
}

func (repo *PostgresDB) TokenRepository() dependency.TokenRepository {
	return &tokenRepository{PostgresDB: repo}
}

func (repo *PostgresDB) CreateOrUpdateToken(token models.Token) (*models.Token, error) {
	newToken := models.Token{
		ID:           token.ID,
		UserID:       token.UserID,
		Provider:     token.Provider,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpirationIn: token.ExpirationIn,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpirationIn) * time.Second),
		Data:         token.Data,
		UpdatedAt:    token.UpdatedAt,
	}

	result := repo.db.Where("user_id = ?", token.UserID).First(&newToken)
	if result.RowsAffected == 0 {
		token.UpdatedAt = time.Now()
		if err := repo.db.Create(&token).Error; err != nil {
			return nil, errors.New("error create token: " + err.Error())
		}
	} else {
		encryptedAccessToken, err := util.Encrypt(token.AccessToken)
		if err != nil {
			return nil, err
		}
		//token.AccessToken = encryptedAccessToken

		encryptedRefreshToken, err := util.Encrypt(token.RefreshToken)
		if err != nil {
			return nil, err
		}
		//token.RefreshToken = encryptedRefreshToken

		updates := map[string]interface{}{
			"access_token":  encryptedAccessToken,
			"refresh_token": encryptedRefreshToken,
			"expiration_in": token.ExpirationIn,
			"expires_at":    token.ExpiresAt,
			"updated_at":    token.UpdatedAt,
		}

		if err := repo.db.Model(&token).Where("user_id = ?", token.UserID).Updates(updates).Error; err != nil {
			return nil, errors.New("error update token: " + err.Error())
		}
	}

	return &token, nil
}

// CreateToken
func (repo *PostgresDB) CreateToken(token *models.Token) error {
	encryptedAccessToken, err := util.Encrypt(token.AccessToken)
	if err != nil {
		return err
	}
	token.AccessToken = encryptedAccessToken

	encryptedRefreshToken, err := util.Encrypt(token.RefreshToken)
	if err != nil {
		return err
	}
	token.RefreshToken = encryptedRefreshToken

	return repo.db.Create(&token).Error
}

// InvalidateToken
func (repo *PostgresDB) InvalidateToken(accessToken string) error {
	encryptedToken, err := util.Encrypt(accessToken)
	if err != nil {
		return err
	}
	return repo.db.Where("access_token = ?", encryptedToken).Delete(&models.Token{}).Error
}

// RefreshAccessToken set decrypted access and refresh tokens
func (repo *PostgresDB) RefreshAccessToken(refreshToken string, needEncrypt bool) (*models.Token, error) {
	if needEncrypt {
		encrypt, err := util.Encrypt(refreshToken)
		if err != nil {
			return nil, err
		}
		refreshToken = encrypt
	}

	var token models.Token
	result := repo.db.Where("refresh_token = ?", refreshToken).First(&token)
	if result.RowsAffected == 0 {
		return nil, nil
	}

	decryptAccess, err := util.Decrypt(token.AccessToken)
	if err != nil {
		return nil, err
	}
	token.AccessToken = decryptAccess

	decryptRefresh, err := util.Decrypt(token.RefreshToken)
	if err != nil {
		return nil, err
	}
	token.RefreshToken = decryptRefresh

	return &token, nil
}
