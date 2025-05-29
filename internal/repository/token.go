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
	return &tokenRepository{
		PostgresDB: repo,
	}
}

func (repo *PostgresDB) CreateOrUpdateToken(token models.Token) (*models.Token, error) {
	encryptedAccessToken := ""
	if token.AccessToken != "" {
		enc, err := util.Encrypt(token.AccessToken)
		if err != nil {
			return nil, err
		}
		token.AccessToken = enc
		encryptedAccessToken = enc
	}
	encryptedRefreshToken := ""
	if token.RefreshToken != "" {
		enc, err := util.Encrypt(token.RefreshToken)
		if err != nil {
			return nil, err
		}
		token.RefreshToken = enc
		encryptedRefreshToken = enc
	}

	encryptedIDToken := ""
	if token.IDToken != "" {
		enc, err := util.Encrypt(token.IDToken)
		if err != nil {
			return nil, err
		}
		token.IDToken = enc
		encryptedIDToken = enc
	}

	encryptedData := ""
	if token.Data != "" {
		enc, err := util.Encrypt(token.Data)
		if err != nil {
			return nil, err
		}
		token.Data = enc
		encryptedData = enc
	}

	newToken := models.Token{
		ID:           token.ID,
		UserID:       token.UserID,
		Provider:     token.Provider,
		DeviceUUID:   token.DeviceUUID,
		AccessToken:  encryptedAccessToken,
		RefreshToken: encryptedRefreshToken,
		ExpirationIn: token.ExpirationIn,
		IDToken:      encryptedIDToken,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpirationIn) * time.Second),
		Data:         encryptedData,
		UpdatedAt:    token.UpdatedAt,
	}

	//result := repo.db.Where("user_id = ? AND device_uuid = ?", token.UserID, token.DeviceUUID).First(&newToken)
	result := repo.db.Where("id_token = ?", encryptedIDToken).First(&newToken)
	if result.RowsAffected == 0 {
		token.UpdatedAt = time.Now()
		if err := repo.db.Create(&token).Error; err != nil {
			return nil, errors.New("error create token: " + err.Error())
		}
	} else {
		updates := map[string]interface{}{
			"access_token":  encryptedAccessToken,
			"refresh_token": encryptedRefreshToken,
			"expiration_in": token.ExpirationIn,
			"expires_at":    token.ExpiresAt,
			"id_token":      encryptedIDToken,
			"updated_at":    token.UpdatedAt,
			"data":          encryptedData,
		}

		if err := repo.db.Model(&token).Where("id_token = ?", encryptedIDToken).Updates(updates).Error; err != nil {
			return nil, errors.New("error update token: " + err.Error())
		}
	}

	return &token, nil
}

func (repo *PostgresDB) UpdateToken(token models.Token, provider string, deviceUUID string) (*models.Token, error) {
	encryptedAccessToken := ""
	if token.AccessToken != "" {
		enc, err := util.Encrypt(token.AccessToken)
		if err != nil {
			return nil, err
		}
		encryptedAccessToken = enc
	}

	encryptedRefreshToken := ""
	if token.RefreshToken != "" {
		enc, err := util.Encrypt(token.RefreshToken)
		if err != nil {
			return nil, err
		}
		encryptedRefreshToken = enc
	}

	encryptedData := ""
	if token.Data != "" {
		enc, err := util.Encrypt(token.Data)
		if err != nil {
			return nil, err
		}
		encryptedData = enc
	}
	encryptedIDToken := ""
	if token.IDToken != "" {
		enc, err := util.Encrypt(token.IDToken)
		if err != nil {
			return nil, err
		}
		encryptedIDToken = enc

	}

	updates := map[string]interface{}{
		"access_token":  encryptedAccessToken,
		"refresh_token": encryptedRefreshToken,
		"expiration_in": token.ExpirationIn,
		"expires_at":    token.ExpiresAt,
		"updated_at":    token.UpdatedAt,
		"data":          encryptedData,
	}

	if provider == models.PROVIDER_GOOGLE || provider == models.PROVIDER_FB {
		delete(updates, "refresh_token")
	}

	if err := repo.db.Model(&token).Where("id_token = ?", encryptedIDToken).Updates(updates).Error; err != nil {
		return nil, errors.New("error update token: " + err.Error())
	}

	return &token, nil
}

func (repo *PostgresDB) InvalidateAccessToken(accessToken string) error {

	return repo.db.Where("access_token = ?", accessToken).Delete(&models.Token{}).Error
}

func (repo *PostgresDB) InvalidateIdToken(idToken string) error {
	return repo.db.Where("id_token = ?", idToken).Delete(&models.Token{}).Error
}

func (repo *PostgresDB) UserToken(userId uint, provider string, deviceUUID string) *models.Token {
	token := &models.Token{}

	result := repo.db.Where("user_id = ? and provider = ? and device_uuid = ?", userId, provider, deviceUUID).First(&token)
	//result := repo.db.Where("id_token = ? ", idToken).First(&token)
	if result.RowsAffected != 0 {
		return token
	}

	return nil
}

func (repo *PostgresDB) UserTokens(userId uint) ([]models.Token, error) {
	var token []models.Token

	if err := repo.db.Where("user_id = ?", userId).Find(&token).Error; err != nil {
		return token, err
	}

	return token, nil
}
