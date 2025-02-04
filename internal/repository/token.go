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

	encryptedAccessToken, err := util.Encrypt(token.AccessToken)
	if err != nil {
		return nil, err
	}
	token.AccessToken = encryptedAccessToken

	if token.RefreshToken != "" {
		encryptedRefreshToken, err := util.Encrypt(token.RefreshToken)
		if err != nil {
			return nil, err
		}
		token.RefreshToken = encryptedRefreshToken
	}

	if token.IDToken != "" {
		encryptedIDToken, err := util.Encrypt(token.IDToken)
		if err != nil {
			return nil, err
		}
		token.IDToken = encryptedIDToken
	}

	newToken := models.Token{
		ID:           token.ID,
		UserID:       token.UserID,
		Provider:     token.Provider,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpirationIn: token.ExpirationIn,
		IDToken:      token.IDToken,
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
		updates := map[string]interface{}{
			"access_token":  token.AccessToken,
			"refresh_token": token.RefreshToken,
			"expiration_in": token.ExpirationIn,
			"expires_at":    token.ExpiresAt,
			"id_token":      token.IDToken,
			"updated_at":    token.UpdatedAt,
			"data":          newToken.Data,
		}

		if err := repo.db.Model(&token).Where("user_id = ?", token.UserID).Updates(updates).Error; err != nil {
			return nil, errors.New("error update token: " + err.Error())
		}
	}

	return &token, nil
}

func (repo *PostgresDB) UpdateToken(token models.Token, provider string) (*models.Token, error) {
	//Шифруем токены
	encryptedAccessToken, err := util.Encrypt(token.AccessToken)
	if err != nil {
		return nil, err
	}
	token.AccessToken = encryptedAccessToken

	encryptedRefreshToken := ""
	if token.RefreshToken != "" {
		encryptedRefreshToken, err = util.Encrypt(token.RefreshToken)
		if err != nil {
			return nil, err
		}
		token.RefreshToken = encryptedRefreshToken
	}

	updates := map[string]interface{}{
		"access_token":  encryptedAccessToken,
		"refresh_token": token.RefreshToken,
		"expiration_in": token.ExpirationIn,
		"expires_at":    token.ExpiresAt,
		"updated_at":    token.UpdatedAt,
		"data":          token.Data,
	}

	if provider == models.PROVIDER_GOOGLE || provider == models.PROVIDER_FB {
		delete(updates, "refresh_token")
	}

	if err := repo.db.Model(&token).Where("user_id = ?", token.UserID).Updates(updates).Error; err != nil {
		return nil, errors.New("error update token: " + err.Error())
	}

	return &token, nil
}

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

func (repo *PostgresDB) InvalidateToken(accessToken string) error {
	return repo.db.Where("access_token = ?", accessToken).Delete(&models.Token{}).Error
}

func (repo *PostgresDB) UserToken(userId uint) *models.Token {
	token := &models.Token{}

	result := repo.db.Where("user_id = ?", userId).First(&token)
	if result.RowsAffected != 0 {
		return token
	}

	return nil
}

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

	return &token, nil
}
