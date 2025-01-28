package dependency

import (
	"net/http"
	"oauth2-server/internal/models"
)

type UserRepository interface {
	CreateOrUpdateUser(userAuth models.UserAuth) (*models.UserAuth, error)
	FindUserByEmail(email string) *models.UserAuth
	GetUserByID(userID uint) *models.UserAuth
	UpdateUser(userID uint, updates map[string]interface{}) error
	DeleteUser(userID uint) error
}

type TokenRepository interface {
	CreateOrUpdateToken(newToken models.Token) (*models.Token, error)
	CreateToken(token *models.Token) error
	InvalidateToken(accessToken string) error
	RefreshAccessToken(refreshToken string, needEncrypt bool) (*models.Token, error)
}

type Repository interface {
	UserRepository() UserRepository
	TokenRepository() TokenRepository
}

type AuthHandler interface {
	SignUpHandler(w http.ResponseWriter, r *http.Request)
	SignInHandler(w http.ResponseWriter, r *http.Request)
	RedirectHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request)
	RefreshTokenHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
}
type UserHandler interface {
	GetUserProfile(w http.ResponseWriter, r *http.Request)
	UpdateUserProfile(w http.ResponseWriter, r *http.Request)
	DeleteUserAccount(w http.ResponseWriter, r *http.Request)
	BackupUserData(w http.ResponseWriter, r *http.Request)
	RestoreUserData(w http.ResponseWriter, r *http.Request)
}

type Handler interface {
	AuthHandler() AuthHandler
	UserHandler() UserHandler
}
