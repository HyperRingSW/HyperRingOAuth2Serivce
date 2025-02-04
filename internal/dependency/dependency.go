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
	UpdateToken(token models.Token, provider string) (*models.Token, error)
	CreateToken(token *models.Token) error
	InvalidateToken(accessToken string) error
	UserToken(userId uint) *models.Token
	RefreshAccessToken(refreshToken string, needEncrypt bool) (*models.Token, error)
}

type RingRepository interface {
	SaveRing(ring *models.Ring) (*models.Ring, error)
}

type UserRingRepository interface {
	SaveUserRing(ur *models.UserRing) error
	DeleteUserRing(ur *models.UserRing) error
	GetUserRing(userID uint) ([]models.UserRing, error)
}

type Repository interface {
	UserRepository() UserRepository
	TokenRepository() TokenRepository
	RingRepository() RingRepository
	UserRingRepository() UserRingRepository
}

type AuthHandler interface {
	AuthUserHandler(w http.ResponseWriter, r *http.Request)
	RefreshTokenHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
}
type UserHandler interface {
	GetUserProfile(w http.ResponseWriter, r *http.Request)
	UpdateUserProfile(w http.ResponseWriter, r *http.Request)
}

type RingHandler interface {
	CreateRingHandler(w http.ResponseWriter, r *http.Request)
	AttachRingHandler(w http.ResponseWriter, r *http.Request)
	UnlinkRingHandler(w http.ResponseWriter, r *http.Request)
}

type Handler interface {
	AuthHandler() AuthHandler
	UserHandler() UserHandler
	RingHandler() RingHandler
}
