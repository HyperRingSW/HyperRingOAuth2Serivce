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
	UserToken(userId uint, provider string) *models.Token
	RefreshAccessToken(refreshToken string, needEncrypt bool) (*models.Token, error)
}

type RingRepository interface {
	SaveRing(ring *models.Ring) (*models.Ring, error)
	UpdateRingName(ringId string, userNamed string) error
	GetRing(id string) (*models.Ring, error)
	DeleteRing(ringId string) error
}

type UserRingRepository interface {
	SaveUserRing(ur *models.UserRing) error
	DeleteUserRing(userId uint, ringId string) error
	GetUserRing(userID uint) ([]models.UserRing, error)
	CheckUserRing(userID uint, ringId string) (*models.UserRing, error)
}

type Repository interface {
	UserRepository() UserRepository
	TokenRepository() TokenRepository
	RingRepository() RingRepository
	UserRingRepository() UserRingRepository
	//TxBegin(func()) (Repository, error)
}

type AuthHandler interface {
	AuthUserHandler(w http.ResponseWriter, r *http.Request, provider string)
	RefreshTokenHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
}
type UserHandler interface {
	GetUserProfile(w http.ResponseWriter, r *http.Request)
}

type RingHandler interface {
	AttachRingHandler(w http.ResponseWriter, r *http.Request)
	UpdateRingHandler(w http.ResponseWriter, r *http.Request)
	UnlinkRingHandler(w http.ResponseWriter, r *http.Request)
}

type Handler interface {
	AuthHandler() AuthHandler
	UserHandler() UserHandler
	RingHandler() RingHandler
}
