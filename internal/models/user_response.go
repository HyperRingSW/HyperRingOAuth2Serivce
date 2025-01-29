package models

type UserProfileGETResponse struct {
	UserId uint   `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}
