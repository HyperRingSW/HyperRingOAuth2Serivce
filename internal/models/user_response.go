package models

type UserProfileGETResponse struct {
	UserId uint   `json:"userId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Rings  []Ring `json:"rings"`
}
