package models

type UserProfileGETResponse struct {
	UserId int            `json:"userId"`
	Name   string         `json:"name"`
	Email  string         `json:"email"`
	Rings  []RingResponse `json:"rings"`
	Demo   bool           `json:"demo"`
}

type UserDataExportResponse struct {
	UserId int                           `json:"userId"`
	Name   string                        `json:"name"`
	Email  string                        `json:"email"`
	Rings  []RingResponse                `json:"rings"`
	Tokens []UserDataExportTokenResponse `json:"tokens"`
}

type UserDataExportTokenResponse struct {
	Provider     string `json:"provider"`
	IdToken      string `json:"idToken"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpirationIn int    `json:"expirationIn"`
	ExpiresAt    int64  `json:"expiresAt"`
	Data         string `json:"data"`
	UpdatedAt    int64  `json:"updatedAt"`
}

type RingResponse struct {
	Id                string                    `json:"id"`
	Name              string                    `json:"name"`
	UserNamed         string                    `json:"userName"`
	Description       string                    `json:"description"`
	Services          []string                  `json:"services"`
	DeviceDescription DeviceDescriptionResponse `json:"deviceDescription"`
}

type DeviceDescriptionResponse struct {
	CIN         string            `json:"cin"`
	IIN         string            `json:"iin"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Batch       RingBatchResponse `json:"batch"`
	ImageURL    string            `json:"imageUrl"`
	SiteURL     string            `json:"siteUrl"`
}

type RingBatchResponse struct {
	BatchId    int    `json:"batchId"`
	IsUser     int64  `json:"isUser"`
	IsUserName string `json:"isUserName"`
}
