package models

type UserProfileGETResponse struct {
	UserId int            `json:"userId"`
	Name   string         `json:"name"`
	Email  string         `json:"email"`
	Rings  []RingResponse `json:"rings"`
}

type RingResponse struct {
	Id                string                    `json:"id"`
	Name              string                    `json:"name"`
	UserNamed         string                    `json:"userName"`
	Description       string                    `json:"description"`
	ImageURL          string                    `json:"imageUrl"`
	SiteURL           string                    `json:"siteUrl"`
	Services          []string                  `json:"services"`
	DeviceDescription DeviceDescriptionResponse `json:"deviceDescription"`
}

type DeviceDescriptionResponse struct {
	CIN         string            `json:"cin"`
	IIN         string            `json:"iin"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Batch       RingBatchResponse `json:"batch"`
}

type RingBatchResponse struct {
	BatchId    int    `json:"batchId"`
	IsUser     int64  `json:"isUser"`
	IsUserName string `json:"isUserName"`
}
