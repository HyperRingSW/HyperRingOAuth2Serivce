package models

type UserProfileGETResponse struct {
	Name  string         `json:"name"`
	Email string         `json:"email"`
	Rings []RingResponse `json:"rings"`
}

type RingResponse struct {
	Id                string
	Name              string
	UserNamed         string
	Description       string
	ImageURL          string
	SiteURL           string
	Services          []string
	DeviceDescription DeviceDescriptionResponse
}

type DeviceDescriptionResponse struct {
	CIN         string
	IIN         string
	Name        string
	Description string
	Batch       RingBatchResponse
}

type RingBatchResponse struct {
	BatchId    int
	IsUser     int64
	IsUserName string
}
