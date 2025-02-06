package models

type RingServiceType string

const (
	RingServiceTypeInstall    RingServiceType = "install"
	RingServiceTypeUninstall  RingServiceType = "uninstall"
	RingServiceTypeDelete     RingServiceType = "delete"
	RingServiceTypeActivate   RingServiceType = "activate"
	RingServiceTypeSuspend    RingServiceType = "suspend"
	RingServiceTypeUnsuspend  RingServiceType = "unsuspend"
	RingServiceTypeRetokenize RingServiceType = "retokenize"
)

type Ring struct {
	Id                string            `json:"id" gorm:"column:id;primaryKey"`
	Name              string            `json:"name"`
	UserNamed         string            `json:"user_named"`
	Description       string            `json:"description,omitempty"`
	ImageURL          string            `json:"image_url,omitempty"`
	SiteURL           string            `json:"site_url,omitempty"`
	Services          RingServiceType   `json:"services,omitempty"`
	DeviceDescription DeviceDescription `json:"device_description,omitempty" gorm:"foreignKey:RingID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// DeviceDescription
type DeviceDescription struct {
	ID          uint      `gorm:"primaryKey"`
	RingID      string    `gorm:"index"` // FK rings.id
	CIN         string    `json:"cin"`
	IIN         string    `json:"iin"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Batch       RingBatch `json:"batch" gorm:"foreignKey:DeviceDescriptionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	ImageURL    string    `json:"image_url,omitempty"`
	SiteURL     string    `json:"site_url,omitempty"`
}

// RingBatch
type RingBatch struct {
	ID                  uint   `gorm:"primaryKey"`
	DeviceDescriptionID uint   `gorm:"index"` // foreign key device_descriptions.ID
	BatchId             int    `json:"batch_id"`
	IsUser              int64  `json:"is_user"`
	IsUserName          string `json:"is_user_name"`
}
