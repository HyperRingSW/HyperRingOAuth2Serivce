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
	Id          string `json:"id" gorm:"column:id;primaryKey"`
	Name        string `json:"name,omitempty"`
	UserNamed   string `json:"userNamed,omitempty"`
	Description string `json:"description,omitempty"`
	ImageURL    string `json:"imageUrl,omitempty"`
	SiteURL     string `json:"siteUrl,omitempty"`
	// Указываем связь с новой таблицей ring_services
	Services          []RingService     `json:"services,omitempty" gorm:"foreignKey:RingID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	DeviceDescription DeviceDescription `json:"deviceDescription,omitempty" gorm:"foreignKey:RingID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type RingService struct {
	ID      int             `gorm:"primaryKey" json:"id"`
	RingID  string          `json:"ringId"` // FK rings.id
	Service RingServiceType `json:"service"`
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
}

// RingBatch
type RingBatch struct {
	ID                  uint   `gorm:"primaryKey"`
	DeviceDescriptionID uint   `gorm:"index"` // foreign key device_descriptions.ID
	BatchId             int    `json:"batchId"`
	IsUser              int64  `json:"isUser"`
	IsUserName          string `json:"isUserName"`
}
