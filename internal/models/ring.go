package models

import "encoding/json"

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
	Name              string            `json:"name,omitempty"`
	UserNamed         string            `json:"userNamed,omitempty"`
	Description       string            `json:"description,omitempty"`
	ImageURL          string            `json:"image_url,omitempty"`
	SiteURL           string            `json:"site_url,omitempty"`
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
	ImageURL    string    `json:"imageUrl,omitempty"`
	SiteURL     string    `json:"siteUrl,omitempty"`
}

// RingBatch
type RingBatch struct {
	ID                  uint   `gorm:"primaryKey"`
	DeviceDescriptionID uint   `gorm:"index"` // foreign key device_descriptions.ID
	BatchId             int    `json:"batchId"`
	IsUser              int64  `json:"isUser"`
	IsUserName          string `json:"isUserName"`
}

func (r *Ring) UnmarshalJSON(data []byte) error {
	type Alias Ring

	aux := &struct {
		Services []string `json:"services"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	for _, s := range aux.Services {
		if _, ok := ServiceMapping[s]; !ok {
			continue
		}
		r.Services = append(r.Services, RingService{
			Service: RingServiceType(s),
		})
	}

	return nil
}

var ServiceMapping = map[string]RingServiceType{
	"install":    RingServiceTypeInstall,
	"uninstall":  RingServiceTypeUninstall,
	"delete":     RingServiceTypeDelete,
	"activate":   RingServiceTypeActivate,
	"suspend":    RingServiceTypeSuspend,
	"unsuspend":  RingServiceTypeUnsuspend,
	"retokenize": RingServiceTypeRetokenize,
}
