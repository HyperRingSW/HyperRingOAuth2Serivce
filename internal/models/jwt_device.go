package models

type JwtDevice struct {
	ID         uint   `gorm:"primaryKey"`
	JWT        string `gorm:"index"`
	DeviceUUID string `gorm:"index"`
	Status     bool   `gorm:"index"`
}
