package models

import (
	"time"
)

const DefaultUUID = "00000000-00000000-00000000-00000000"

type Token struct {
	ID           uint      `gorm:"primaryKey"` //UUID
	UserID       uint      `gorm:"not null"`
	Provider     string    `gorm:"not null"`
	DeviceUUID   string    `gorm:"default:'00000000-00000000-00000000-00000000'"`
	AccessToken  string    `gorm:"not null"`
	RefreshToken string    `gorm:"null"`
	IDToken      string    `gorm:"null"`
	ExpirationIn int       `gorm:"not null"`
	ExpiresAt    time.Time `gorm:"not null"`
	Data         string    `gorm:"not null"` //type:json;
	UpdatedAt    time.Time `gorm:"not null"`
}
