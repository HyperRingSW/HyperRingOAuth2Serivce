package models

import (
	"time"
)

type Token struct {
	ID           uint      `gorm:"primaryKey"` //UUID
	UserID       uint      `gorm:"not null"`
	Provider     string    `gorm:"not null"`
	AccessToken  string    `gorm:"not null"`
	RefreshToken string    `gorm:"null"`
	ExpirationIn int       `gorm:"not null"`
	ExpiresAt    time.Time `gorm:"not null"`
	Data         string    `gorm:"type:json;not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}
