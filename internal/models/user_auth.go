package models

import "time"

type UserAuth struct {
	ID        uint   `gorm:"primaryKey"` //UUID
	Email     string `gorm:"unique;not null"`
	Name      string
	Data      string `gorm:"type:json;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
