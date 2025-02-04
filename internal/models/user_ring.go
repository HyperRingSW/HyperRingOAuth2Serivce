package models

type UserRing struct {
	ID     uint   `gorm:"primaryKey"`
	RingID string `gorm:"index"`
	UserID uint   `gorm:"index"`
}
