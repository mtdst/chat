package models

import (
	"time"
)

// User описывает структуру пользователя
type User struct {
	ID               *int       `db:"id"                 json:"ID,omitempty"`
	Name             *string    `db:"name"               json:"name,omitempty"`
	Email            *string    `db:"email"              json:"email,omitempty"`
	Phone            *int64     `db:"phone"              json:"phone,omitempty"`
	IsEmailConfirmed *bool      `db:"is_email_confirmed" json:"isEmailConfirmed,omitempty"`
	Birthday         *time.Time `db:"birthday"           json:"birthday,omitempty"`
	Avatar           *string    `db:"avatar"             json:"avatar,omitempty"`
	Gender           *string    `db:"gender"             json:"gender,omitempty"`
	CityID           *int       `db:"city_id"            json:"cityID,omitempty"`
	TypeID           *int       `db:"type_id"            json:"typeID,omitempty"`
	Active           *bool      `db:"active"             json:"active,omitempty"`
}
