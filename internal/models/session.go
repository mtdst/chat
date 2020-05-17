package models

import "time"

// Session описывает структуру пользовательской сессии
type Session struct {
	UserID     int
	IPAdress   string
	Session    string
	UserAgent  string
	CSRFToken  string
	CreateTime time.Time
	ExpireTime time.Time
}
