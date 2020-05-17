package session

import (
	"database/sql"
	"net/http"

	"github.com/mtdst/chat/internal/models"
	"github.com/mtdst/chat/pkg/database"

	"github.com/x-foby/errors"
)

// ошибки
const (
	ErrFailedOpenDBConn = models.ErrModuleSession + iota + 1
	ErrFailedQueryScan
)

// Get возвращает сессию привязанную к идентификатору в Cookies и переданному CSRF-токену
func Get(r *http.Request) (*models.Session, error) {
	sessionID, err := r.Cookie("session")
	if err != nil || sessionID.Value == "" {
		return nil, nil
	}
	CSRFToken := r.Header.Get("X-Token")
	if CSRFToken == "" {
		return nil, nil
	}

	db, err := database.Open("")
	if err != nil {
		return nil, errors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}
	var s models.Session
	if err := db.QueryRow(
		`select
			s.session,
			s.csrf_token,
			s.user_id,
			s.user_phone,
			s.user_email,
			s.user_name,
			s.expire_time
		from v_session s
		where
			s.session = $1 and
			s.csrf_token = $2`,
		sessionID.Value,
		CSRFToken,
	).Scan(&s.Session, &s.CSRFToken, &s.UserID, &s.UserPhone, &s.UserEmail, &s.UserName, &s.ExpireTime); err != nil && err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, errors.FromError(err).WithCode(ErrFailedQueryScan)
	}
	return &s, nil
}
