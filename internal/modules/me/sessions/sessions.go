package sessions

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mtdst/chat/api/session"
	"github.com/mtdst/chat/internal/models"
	"github.com/mtdst/chat/internal/modules/users"
	"github.com/mtdst/chat/pkg/database"
	"github.com/mtdst/chat/pkg/server"
	"github.com/mtdst/chat/pkg/sms"
	"github.com/mtdst/chat/pkg/timeutil"
	"github.com/mtdst/chat/pkg/validation"
	"github.com/mtdst/chat/pkg/w3sqlutil"

	xerrors "github.com/x-foby/errors"
	"github.com/x-foby/w3sql/source"
	"github.com/x-foby/w3sql/webserver"
)

// ошибки
const (
	ErrFailedAuth = models.ErrModuleMeSessions + iota + 1
	ErrAlreadyAuth
	ErrFailedOpenDBConn
	ErrFailedReadJSON
	ErrFailedParseJSON
	ErrFailedQueryExec
	ErrFailedQueryCompile
	ErrFailedQueryScan
	ErrNoPhone
	ErrUserIsBanned
	ErrSMSIsBlocked
	ErrFailedSMSSending
	ErrNoPassword
	ErrFailedOpenMeDBConn
	ErrFailedQueryMeExec
	ErrBadPhone
	ErrFailedGetMobileContext
	ErrFailedPasswordGenerating
	ErrFailedUserCreating
)

type confirmation struct {
	Code    *string `db:"code"    json:"code,omitempty"`
	Timeout *int    `db:"timeout" json:"timeout,omitempty"`
}

type loginRequest struct {
	Phone    *int64  `json:"phone,omitempty"`
	Password *string `json:"password,omitempty"`
	Code     *string `json:"code,omitempty"`
}

type response struct {
	Token *string `json:"token"`
}

// Config описывает структуру конфигурации модуля
type Config models.ModuleConfig

var cfg Config

func init() {
	module := webserver.NewSourceHandlers(&source.Source{}).
		Post(create).
		Put(update).
		Delete(delete)

	server.Server().Route("me/sessions", module)
}

// GetConfig возвращает указатель на структуру для заполнения настроек
func GetConfig() *Config {
	return &cfg
}

func create(ctx webserver.Context) (int, interface{}, error) {
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s != nil {
		return http.StatusForbidden, nil, xerrors.New("Вы уже авторизованы").WithCode(ErrAlreadyAuth)
	}

	body, err := ioutil.ReadAll(ctx.R.Body)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedReadJSON)
	}

	var req loginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedParseJSON)
	}

	if req.Phone == nil {
		return http.StatusBadRequest, nil, xerrors.FromError(err).WithCode(ErrNoPhone)
	}
	if !validation.Phone(req.Phone, false) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный номер телефона").WithCode(ErrBadPhone)
	}

	isMobile, ok := ctx.R.Context().Value(models.ContextIsMobile).(bool)
	if !ok {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedGetMobileContext)
	}

	if req.Password != nil && !isMobile {
		return createByPassword(ctx, req)
	}

	return createByCode(ctx, req)
}

func createByPassword(ctx webserver.Context, req loginRequest) (int, interface{}, error) {
	db, err := database.Open(cfg.DB.Create)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	var s models.Session
	if err := db.QueryRowContext(
		ctx.R.Context(),
		`select
			s.session,
			s.csrf_token,
			s.user_id,
			s.user_phone,
			s.expire_time
		from fn_session_by_password_ins($1, $2) s`,
		req.Phone,
		req.Password,
	).Scan(&s.Session, &s.CSRFToken, &s.UserID, &s.UserPhone, &s.ExpireTime); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	setSessionCookie(ctx.W, s.Session, s.ExpireTime)

	return http.StatusOK, response{Token: &s.CSRFToken}, nil
}

func createByCode(ctx webserver.Context, req loginRequest) (int, interface{}, error) {
	if isMobile, ok := ctx.R.Context().Value(models.ContextIsMobile).(bool); !ok || !isMobile {
		return http.StatusInternalServerError, nil, xerrors.New("Не передан идентификатор сессии").WithCode(ErrNoPassword)
	}

	dbMe, err := database.Open(cfg.DB.Read)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenMeDBConn)
	}

	var isExists bool
	if err := dbMe.QueryRowContext(ctx.R.Context(), `select true from v_user u where u.phone = $1 limit 1`, req.Phone).Scan(&isExists); err != nil && err != sql.ErrNoRows {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryMeExec)
	}

	if !isExists {
		var password string
		if err := dbMe.QueryRowContext(ctx.R.Context(), "select z_generate_password()").Scan(&password); err != nil {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedPasswordGenerating)
		}
		if _, err := users.CreateUser(ctx.R.Context(), req.Phone, &password, nil, nil, nil, nil, nil); err != nil {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedUserCreating)
		}
	}

	if req.Code == nil {
		return sendCode(ctx, req)
	}

	db, err := database.Open(cfg.DB.Create)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	var s models.Session
	if err := db.QueryRowContext(
		ctx.R.Context(),
		`select
			s.session,
			s.csrf_token,
			s.user_id,
			s.user_phone,
			s.expire_time
		from fn_session_by_code_ins($1, $2) s`,
		req.Phone,
		req.Code,
	).Scan(&s.Session, &s.CSRFToken, &s.UserID, &s.UserPhone, &s.ExpireTime); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	setSessionCookie(ctx.W, s.Session, s.ExpireTime)

	return http.StatusOK, response{Token: &s.CSRFToken}, nil
}

func update(ctx webserver.Context) (int, interface{}, error) {
	sid, err := ctx.R.Cookie("session")
	if err != nil {
		return http.StatusForbidden, nil, xerrors.New("Не передан идентификатор сессии").WithCode(ErrFailedAuth)
	}
	if sid.Value == "" {
		return http.StatusForbidden, nil, xerrors.New("Некорректный идентификатор сессии").WithCode(ErrFailedAuth)
	}

	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	var s models.Session
	if err := db.QueryRowContext(
		ctx.R.Context(),
		`select
			s.session,
			s.csrf_token,
			s.user_id,
			s.user_phone,
			s.expire_time
		from fn_session_upd($1) s`,
		sid.Value,
	).Scan(&s.Session, &s.CSRFToken, &s.UserID, &s.UserPhone, &s.ExpireTime); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	setSessionCookie(ctx.W, s.Session, s.ExpireTime)

	return http.StatusOK, response{Token: &s.CSRFToken}, nil
}

func delete(ctx webserver.Context) (int, interface{}, error) {
	// Получаем информацию о сессии. Если её нет, то отказываем пользователю в получении информации
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s == nil {
		return http.StatusForbidden, nil, xerrors.New("Вы не авторизованы").WithCode(ErrFailedAuth)
	}

	db, err := database.Open(cfg.DB.Delete)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	if _, err := db.ExecContext(ctx.R.Context(), "select fn_session_del($1, $2)", s.Session, s.CSRFToken); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	setSessionCookie(ctx.W, "", time.Unix(0, 0))

	return http.StatusOK, nil, nil
}

func sendCode(ctx webserver.Context, req loginRequest) (int, interface{}, error) {
	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_auth_confirm_code_ins_upd($1)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	rows, err := db.QueryContext(ctx.R.Context(), q, req.Phone)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}
	defer rows.Close()

	var c confirmation
	if rows.Next() {
		if err := w3sqlutil.ScanToStruct(&c, rows); err != nil {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryScan)
		}
	}

	if c.Code == nil && c.Timeout == nil {
		return http.StatusForbidden, nil, xerrors.New("Пользователь заблокирован").WithCode(ErrUserIsBanned)
	}

	if c.Code == nil && *c.Timeout > 0 {
		return http.StatusForbidden, nil, xerrors.New("Вы не можете отправлять запросы на авторизацию ещё " + timeutil.ToString(time.Second*time.Duration(*c.Timeout))).WithCode(ErrSMSIsBlocked)
	}

	if _, err := sms.Send(uint64(*req.Phone), "APREL", "Код подтверждения: "+*c.Code, fmt.Sprintf("auth%v", *req.Phone), 0); err != nil {
		if errors.Is(err, sms.ErrPublicError) {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedSMSSending)
		}
		return http.StatusInternalServerError, nil, xerrors.FromError(errors.Unwrap(err)).WithCode(ErrFailedSMSSending)
	}

	return http.StatusOK, confirmation{Timeout: c.Timeout}, nil
}

func setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	c := http.Cookie{
		HttpOnly: true,
		Name:     "session",
		Path:     "/",
		Secure:   true,
		Value:    value,
		Expires:  expires,
		SameSite: http.SameSiteNoneMode,
	}

	http.SetCookie(w, &c)
}
