package password

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mtdst/chat/api/session"
	"github.com/mtdst/chat/internal/models"
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
	ErrFailedOpenDBConn = models.ErrModuleMePassword + iota + 1
	ErrFailedReadJSON
	ErrFailedParseJSON
	ErrFailedQueryCompile
	ErrFailedQueryExec
	ErrFailedQueryScan
	ErrNoPassword
	ErrNoCode
	ErrNoPhone
	ErrUserIsBanned
	ErrSMSIsBlocked
	ErrFailedSMSSending
	ErrBadPhone
	ErrBadPassword
	ErrFailedAuth
)

// Config описывает структуру конфигурации модуля
type Config models.ModuleConfig

var cfg Config

type updPasswordData struct {
	Phone       *int64  `json:"phone,omitempty"`
	Code        *string `json:"code,omitempty"`
	Password    *string `json:"password,omitempty"`
	NewPassword *string `json:"newPassword,omitempty"`
}

type confirmation struct {
	Code    *string `db:"code"    json:"code,omitempty"`
	Timeout *int    `db:"timeout" json:"timeout,omitempty"`
}

func init() {
	module := webserver.NewSourceHandlers(&source.Source{}).Patch(update)

	server.Server().Route("me/password", module)
}

// GetConfig возвращает указатель на структуру для заполнения настроек
func GetConfig() *Config {
	return &cfg
}

func update(ctx webserver.Context) (int, interface{}, error) {
	body, err := ioutil.ReadAll(ctx.R.Body)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedReadJSON)
	}

	var d updPasswordData
	if err := json.Unmarshal(body, &d); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedParseJSON)
	}

	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s != nil {
		return change(ctx, d, s)
	}

	switch {
	case d.Code == nil && d.Password == nil:
		return sendCode(ctx, d)
	case d.Code != nil && d.Password != nil:
		return recovery(ctx, d)
	case d.Password == nil:
		return http.StatusBadRequest, nil, xerrors.New("Не передан новый пароль").WithCode(ErrNoPassword)

	default:
		return http.StatusBadRequest, nil, xerrors.New("Не передан код подтверждения").WithCode(ErrNoCode)
	}
}

func sendCode(ctx webserver.Context, d updPasswordData) (int, interface{}, error) {
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s != nil {
		return http.StatusForbidden, nil, xerrors.New("Вы уже авторизованы").WithCode(ErrFailedAuth)
	}

	if d.Phone == nil {
		return http.StatusBadRequest, nil, xerrors.New("Не передан номер телефона").WithCode(ErrNoPhone)
	}
	if !validation.Phone(d.Phone, false) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный номер телефона").WithCode(ErrBadPhone)
	}

	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_password_recovery_code_ins_upd($1)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	rows, err := db.QueryContext(ctx.R.Context(), q, d.Phone)
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
		return http.StatusForbidden, nil, xerrors.New("Вы не можете отправлять запросы на восстановление пароля ещё " + timeutil.ToString(time.Second*time.Duration(*c.Timeout))).WithCode(ErrSMSIsBlocked)
	}

	if _, err := sms.Send(uint64(*d.Phone), "APREL", "Код подтверждения: "+*c.Code, fmt.Sprintf("updpswd%v", *d.Phone), 0); err != nil {
		if errors.Is(err, sms.ErrPublicError) {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedSMSSending)
		}
		return http.StatusInternalServerError, nil, xerrors.FromError(errors.Unwrap(err)).WithCode(ErrFailedSMSSending)
	}

	return http.StatusOK, confirmation{Timeout: c.Timeout}, nil
}

func recovery(ctx webserver.Context, d updPasswordData) (int, interface{}, error) {
	if !validation.Password(d.Password) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный новый пароль").WithCode(ErrBadPassword)
	}
	if !validation.Phone(d.Phone, false) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный номер телефона").WithCode(ErrBadPhone)
	}

	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_password_recovery($1, $2, $3)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	_, err = db.ExecContext(ctx.R.Context(), q, d.Phone, d.Code, d.Password)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	return http.StatusOK, nil, nil
}

func change(ctx webserver.Context, d updPasswordData, s *models.Session) (int, interface{}, error) {
	if d.NewPassword == nil {
		return http.StatusBadRequest, nil, xerrors.New("Не передан новый пароль").WithCode(ErrNoPassword)
	}
	if !validation.Password(d.NewPassword) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный новый пароль").WithCode(ErrBadPassword)
	}

	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_password_upd($1, $2, $3)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	_, err = db.ExecContext(ctx.R.Context(), q, s.UserID, d.Password, d.NewPassword)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	return http.StatusOK, nil, nil
}
