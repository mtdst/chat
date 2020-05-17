package phone

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/api/session"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/models"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/database"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/server"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/sms"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/timeutil"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/validation"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/w3sqlutil"

	xerrors "github.com/x-foby/errors"
	"github.com/x-foby/w3sql/source"
	"github.com/x-foby/w3sql/webserver"
)

// ошибки
const (
	ErrFailedAuth = models.ErrModuleMePhone + iota + 1
	ErrFailedOpenDBConn
	ErrFailedReadJSON
	ErrFailedParseJSON
	ErrFailedQueryCompile
	ErrFailedQueryExec
	ErrFailedQueryScan
	ErrNoPhone
	ErrUserIsBanned
	ErrSMSIsBlocked
	ErrFailedSMSSending
	ErrBadPhone
)

// Config описывает структуру конфигурации модуля
type Config models.ModuleConfig

var cfg Config

type updPhoneData struct {
	Phone *int64  `json:"phone,omitempty"`
	Code  *string `json:"code,omitempty"`
}

type confirmation struct {
	Code    *string `db:"code"    json:"code,omitempty"`
	Timeout *int    `db:"timeout" json:"timeout,omitempty"`
}

func init() {
	module := webserver.NewSourceHandlers(&source.Source{}).Patch(update)

	server.Server().Route("me/phone", module)
}

// GetConfig возвращает указатель на структуру для заполнения настроек
func GetConfig() *Config {
	return &cfg
}

func update(ctx webserver.Context) (int, interface{}, error) {
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s == nil {
		return http.StatusForbidden, nil, xerrors.New("Вы не авторизованы").WithCode(ErrFailedAuth)
	}

	body, err := ioutil.ReadAll(ctx.R.Body)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedReadJSON)
	}

	var d updPhoneData
	if err := json.Unmarshal(body, &d); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedParseJSON)
	}

	if d.Phone == nil {
		return http.StatusBadRequest, nil, xerrors.New("Не передан номер телефона").WithCode(ErrNoPhone)
	}
	if !validation.Phone(d.Phone, false) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный номер телефона").WithCode(ErrBadPhone)
	}

	if d.Code == nil {
		return sendCode(ctx, s, d)
	}

	return change(ctx, s, d)
}

func sendCode(ctx webserver.Context, s *models.Session, d updPhoneData) (int, interface{}, error) {
	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_phone_change_code_ins_upd($1, $2)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	rows, err := db.QueryContext(ctx.R.Context(), q, s.UserID, d.Phone)
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
		return http.StatusForbidden, nil, xerrors.New("Вы не можете отправлять запросы на смену номера телефона ещё " + timeutil.ToString(time.Second*time.Duration(*c.Timeout))).WithCode(ErrSMSIsBlocked)
	}

	if _, err := sms.Send(uint64(*d.Phone), "APREL", "Код подтверждения: "+*c.Code, fmt.Sprintf("updphn%v", *d.Phone), 0); err != nil {
		if errors.Is(err, sms.ErrPublicError) {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedSMSSending)
		}
		return http.StatusInternalServerError, nil, xerrors.FromError(errors.Unwrap(err)).WithCode(ErrFailedSMSSending)
	}

	return http.StatusOK, confirmation{Timeout: c.Timeout}, nil
}

func change(ctx webserver.Context, s *models.Session, d updPhoneData) (int, interface{}, error) {
	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_phone_upd($1, $2, $3)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	rows, err := db.QueryContext(ctx.R.Context(), q, s.UserID, d.Phone, d.Code)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}
	defer rows.Close()

	var u models.User
	if rows.Next() {
		if err := w3sqlutil.ScanToStruct(&u, rows); err != nil {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryScan)
		}
	}

	return http.StatusOK, u, nil
}
