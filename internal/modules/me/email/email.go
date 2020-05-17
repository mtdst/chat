package email

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/mtdst/chat/api/session"
	"github.com/mtdst/chat/internal/models"
	"github.com/mtdst/chat/pkg/database"
	"github.com/mtdst/chat/pkg/mail"
	"github.com/mtdst/chat/pkg/server"
	"github.com/mtdst/chat/pkg/transaction"
	"github.com/mtdst/chat/pkg/validation"
	"github.com/mtdst/chat/pkg/w3sqlutil"

	xerrors "github.com/x-foby/errors"
	"github.com/x-foby/w3sql/source"
	"github.com/x-foby/w3sql/webserver"
)

// ошибки
const (
	ErrFailedAuth = models.ErrModuleMeEmail + iota + 1
	ErrFailedOpenDBConn
	ErrFailedReadJSON
	ErrFailedParseJSON
	ErrFailedQueryCompile
	ErrFailedQueryExec
	ErrFailedQueryScan
	ErrNoEmail
	ErrFailedSendMessage
	ErrBadEmail
	ErrFailedStartTx
)

// Config описывает структуру конфигурации модуля
type Config struct {
	models.ModuleConfig
	mail.Email
}

var cfg Config

type updEmailData struct {
	Email *string `json:"email,omitempty"`
}

type confirmation struct {
	Code    *string `db:"code"    json:"code,omitempty"`
	Timeout *int    `db:"timeout" json:"timeout,omitempty"`
}

func init() {
	module := webserver.NewSourceHandlers(&source.Source{Cols: source.NewCols(
		source.NewCol(source.TypeString, "code", "code", false),
	)}).Patch(update)

	server.Server().Route("me/email", module)
}

// GetConfig возвращает указатель на структуру для заполнения настроек
func GetConfig() *Config {
	return &cfg
}

func update(ctx webserver.Context) (int, interface{}, error) {
	code, err := w3sqlutil.GetByName(&ctx, "code")
	if err == nil {
		return confirm(ctx, code)
	}

	body, err := ioutil.ReadAll(ctx.R.Body)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedReadJSON)
	}

	var d updEmailData
	if err := json.Unmarshal(body, &d); err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedParseJSON)
	}

	if d.Email == nil {
		return http.StatusBadRequest, nil, xerrors.New("Не передан email").WithCode(ErrNoEmail)
	}
	if !validation.Email(d.Email, false) {
		return http.StatusBadRequest, nil, xerrors.New("Указан некорректный email").WithCode(ErrBadEmail)
	}

	return change(ctx, d.Email)
}

func confirm(ctx webserver.Context, code string) (int, interface{}, error) {
	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	q, err := ctx.Query.Compile(`fn_email_upd($1)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	rows, err := db.QueryContext(ctx.R.Context(), q, code)
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

func change(ctx webserver.Context, addr *string) (int, interface{}, error) {
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s == nil {
		return http.StatusForbidden, nil, xerrors.New("Вы не авторизованы").WithCode(ErrFailedAuth)
	}

	db, err := database.Open(cfg.DB.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedOpenDBConn)
	}

	tx, err := db.Begin()
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedStartTx)
	}
	defer func() { transaction.CompleteTx(tx, err) }()

	q, err := ctx.Query.Compile(`fn_email_code_ins_upd($1, $2)`)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	rows, err := tx.QueryContext(ctx.R.Context(), q, s.UserID, *addr)
	if err != nil {
		return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
	}
	defer rows.Close()

	var code *string
	if rows.Next() {
		if err = rows.Scan(&code); err != nil {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedQueryScan)
		}
	}

	email := cfg.Email
	email.Recipient = addr
	if err = mail.SendHTML(email, map[string]*string{"Code": code, "Address": addr}); err != nil {
		if errors.Is(err, mail.ErrPrivate) {
			return http.StatusInternalServerError, nil, xerrors.FromError(err).WithCode(ErrFailedSendMessage)
		}
		return http.StatusInternalServerError, nil, xerrors.FromError(errors.Unwrap(err)).WithCode(ErrFailedSendMessage)
	}

	return http.StatusOK, nil, nil
}
