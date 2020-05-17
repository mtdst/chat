package users

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mtdst/chat/api/session"
	"github.com/mtdst/chat/internal/models"
	"github.com/mtdst/chat/pkg/database"
	"github.com/mtdst/chat/pkg/errorutil"
	"github.com/mtdst/chat/pkg/server"
	"github.com/mtdst/chat/pkg/validation"
	"github.com/mtdst/chat/pkg/w3sqlutil"

	xerrors "github.com/x-foby/errors"
	"github.com/x-foby/go-short/log"
	"github.com/x-foby/w3sql/source"
	"github.com/x-foby/w3sql/webserver"
)

type newUser struct {
	models.User
	Password *string `json:"password,omitempty"`
}

// ошибки
const (
	ErrAlreadyAuth = models.ErrModuleUsers + iota + 1
	ErrFailedQueryExec
)

// Общие ошибки методов остатков товаров
const (
	ErrCreate = "Не удалось создать пользователя"
)

// Config описывает структуру конфигурации модуля
type Config models.ModuleConfig

var cfg Config

func init() {
	module := webserver.NewSourceHandlers(&source.Source{Cols: source.NewCols(
		source.NewCol(source.TypeNumber, "ID", "id", false),
		source.NewCol(source.TypeNumber, "phone", "phone", false),
		source.NewCol(source.TypeString, "name", "name", false),
		source.NewCol(source.TypeString, "sname", "sname", false),
		source.NewCol(source.TypeString, "pname", "pname", false),
		source.NewCol(source.TypeString, "email", "email", false),
		source.NewCol(source.TypeBool, "isEmailConfirmed", "is_email_confirmed", false),
		source.NewCol(source.TypeTime, "birthday", "birthday", false),
		source.NewCol(source.TypeString, "avatar", "avatar", false),
		source.NewCol(source.TypeObject, "loyalCard", "loyal_card", false).WithChildren(source.NewCols(
			source.NewCol(source.TypeNumber, "barcode", "barcode", false),
			source.NewCol(source.TypeNumber, "periodID", "periodID", false),
			source.NewCol(source.TypeTime, "periodBlockDate", "periodBlockDate", false),
			source.NewCol(source.TypeNumber, "balance", "balance", false),
			source.NewCol(source.TypeNumber, "saved", "saved", false),
		)),
	)}).Post(create)

	server.Server().Route("users", module)
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
		log.Print(log.WARNING, err)
		return http.StatusInternalServerError, nil, errors.New(ErrCreate)
	}
	var nu newUser
	if err := json.Unmarshal(body, &nu); err != nil {
		log.Print(log.WARNING, err)
		return http.StatusForbidden, nil, errors.New(ErrCreate)
	}

	u, err := CreateUser(ctx.R.Context(), nu.Phone, nu.Password, nu.Name, nu.Sname, nu.Pname, nu.Email, nu.Birthday)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}

	return http.StatusOK, u, nil
}

// CreateUser создает нового пользователя
func CreateUser(ctx context.Context, phone *int64, password *string, name *string, sname *string, pname *string, email *string, birthday *time.Time) (interface{}, error) {
	if !validation.Phone(phone, false) {
		return nil, errors.New("Указан некорректный номер телефона")
	}
	if !validation.Email(email, true) {
		return nil, errors.New("Указан некорректный email")
	}
	if !validation.Password(password) {
		return nil, errors.New("Указан некорректный пароль")
	}

	db, err := database.Open(cfg.DB.Create)
	if err != nil {
		log.Print(log.WARNING, err)
		return nil, errors.New(ErrCreate)
	}
	rows, err := db.QueryContext(
		ctx,
		`select
			u.id,
			u.phone,
			u.name,
			u.sname,
			u.pname,
			u.email,
			u.is_email_confirmed,
			u.birthday,
			u.avatar
		from fn_user_ins($1, $2, $3, $4, $5, $6, $7) u`,
		phone,
		password,
		name,
		sname,
		pname,
		email,
		birthday,
	)
	if err != nil {
		ok, err := errorutil.DetectUserError(err)
		if ok {
			return nil, xerrors.FromError(err).WithCode(ErrFailedQueryExec)
		}

		log.Print(log.WARNING, err)
		return nil, errors.New(ErrCreate)
	}
	defer rows.Close()

	var u models.User
	if rows.Next() {
		if err := w3sqlutil.ScanToStruct(&u, rows); err != nil {
			log.Print(log.WARNING, err)
			return nil, errors.New(ErrCreate)
		}
	}

	return u, nil
}
