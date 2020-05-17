package me

import (
	"context"
	"database/sql"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/api/session"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/models"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/modules/me/coupon"
	disposablebarcode "devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/modules/me/disposable-barcode"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/modules/me/email"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/modules/me/password"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/modules/me/phone"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/internal/modules/me/sessions"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/cache"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/database"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/fileutil"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/server"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/transaction"
	"devgit.apteka-aprel.ru/web/api.apteka-april.ru/pkg/w3sqlutil"

	"github.com/x-foby/errors"
	"github.com/x-foby/go-short/log"
	"github.com/x-foby/w3sql/ast"
	"github.com/x-foby/w3sql/source"
	"github.com/x-foby/w3sql/token"
	"github.com/x-foby/w3sql/webserver"
)

// ошибки
const (
	ErrFailedAuth = models.ErrModuleMe + iota + 1
	ErrFailedOpenPrimaryDBConn
	ErrFailedQueryCompile
	ErrFailedQueryExec
	ErrFailedQueryScan
	ErrAccountNotFound
	ErrGetContentType
	ErrBadContentType
	ErrParseMultipart
	ErrFailedParseJSON
	ErrNoProfile
	ErrFailedReadHeader
	ErrBadFileType
	ErrFailedStartTx
	ErrFailedDeleteAvatarFromDB
	ErrFailedUpdateAvatarInDB
	ErrFailedOpenSecondaryDBConn
	ErrFailedQueryLoyalScan
	ErrFailedQueryLoyalUnmarshalJSON
	ErrFailedSaveFile
	ErrFailedGetAvatarsURL
)

// Config описывает структуру конфигурации модуля
type Config struct {
	models.ModuleWithTwoDBConfig
	AvatarsDir        *string                   `json:"avatarsDir,omitempty"`
	Coupon            *coupon.Config            `json:"coupon,omitempty"`
	DisposableBarcode *disposablebarcode.Config `json:"disposableBarcode,omitempty"`
	Password          *password.Config          `json:"password,omitempty"`
	Phone             *phone.Config             `json:"phone,omitempty"`
	Sessions          *sessions.Config          `json:"sessions,omitempty"`
	Email             *email.Config             `json:"email,omitempty"`
}

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
	)}).
		Get(read).
		Patch(update)

	server.Server().Route("me", module)

	cfg.Coupon = coupon.GetConfig()
	cfg.DisposableBarcode = disposablebarcode.GetConfig()
	cfg.Password = password.GetConfig()
	cfg.Phone = phone.GetConfig()
	cfg.Sessions = sessions.GetConfig()
	cfg.Email = email.GetConfig()
}

// GetConfig возвращает указатель на структуру для заполнения настроек
func GetConfig() *Config {
	return &cfg
}

func read(ctx webserver.Context) (int, interface{}, error) {
	// Получаем информацию о сессии. Если её нет, то отказываем пользователю в получении информации
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s == nil {
		return http.StatusForbidden, nil, errors.New("Вы не авторизованы").WithCode(ErrFailedAuth)
	}

	ctx.Query.WrapCondition(
		ast.NewBinaryExpr(
			token.EQL,
			ast.NewIdent("ID", 0),
			ast.NewConst(strconv.Itoa(s.UserID), 0, token.INT),
			0,
		),
		token.AND,
	)

	q, err := ctx.Query.Compile("v_user")
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	var cached *models.User
	cacher, key := cache.FromCache(ctx.R.Context(), models.ContextCacher, q, cfg.CacheDuration, &cached)
	if cacher != nil && cached != nil {
		return http.StatusOK, cached, nil
	}

	primaryDB, err := database.Open(cfg.DB.Primary.Read)
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedOpenPrimaryDBConn)
	}

	rows, err := primaryDB.QueryContext(ctx.R.Context(), q)
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryExec)
	}
	defer rows.Close()

	var u models.User
	if rows.Next() {
		if err := w3sqlutil.ScanToStruct(&u, rows); err != nil {
			return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryScan)
		}
	} else {
		return http.StatusNotFound, nil, errors.New("Пользователь не найден").WithCode(ErrAccountNotFound)
	}

	fields := ctx.Query.Fields()
	if !w3sqlutil.ContainsField(fields, "loyalCard") {
		if cacher != nil {
			if err := cacher.Store(key, u, *cfg.CacheDuration); err != nil {
				log.Print(log.WARNING, err)
			}
		}
		return http.StatusOK, u, nil
	}

	return getLoyalCard(ctx.R.Context(), u, s, cacher, key)
}

func update(ctx webserver.Context) (int, interface{}, error) {
	// Получаем информацию о сессии. Если её нет, то отказываем пользователю в получении информации
	s, err := session.Get(ctx.R)
	if err != nil {
		return http.StatusForbidden, nil, err
	}
	if s == nil {
		return http.StatusForbidden, nil, errors.New("Вы не авторизованы").WithCode(ErrFailedAuth)
	}

	contentType, _, err := mime.ParseMediaType(ctx.R.Header.Get("Content-Type"))
	if err != nil {
		return http.StatusBadRequest, nil, errors.FromError(err).WithCode(ErrGetContentType)
	}
	if contentType != "multipart/form-data" {
		return http.StatusBadRequest, nil, errors.New("Ожидался запрос формата multipart/form-data").WithCode(ErrBadContentType)
	}

	if err := ctx.R.ParseMultipartForm(4 * 1024 * 1024); err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrParseMultipart)
	}

	buf := []byte(strings.TrimSpace(ctx.R.FormValue("profile")))
	if len(buf) == 0 {
		return http.StatusBadRequest, nil, errors.New("Не передан профиль пользователя").WithCode(ErrNoProfile)
	}

	var u models.User
	if err := json.Unmarshal(buf, &u); err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedParseJSON)
	}

	db, err := database.Open(cfg.DB.Primary.Update)
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedOpenPrimaryDBConn)
	}
	tx, err := db.Begin()
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedStartTx)
	}
	defer func() { transaction.CompleteTx(tx, err) }()

	q, err := ctx.Query.Compile("fn_user_upd($1, $2, $3, $4, $5, $6)")
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryCompile)
	}

	if isMobile, ok := ctx.R.Context().Value(models.ContextIsMobile).(bool); !ok || !isMobile {
		u.Email = nil
	}

	rows, err := tx.QueryContext(ctx.R.Context(), q, &s.UserID, &u.Name, &u.Sname, &u.Pname, &u.Birthday, &u.Email)
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryExec)
	}

	// rows.Close() вызывается не через defer, а явно, так как в этой же транзакции вызывается метод UPDATE,
	// на что lib/pq отвечает pq: unexpected Parse response 'C'
	u = models.User{}
	if rows.Next() {
		if err := w3sqlutil.ScanToStruct(&u, rows); err != nil {
			rows.Close()
			return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryScan)
		}
	}
	rows.Close()

	file, header, err := ctx.R.FormFile("avatar")
	if err != nil {
		err = nil
		if contains(ctx.R.MultipartForm.Value, "avatar") {
			if err = deleteAvatar(ctx.R.Context(), tx, &u); err != nil {
				return http.StatusInternalServerError, nil, err
			}
		}
	} else {
		if err = updateAvatar(ctx.R.Context(), tx, &u, file, header); err != nil {
			return http.StatusInternalServerError, nil, err
		}
	}

	fields := ctx.Query.Fields()
	if !w3sqlutil.ContainsField(fields, "loyalCard") {
		return http.StatusOK, u, nil
	}

	return getLoyalCard(ctx.R.Context(), u, s, nil, "")
}

func contains(form map[string][]string, key string) bool {
	for k := range form {
		if k == key {
			return true
		}
	}
	return false
}

func deleteAvatar(ctx context.Context, tx *sql.Tx, u *models.User) error {
	var fn *string
	if err := tx.QueryRowContext(ctx, "select * from fn_user_avatar_del($1)", u.ID).Scan(&fn); err != nil {
		return errors.FromError(err).WithCode(ErrFailedDeleteAvatarFromDB)
	}

	if fn != nil {
		fileutil.Delete(*fn, cfg.AvatarsDir) // ignore err
	}

	return nil
}

func updateAvatar(ctx context.Context, tx *sql.Tx, u *models.User, file multipart.File, header *multipart.FileHeader) error {
	var allowedMimeTypes = map[string]string{
		"image/jpeg": "jpg",
		"image/png":  "png",
	}

	var ext string
	filebuf := make([]byte, header.Size)
	if header != nil {
		if _, err := file.Read(filebuf); err != nil {
			return errors.FromError(err).WithCode(ErrFailedReadHeader)
		}

		fileType := http.DetectContentType(filebuf[:512])
		var ok bool
		ext, ok = allowedMimeTypes[fileType]
		if !ok {
			return errors.New("Изображение должно иметь формат jpeg или png").WithCode(ErrBadFileType)
		}
	}

	var (
		fn    *string
		oldFn *string
	)
	if err := tx.QueryRowContext(ctx, "select * from fn_user_avatar_upd($1, $2)", u.ID, ext).Scan(&fn, &oldFn); err != nil {
		return errors.FromError(err).WithCode(ErrFailedUpdateAvatarInDB)
	}

	if err := fileutil.Save(filebuf, cfg.AvatarsDir, *fn); err != nil {
		return errors.FromError(err).WithCode(ErrFailedSaveFile)
	}

	var avatarsURL string
	if err := tx.QueryRowContext(ctx, "select z_param($1)", "avatarsURL").Scan(&avatarsURL); err != nil {
		return errors.FromError(err).WithCode(ErrFailedGetAvatarsURL)
	}

	url := avatarsURL + "/" + *fn
	u.Avatar = &url

	if oldFn != nil {
		fileutil.Delete(*oldFn, cfg.AvatarsDir) // ignore err
	}

	return nil
}

func getLoyalCard(ctx context.Context, u models.User, s *models.Session, cacher cache.Cacher, key string) (int, interface{}, error) {
	secondaryDB, err := database.Open(cfg.DB.Secondary.Read)
	if err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedOpenSecondaryDBConn)
	}

	payload := []byte(`{"client_phone": ` + strconv.FormatInt(s.UserPhone, 10) + `}`)
	var buf []byte
	if err := secondaryDB.QueryRowContext(ctx, "select * from api.fn_loyal_client_search_web($1)", string(payload)).Scan(&buf); err != nil {
		if !strings.Contains(err.Error(), "USER_ERROR") {
			return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryLoyalScan)
		}
	}
	if buf == nil {
		if cacher != nil {
			if err := cacher.Store(key, u, *cfg.CacheDuration); err != nil {
				log.Print(log.WARNING, err)
			}
		}
		return http.StatusOK, u, nil
	}

	var data struct {
		PeriodID         *int     `json:"period_id"`
		SumDiscount      *float64 `json:"sum_discount"`
		CardScanCode     *int64   `json:"card_scan_code"`
		PeriodBlockDate  *string  `json:"period_block_date"`
		BonusCountActive *float64 `json:"bonus_count_active"`
	}
	if err := json.Unmarshal(buf, &data); err != nil {
		return http.StatusInternalServerError, nil, errors.FromError(err).WithCode(ErrFailedQueryLoyalUnmarshalJSON)
	}

	u.LoyalCard = &models.LoyalCard{
		Barcode:  data.CardScanCode,
		PeriodID: data.PeriodID,
		Balance:  data.BonusCountActive,
		Saved:    data.SumDiscount,
	}

	if data.PeriodBlockDate != nil {
		if t, err := time.Parse("2006-01-02", *data.PeriodBlockDate); err == nil {
			u.LoyalCard.PeriodBlockDate = &t
		}
	}

	if cacher != nil {
		if err := cacher.Store(key, u, *cfg.CacheDuration); err != nil {
			log.Print(log.WARNING, err)
		}
	}
	return http.StatusOK, u, nil
}
