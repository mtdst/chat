package database

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/mtdst/chat/pkg/config"
	"github.com/x-foby/go-short/database"
)

// Open устанавливает соединение с базой данных из пула, если соединение ещё не установлено, и возвращает ссылку на него
func Open(name string) (*sql.DB, error) {
	s := strings.TrimSpace(name)
	if s == "" {
		s = strings.TrimSpace(config.Get().Database.DefaultConnection)
	}

	if s == "" {
		return nil, errors.New("Не задано соединение по умолчанию")
	}

	return database.Open(s)
}
