package module

import (
	"errors"
	"net/http"

	"github.com/mtdst/chat/internal/models"
)

// Возможные типы данных полей в БД
const (
	Int = iota + 1
	Numeric
	String
	Bool
	TimeStamp
	JSON
)

var typeName = map[int]string{
	Int:       "int",
	Numeric:   "numeric",
	String:    "string",
	Bool:      "bool",
	TimeStamp: "timestamp",
	JSON:      "jsonb",
}

// Method описывает тип функции для метода модуля
type Method func(*Module, http.ResponseWriter, *http.Request, string) models.Response

// Methods описывает соответствие функций модуля HTTP-методам
type Methods map[string]Method

// Column описывает структуру поля в БД для алиаса в запросе
type Column struct {
	Alias    string
	Name     string
	Type     int
	Required bool
	Default  interface{}
}

// Columns описывает соответствие полей в БД алиасам в запросе
type Columns []Column

// Module описывает стурктуру модуля
type Module struct {
	Session models.Session
	Methods Methods
	Columns []Column
	Aliases []string
}

// Run запускает модуль в работу
func (m *Module) Run(w http.ResponseWriter, r *http.Request, cols string) models.Response {
	method, ok := m.Methods[r.Method]
	if !ok {
		return models.Response{Status: http.StatusNotFound, Error: errors.New("Запрошенный ресурс не найден")}
	}

	return method(m, w, r, cols)
}

// CreateAliases создаёт упорядоченный массив синонимов полей БД
func (m *Module) CreateAliases() {
	m.Aliases = make([]string, len(m.Columns))
	for k, v := range m.Columns {
		m.Aliases[k] = v.Alias
	}
}
