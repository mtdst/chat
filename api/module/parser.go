package module

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/mtdst/chat/pkg/arrays"
)

// OPERANDS TYPE
const (
	LESS = iota + 1
	LESSOREQUAL
	MORE
	MOREOREQUAL
	EQUAL
	NOTEQUAL
	LIKE
)

// // ParserError описывает ошибку парсера
// type ParserError struct {
// 	Position int
// 	Message  string
// }

// // FilterError описывает ошибку парсера
// type FilterError struct {
// 	Message string
// }

// Filter описывает поле фильтра
type Filter struct {
	Field   string
	Operand int
	Value   interface{}
}

// Request описывает пользовательский запрос
// type Request struct {
// 	Path   []string
// 	Fields []string
// 	Filter []Filter
// }

// func (e ParserError) Error() string {
// 	return fmt.Sprintf("%v at %v", e.Message, e.Position)
// }

// func (e FilterError) Error() string {
// 	return e.Message
// }

// GetCols возвращает список полей для запроса в БД
func (m *Module) GetCols(cols string) (string, []string, error) {
	if strings.TrimSpace(cols) == "" {
		return "*", []string{}, nil
	}
	userCols := make([]string, 0)
	for _, col := range strings.Split(cols, ",") {
		cn := strings.TrimSpace(col)
		if cn == "" {
			return "", []string{}, errors.New("Сolumn name can't be empty")
		}
		if !arrays.InArray(m.Aliases, cn) {
			return "", []string{}, fmt.Errorf("Unknown column name %q", cn)
		}
		userCols = append(userCols, cn)
	}
	result := make([]string, len(m.Columns))
	for k, col := range m.Columns {
		if !arrays.InArray(userCols, col.Alias) && !col.Required {
			result[k] = "null"
		} else {
			result[k] = col.Name
		}
	}
	return strings.Join(result, ", "), userCols, nil
}

// GetFilter возвращает список полей для запроса в БД
func (m *Module) GetFilter(r *http.Request, defaultValues *[]Filter, forcedValues *[]Filter) ([]Filter, error) {
	q, err := url.QueryUnescape(r.URL.RawQuery)
	if err != nil {
		return []Filter{}, err
	}
	return m.getFilter(q, defaultValues, forcedValues)
}

// GetWhere формирует список полей запроса
func (m *Module) GetWhere(r *http.Request, defaultValues *[]Filter, forcedValues *[]Filter) (string, []interface{}, error) {
	q, err := url.QueryUnescape(r.URL.RawQuery)
	if err != nil {
		return "", []interface{}{}, err
	}
	filter, err := m.getFilter(q, defaultValues, forcedValues)
	if err != nil {
		return "", []interface{}{}, err
	}
	result := make([]string, len(filter))
	values := make([]interface{}, len(filter))
	for k, f := range filter {
		i := arrays.IndexOf(m.Aliases, f.Field)
		if i == -1 {
			return "", []interface{}{}, fmt.Errorf("Unknown field %q", f.Field)
		}
		wp, err := m.getWherePart(f, m.Columns[i].Name, m.Columns[i].Type, k+1)
		if err != nil {
			return "", []interface{}{}, err
		}
		result[k] = wp
		if f.Operand == LIKE {
			v := "%" + f.Value.(string) + "%"
			values[k] = v
		} else {
			values[k] = f.Value
		}
	}
	if len(result) == 0 {
		return "", []interface{}{}, nil
	}
	return " where " + strings.Join(result, " and "), values, nil
}

func (m *Module) getWherePart(f Filter, fieldName string, fieldType int, n int) (string, error) {
	format := ""
	isDigit := fieldType != Int && fieldType != Numeric && fieldType != TimeStamp
	switch f.Operand {
	case LESS:
		if isDigit {
			return "", convertError(f.Field, fieldType)
		}
		format = "%s < $%v"
	case LESSOREQUAL:
		if isDigit {
			return "", convertError(f.Field, fieldType)
		}
		format = "%s <= $%v"
	case MORE:
		if isDigit {
			return "", convertError(f.Field, fieldType)
		}
		format = "%s > $%v"
	case MOREOREQUAL:
		if isDigit {
			return "", convertError(f.Field, fieldType)
		}
		format = "%s >= $%v"
	case EQUAL:
		format = "%s = $%v"
	case NOTEQUAL:
		format = "%s != $%v"
	case LIKE:
		if fieldType != String {
			return "", convertError(f.Field, fieldType)
		}
		format = "%s like $%v"
	}
	return fmt.Sprintf(format, fieldName, n), nil
}

func convertError(f string, t int) error {
	return fmt.Errorf("Сannot convert %v to type %s", f, typeName[t])
}

func (m *Module) getFilter(q string, defaultValues *[]Filter, forcedValues *[]Filter) ([]Filter, error) {
	const (
		FIELD = iota + 1
		OPERAND
		VALUE
	)
	result := []Filter{}
	var currPartType int
	currPart := ""
	currFilter := Filter{}
	for i := range q {
		runeValue, runeWidth := utf8.DecodeRuneInString(q[i:])
		currSymbol := string(runeValue)
		switch currSymbol {
		case "<", ">", "!", "~":
			if currPartType != FIELD || currPartType == 0 {
				return nil, fmt.Errorf("Unexpected symbol %q at %v", currSymbol, i)
			}
			currFilter.Field = currPart
			currPart = currSymbol
			currPartType = OPERAND
		case "=":
			if currPartType == OPERAND && currPart == "<" {
				currFilter.Operand = LESSOREQUAL
			} else if currPartType == OPERAND && currPart == ">" {
				currFilter.Operand = MOREOREQUAL
			} else if currPartType == OPERAND && currPart == "!" {
				currFilter.Operand = NOTEQUAL
			} else if currPartType == OPERAND && currPart == "~" {
				currFilter.Operand = LIKE
			} else if currPartType == FIELD {
				currFilter.Field = currPart
				currFilter.Operand = EQUAL
				currPartType = OPERAND
			} else {
				return nil, fmt.Errorf("Unexpected symbol %q at %v", currSymbol, i)
			}
			currPart = ""
		default:
			if currPartType == OPERAND {
				if currPart == "<" {
					currFilter.Operand = LESS
				}
				if currPart == ">" {
					currFilter.Operand = MORE
				}
				currPartType = VALUE
				currPart = ""
			}
			if currPartType == VALUE {
				if currSymbol == "&" {
					// df := getFilter(defaultValues, currFilter.Field)
					// if df != nil {
					// 	currFilter.Operand = df.Operand
					// 	currFilter.Value = df.Value
					// } else {
					// 	currFilter.Value = currPart
					// }
					currFilter.Value = currPart
					currPart = ""
					currPartType = FIELD
					result = append(result, currFilter)
				} else if i+runeWidth == len(q) {
					currPart += currSymbol
					// df := getFilter(defaultValues, currFilter.Field)
					// if df != nil {
					// 	currFilter.Operand = df.Operand
					// 	currFilter.Value = df.Value
					// } else {
					// 	currFilter.Value = currPart
					// }
					currFilter.Value = currPart
					result = append(result, currFilter)
				} else {
					currPart += currSymbol
				}
			} else if currPartType == FIELD {
				currPart += currSymbol
			} else if currPartType == 0 {
				currPartType = FIELD
				currPart += currSymbol
			} else {
				return nil, fmt.Errorf("Unexpected symbol %q at %v", currSymbol, i)
			}
		}
	}
	if defaultValues != nil {
		for _, v := range *defaultValues {
			i := getFilterPos(&result, v.Field)
			if i == -1 {
				result = append(result, v)
			}
		}
	}
	if forcedValues != nil {
		for _, v := range *forcedValues {
			i := getFilterPos(&result, v.Field)
			if i == -1 {
				result = append(result, v)
			} else {
				result[i].Operand = v.Operand
				result[i].Value = v.Value
			}
		}
	}
	return result, nil
}

func getFilterPos(filters *[]Filter, name string) int {
	if filters == nil {
		return -1
	}
	for k, v := range *filters {
		if v.Field == name {
			return k
		}
	}
	return -1
}
