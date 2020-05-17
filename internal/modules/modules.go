package modules

import (
	"github.com/mtdst/chat/internal/modules/me"
	"github.com/mtdst/chat/internal/modules/users"
	"github.com/mtdst/chat/pkg/config"
)

// Config описывает структуру конфигурации модуля
type Config struct {
	Me    *me.Config    `json:"me,omitempty"`
	Users *users.Config `json:"users,omitempty"`
}

var cfg Config

func init() {
	cfg.Me = me.GetConfig()
	cfg.Users = users.GetConfig()

	config.Get().Modules = &cfg
}
