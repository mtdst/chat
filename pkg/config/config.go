package config

import (
	"os"
	"path/filepath"

	"github.com/x-foby/go-short/config"
	"github.com/x-foby/go-short/database"
	"github.com/x-foby/go-short/log"
)

// DBConfig описывает структуру конфигурации БД
type DBConfig struct {
	*database.Settings
	DefaultConnection string `json:"defaultConnection"`
}

// CacheConfig описывает настройки кэша
type CacheConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// CoreConfig содержит основные настройки приложения
type CoreConfig struct {
	PrettyJSON bool        `json:"prettyJSON"`
	Cache      CacheConfig `json:"cache"`
}

// Config описывает структуру настроек
type Config struct {
	Core     CoreConfig  `json:"core"`
	Database DBConfig    `json:"db"`
	HTTP     interface{} `json:"http"`
	SMS      interface{} `json:"sms"`
	Mail     interface{} `json:"mail"`
	Modules  interface{} `json:"modules"`
	Payment  interface{} `json:"payment"`
}

var cfg Config
var afterLoading []func()

// Get возвращает сыылку на экземпляр cfg
func Get() *Config {
	return &cfg
}

// AfterLoading вызывает переданную функцию после чтения настроек
func AfterLoading(cb func()) {
	afterLoading = append(afterLoading, cb)
}

// Init иницализирует конфигурацию
func Init() {
	cfg.Database.Settings = database.GetSettings()

	config.Set(&cfg)
	config.SetFilename(filepath.Dir(os.Args[0]) + string(os.PathSeparator) + "config.json")

	if err := config.ReadFromFile(); err != nil {
		log.Print(log.WARNING, err)
	}

	for _, cb := range afterLoading {
		cb()
	}
}
