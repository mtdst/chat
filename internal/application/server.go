package application

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	flags "github.com/jessevdk/go-flags"
)

var options = struct {
	WorkspaceFolder string `long:"workspace_folder" description:"path to root folder" env:"WORKSPACE_FOLDER"`
	PagesPath       string `long:"templates_path" description:"path to templates catalog" default:"./pages/" env:"PAGES_PATH"`

	Host string `long:"host" description:"the IP to listen on" default:"localhost" env:"HOST"`
	Port int    `long:"port" description:"the port to listen on for insecure connections, defaults 8080" default:"8080" env:"PORT"`
}{}

func configure() error {
	_, err := flags.ParseArgs(&options, os.Args)
	if err != nil {
		return err
	}
	return nil
}

// Run запускает сервер
func Run() error {
	if err := configure(); err != nil {
		return err
	}

	PagePath := filepath.Join(options.WorkspaceFolder, options.PagesPath)
	fs := http.FileServer(http.Dir(PagePath))
	port := strconv.Itoa(options.Port)
	mux := http.NewServeMux()

	mux.Handle("/", http.StripPrefix("", fs))
	mux.HandleFunc("/socket", handler)

	log.Println("Сервер успешно запущен: http://localhost:" + port)

	http.ListenAndServe(":"+port, mux)
	return nil
}
