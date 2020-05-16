package application

import (
	"log"
	"net/http"
)

// Run запускает сервер
func Run() error {

	myhttp := http.NewServeMux()
	fs := http.FileServer(http.Dir("./views/"))
	myhttp.Handle("/", http.StripPrefix("", fs))

	myhttp.HandleFunc("/socket", websocket)

	log.Println("http://localhost:8080")
	http.ListenAndServe(":8080", myhttp)
	return nil
}
