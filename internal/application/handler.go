package application

import (
	"net/http"

	"github.com/mtdst/chat/internal/socket"
	"github.com/mtdst/chat/pkg/database"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db, err = database.Connect()
	if err != nil {
		panic(err.Error())
	}
	socket.Create(w, r)
}
