package application

import (
	"net/http"

	"github.com/mtdst/chat/internal/socket"
)

func handler(w http.ResponseWriter, r *http.Request) {
	socket.Create(w, r)
}
