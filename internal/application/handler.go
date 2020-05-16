package application

import (
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	log.Println("socket request")
	if savedsocketreader == nil {
		savedsocketreader = make([]*socketReader, 0)
	}

	defer func() {
		err := recover()
		if err != nil {
			log.Println(err)
		}
		r.Body.Close()

	}()
	con, _ := upgrader.Upgrade(w, r, nil)

	ptrSocketReader := &socketReader{
		con: con,
	}

	savedsocketreader = append(savedsocketreader, ptrSocketReader)

	ptrSocketReader.startThread()
}
