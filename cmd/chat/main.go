package main

import "github.com/mtdst/chat/internal/application"

func main() {
	if err := application.Run(); err != nil {
		panic(err)
	}
}
