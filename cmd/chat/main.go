package main

func main() {
	if err := application.Run(); err != nil {
		panic(err)
	}
}
