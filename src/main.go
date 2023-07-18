package main

import (
	"net/http"
)

func main() {
	go checkfilesmain()
	http.HandleFunc("/", handleHttp)
	http.ListenAndServe(":80", nil)
}
