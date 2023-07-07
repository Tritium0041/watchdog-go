package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", handleHttp)
	http.ListenAndServe(":80", nil)
}
