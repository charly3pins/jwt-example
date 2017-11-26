package main

import (
	"log"
	"net/http"

	"github.com/charly3pins/jwt-example/authentication"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", authentication.Login)
	mux.HandleFunc("/validate", authentication.ValidateToken)

	log.Println("Listening in port 8080")
	http.ListenAndServe(":8080", mux)
}
