// Command upstream runs the local echo service used to record Cover's README
// demo. It never contacts an external service: it returns the protected input
// it receives so the proxy can demonstrate response restoration.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type request struct {
	Input string `json:"input"`
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		target := strings.TrimPrefix(body.Input, "Check ")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"reply": "Checked " + target + " — healthy",
		})
	})

	server := &http.Server{Addr: "127.0.0.1:19318", Handler: handler}
	log.Fatal(server.ListenAndServe())
}
