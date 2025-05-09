package apiws

import (
	"encoding/json"
	"net/http"
)

type apiResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(apiResult{Status: "error", Message: msg})
}

func writeSuccessJSON(w http.ResponseWriter, body any) {
	err := json.NewEncoder(w).Encode(body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
