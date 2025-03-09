package apiws

import (
	"encoding/json"
	"net/http"
)

type APIResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func WriteError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIResult{Status: "error", Message: msg})
}

func WriteSuccessJSON(w http.ResponseWriter, body any) {
	err := json.NewEncoder(w).Encode(body)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
	}
}

func WriteSuccess(w http.ResponseWriter, message string) {
	WriteSuccessJSON(w, APIResult{Status: "success", Message: message})
}
