package open

import (
	"net/http"
	"testing"

	"github.com/ybizeul/apiws/auth"
)

func TestOpenAuthWithCredentials(t *testing.T) {

	m := Middleware{}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)

		if !ok {
			t.Errorf("Expected AuthStatus, got nil")
		}
		if authStatus.Error != nil {
			t.Errorf("Expected nil, got %+v", authStatus.Error)
		}
		if !authStatus.Authenticated {
			t.Errorf("Expected AuthStatusSuccess, got %t", authStatus.Authenticated)
		}
		if authStatus.User != "" {
			t.Errorf("Expected nil, got %s", authStatus.User)
		}
	}

	h1 := m.Middleware(http.HandlerFunc(fn1))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.SetBasicAuth("admin", "hupload")

	h1.ServeHTTP(nil, req)
}

func TestOpenAuthWithoutCredentials(t *testing.T) {

	m := Middleware{}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)

		if !ok {
			t.Errorf("Expected AuthStatus, got nil")
		}
		if authStatus.Error != nil {
			t.Errorf("Expected nil, got %v", authStatus.Error)
		}
		if !authStatus.Authenticated {
			t.Errorf("Expected AuthStatusSuccess, got %t", authStatus.Authenticated)
		}
		if authStatus.User != "" {
			t.Errorf("Expected nil, got %v", authStatus.User)
		}
	}

	h1 := m.Middleware(http.HandlerFunc(fn1))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	h1.ServeHTTP(nil, req)
}
