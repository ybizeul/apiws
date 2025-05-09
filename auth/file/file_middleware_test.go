package file

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ybizeul/apiws/auth"
	"github.com/ybizeul/apiws/internal/middleware/confirm"
)

func TestFileAuth(t *testing.T) {
	a, err := NewFile("file_testdata/users.yml")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	m := FileMiddleware{
		File: a,
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)
		if !ok {
			t.Errorf("Expected AuthStatus, got nil")
		}
		if authStatus.Error != nil {
			t.Errorf("Expected nil, got %v", authStatus.Error)
		}
		if authStatus.Authenticated == false {
			t.Errorf("Expected Success, got %t", authStatus.Authenticated)
		}
		if authStatus.User != "admin" {
			t.Errorf("Expected admin, got %v", authStatus.User)
		}
	}

	h1 := m.AuthMiddleware(http.HandlerFunc(fn1))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.SetBasicAuth("admin", "hupload")
	w := httptest.NewRecorder()
	h1.ServeHTTP(w, req)
}

func TestFileWrongCredentials(t *testing.T) {
	a, err := NewFile("file_testdata/users.yml")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	m := FileMiddleware{
		File: a,
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)
		if !ok {
			t.Errorf("Expected AuthStatus, got nil")
		}
		if authStatus.Error == nil {
			t.Errorf("Expected error, got nil")
		} else {
			if !errors.Is(authStatus.Error, ErrBadCredentials) {
				t.Errorf("Expected authentication failed, got %+v", authStatus.Error)
			}
		}
	}

	h1 := confirm.ConfirmMiddleware("realm", m.AuthMiddleware(http.HandlerFunc(fn1)))

	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.SetBasicAuth("admin", "wrong")

	h1.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %v", w.Code)
	}
}

func TestBasicAuthNoCredentials(t *testing.T) {
	a, err := NewFile("file_testdata/users.yml")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	m := FileMiddleware{
		File: a,
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// s, ok := r.Context().Value(AuthStatusKey).(AuthStatus)
		// if !ok {
		// 	t.Errorf("Expected AuthStatus, got nil")
		// }
		// if !errors.Is(s.Error, ErrBasicAuthNoCredentials) {
		// 	t.Errorf("Expected ErrBasicAuthNoCredentials, got %v", c)
		// }
	}

	h1 := confirm.ConfirmMiddleware("realm", m.AuthMiddleware(http.HandlerFunc(fn1)))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	w := httptest.NewRecorder()
	h1.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %v", w.Code)
	}
}
