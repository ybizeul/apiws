package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ybizeul/apiws/auth"
	"github.com/ybizeul/apiws/internal/middleware/confirm"
)

func TestServeNextAuthenticated(t *testing.T) {
	successMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ServeNextAuthenticated("user", next, w, r)
		})
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)

		if authStatus.Error != nil {
			t.Errorf("Expected nil, got %+v", authStatus.Error)
		}
		if !authStatus.Authenticated || !ok {
			t.Errorf("Expected AuthStatusSuccess, got %+v", authStatus)
		}
		u := authStatus.User
		if u != "user" {
			t.Errorf("Expected admin, got %s", authStatus.User)
		}
	}

	h1 := successMiddleware(http.HandlerFunc(fn1))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	h1.ServeHTTP(nil, req)
}

var fakeError = errors.New("Some Error")

func TestServeNextAuthFailed(t *testing.T) {
	failMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ServeNextError(next, w, r, fakeError)
		})
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)

		if authStatus.Error == nil {
			t.Errorf("Expected error, got nil, %t", ok)
		} else {
			if !errors.Is(authStatus.Error, fakeError) {
				t.Errorf("Expected fakeError, got %+v", authStatus.Error)
			}
		}
	}

	h1 := failMiddleware(http.HandlerFunc(fn1))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	h1.ServeHTTP(nil, req)
}

func TestConfirmAuthentication(t *testing.T) {
	successMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ServeNextAuthenticated("user", next, w, r)
		})
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}

	h1 := successMiddleware(confirm.ConfirmMiddleware("realm", http.HandlerFunc(fn1)))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	r := httptest.NewRecorder()

	h1.ServeHTTP(r, req)

	if r.Code != http.StatusOK {
		t.Errorf("Expected 200, got %v", r.Code)
	}
}

func TestFailedAuthentication(t *testing.T) {
	failMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ServeNextError(next, w, r, fakeError)
		})
	}

	fn1 := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}

	h1 := failMiddleware(confirm.ConfirmMiddleware("realm", http.HandlerFunc(fn1)))

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	r := httptest.NewRecorder()

	h1.ServeHTTP(r, req)

	if r.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %v", r.Code)
	}
	expected := "{\"errors\":[\"Some Error\"]}"
	b, _ := io.ReadAll(r.Result().Body)
	if string(b) != expected {
		t.Errorf("Expected %s, got %v", expected, string(b))
	}
}
