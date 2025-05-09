package basic

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/ybizeul/apiws/internal/middleware/confirm"
)

func TestBasicRandomPass(t *testing.T) {
	a := NewBasic("admin", nil)

	p := a.Password

	m := regexp.MustCompile(`^[A-Za-z]{7}$`).MatchString(p)
	if !m {
		t.Errorf("Expected password to be 7 characters long, got %s", p)
	}

	r, _ := http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("admin", p)

	err := a.authenticateRequest(r)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestNoCredentials(t *testing.T) {
	password := "password"
	a := NewBasic("admin", &password)

	r, _ := http.NewRequest("GET", "http://localhost:8080", nil)

	err := a.authenticateRequest(r)

	if err != ErrMissingCredentials {
		t.Errorf("Expected %v, got %v", ErrMissingCredentials, err)
	}
}

func TestBasic(t *testing.T) {
	cases := []struct {
		Username string
		Password string
		Error    error
	}{
		{"admin", "password", nil},
		{"admin", "password2", ErrBadCredentials},
	}

	for _, c := range cases {
		password := "password"
		a := NewBasic("admin", &password)

		r, _ := http.NewRequest("GET", "http://localhost:8080", nil)
		r.SetBasicAuth(c.Username, c.Password)

		err := a.authenticateRequest(r)

		if err != c.Error {
			t.Errorf("Expected %v, got %v", c.Error, err)
		}
	}
}

func TestMiddleware(t *testing.T) {
	cases := []struct {
		Username string
		Password string
		Status   int
	}{
		{"admin", "password", http.StatusOK},
		{"admin", "password2", http.StatusUnauthorized},
	}

	for _, c := range cases {
		password := "password"
		a := NewBasic("admin", &password)

		r, _ := http.NewRequest("GET", "http://localhost:8080", nil)
		r.SetBasicAuth(c.Username, c.Password)

		w := httptest.NewRecorder()

		a.AuthMiddleware(confirm.ConfirmMiddleware(
			"APIWSTEST", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))).ServeHTTP(w, r)

		if w.Result().StatusCode != c.Status {
			t.Errorf("Expected status %d, got %d", c.Status, w.Result().StatusCode)
		}
	}
}
