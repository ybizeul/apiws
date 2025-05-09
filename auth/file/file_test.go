package file

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuthentication(t *testing.T) {
	a, err := NewFile("file_testdata/users.yml")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	r, _ := http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("admin", "hupload")

	err = a.authenticateRequest(nil, r)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	r, _ = http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("admin", "random")

	err = a.authenticateRequest(nil, r)

	if err != ErrBadCredentials {
		t.Errorf("Expected ErrAuthenticationBadCredentials, got %v", err)
	}

	r, _ = http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("nonexistant", "random")

	err = a.authenticateRequest(nil, r)

	if err != ErrBadCredentials {
		t.Errorf("Expected ErrAuthenticationBadCredentials, got %v", err)
	}
}

func TestAuthenticationInexistantUsersFile(t *testing.T) {
	_, err := NewFile("file_testdata/users_inexistant.yml")

	if !errors.Is(err, ErrMissingUsersFile) {
		t.Errorf("Expected error, got nil")
	}
}
