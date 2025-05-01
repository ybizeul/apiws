package authentication

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuthentication(t *testing.T) {
	c := FileConfig{
		Path: "file_testdata/users.yml",
	}

	a, err := NewFile(c)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	r, _ := http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("admin", "hupload")

	err = a.AuthenticateRequest(nil, r)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	r, _ = http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("admin", "random")

	err = a.AuthenticateRequest(nil, r)

	if err != ErrAuthenticationBadCredentials {
		t.Errorf("Expected ErrAuthenticationBadCredentials, got %v", err)
	}

	r, _ = http.NewRequest("GET", "http://localhost:8080", nil)
	r.SetBasicAuth("nonexistant", "random")

	err = a.AuthenticateRequest(nil, r)

	if err != ErrAuthenticationBadCredentials {
		t.Errorf("Expected ErrAuthenticationBadCredentials, got %v", err)
	}
}

func TestAuthenticationInexistantUsersFile(t *testing.T) {
	c := FileConfig{
		Path: "file_testdata/users_inexistant.yml",
	}

	_, err := NewFile(c)

	if !errors.Is(err, ErrAuthenticationMissingUsersFile) {
		t.Errorf("Expected error, got nil")
	}
}
