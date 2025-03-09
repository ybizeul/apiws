package authentication

import (
	"net/http"
)

// AuthenticationNone is the default authentication when none has been found
// in configuration. Username is `admin` and password is a random 7 characters
type AuthenticationNone struct {
	Password string
}

func NewAuthenticationNone() *AuthenticationNone {
	return &AuthenticationNone{}
}

func (a *AuthenticationNone) AuthenticateRequest(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (o *AuthenticationNone) CallbackFunc(http.Handler) (func(w http.ResponseWriter, r *http.Request), bool) {
	return nil, false
}

func (o *AuthenticationNone) ShowLoginForm() bool {
	return false
}
func (o *AuthenticationNone) LoginURL() string {
	return "/"
}
