package authentication

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
)

// Basic is the default authentication when none has been found
// in configuration. Username is `admin` and password is a random 7 characters
type Basic struct {
	Username string
	Password string
}

func NewBasic(username string, password *string) *Basic {
	if password == nil {
		p := generateCode(7)
		password = &p
	}
	slog.Info(fmt.Sprintf("Starting with default authentication backend. username: %s, password: %s", username, *password))

	r := &Basic{
		Username: username,
		Password: *password,
	}

	return r
}

func (a *Basic) AuthenticateRequest(w http.ResponseWriter, r *http.Request) error {
	username, password, ok := r.BasicAuth()
	if !ok {
		return ErrAuthenticationMissingCredentials
	}
	if username == a.Username && password == a.Password {
		return nil
	}
	return ErrAuthenticationBadCredentials
}

func (o *Basic) Callback(http.Handler) (http.Handler, string) {
	return nil, ""
}

func (o *Basic) ShowLoginForm() bool {
	return true
}
func (o *Basic) LoginURL() string {
	return "/"
}
func generateCode(l int) string {
	code := ""

	for i := 0; i < l; i++ {
		c := rand.IntN(52)
		if c > 25 {
			c += 6
		}
		code += string(rune(c + 65))
	}
	return code
}
