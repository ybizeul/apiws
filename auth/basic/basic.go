/*
Basic authentication provides a simple username/password authentication assed
in authentication header.
*/
package basic

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
)

var (
	ErrMissingCredentials = errors.New("no credentials provided in request")
	ErrBadCredentials     = errors.New("bad username or password")
)

// Basic is a rudimentary backend for auth. It uses a username and
// password to authenticate the user. The password is generated if not
// provided.
type Basic struct {
	BasicMiddleware
	Username string
	Password string
}

// NewBasic creates a new Basic backend. If password is nil, a random password
// is generated and sent to the logs.
func NewBasic(username string, password *string) *Basic {
	if password == nil {
		p := generateCode(7)
		password = &p
		slog.Info(fmt.Sprintf(`Generated random password for '%s' : %s`, username, *password))
	}

	r := &Basic{
		Username: username,
		Password: *password,
	}

	r.BasicMiddleware = BasicMiddleware{
		Basic: r,
	}
	return r
}

func (a *Basic) authenticateRequest(r *http.Request) error {
	username, password, ok := r.BasicAuth()
	if !ok {
		return ErrMissingCredentials
	}
	if username == a.Username && password == a.Password {
		return nil
	}
	return ErrBadCredentials
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
