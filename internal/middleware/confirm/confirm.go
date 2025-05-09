package confirm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ybizeul/apiws/auth"
)

// ConfirmMiddleware is a middleware that checks if the user is authenticated.
// It must always be called after any custom authentication middleware
// you provide. ConfirmMiddleware is already called by standard authentication
// backends.
func ConfirmMiddleware(realm string, mw http.Handler) http.Handler {
	c := confirmAuthenticator{
		Realm: realm,
	}
	return c.Middleware(mw)
}

// confirmAuthenticator is responsible for checking the request is
// authenticated. It calls the next handler if authentication is valid, and
// resturns a 401 Unauthorized response if not.
type confirmAuthenticator struct {
	Realm string
}

func (a *confirmAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authStatus, ok := auth.AuthForRequest(r)
		if ok && authStatus.Authenticated {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\"", a.Realm))

		w.WriteHeader(http.StatusUnauthorized)

		if authStatus.Error != nil {
			errs := struct {
				Errors []string `json:"errors"`
			}{
				Errors: strings.Split(authStatus.Error.Error(), "\n"),
			}
			b, _ := json.Marshal(errs)

			slog.Error("authentication failed", slog.Any("errors", b))

			_, _ = w.Write(b)
		} else {
			slog.Error("authentication failed")
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}

	})
}
