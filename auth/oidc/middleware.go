package oidc

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ybizeul/apiws/auth/middleware"
)

// OIDCMiddleware is a middleware that checks the authentication of the user
// using OIDC.
type OIDCMiddleware struct {
	OIDC *OIDC
}

func (a OIDCMiddleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.OIDC == nil {
			middleware.ServeNextError(next, w, r, errors.New("no authentication backend"))
			return
		}

		session, err := a.OIDC.session(r)
		if err != nil {
			slog.Error("Unable to get session", "error", err, "url", r.URL.String())
			return
			// middleware.ServeNextError(next, w, r, err)
			// return
		}

		err = a.OIDC.authenticateRequest(w, r)
		if err != nil {
			if err == ErrAuthenticationRedirect {
				return
			}
			middleware.ServeNextError(next, w, r, err)
			return
		}

		if session.Values["username"] != nil && session.Values["username"] != "" {
			middleware.ServeNextAuthenticated(session.Values["username"].(string), next, w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}
