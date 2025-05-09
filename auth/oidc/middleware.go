package oidc

import (
	"errors"
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

		store, err := a.OIDC.store.Get(r, a.OIDC.config.SessionName)
		if err != nil {
			middleware.ServeNextError(next, w, r, err)
			return
		}

		err = a.OIDC.authenticateRequest(w, r)
		if err != nil {
			if err == ErrAuthenticationRedirect {
				return
			}
			middleware.ServeNextError(next, w, r, err)
			return
		}

		if store.Values["username"] != nil && store.Values["username"] != "" {
			middleware.ServeNextAuthenticated(store.Values["username"].(string), next, w, r)
			return
		}

		next.ServeHTTP(w, r)
		//ServeNextError(next, w, r, auth.ErrAuthenticationMissingCredentials)
	})
}
