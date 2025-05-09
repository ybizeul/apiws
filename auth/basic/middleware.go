package basic

import (
	"errors"
	"net/http"
	"os"

	"github.com/ybizeul/apiws/auth/middleware"
	"github.com/ybizeul/apiws/internal/middleware/jwt"
)

type BasicMiddleware struct {
	Basic *Basic
}

// AuthMiddleware is a middleware that checks the authentication of the user
func (a BasicMiddleware) AuthMiddleware(next http.Handler) http.Handler {
	j := jwt.JWTAuthMiddleware{
		HMACSecret: os.Getenv("JWT_SECRET"),
	}
	next = j.Middleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if a.Basic == nil {
			middleware.ServeNextError(next, w, r, errors.New("no authentication backend"))
			return
		}

		// If there is no credentials, skip middleware
		var qUser string
		var ok bool

		// Pass next handler if no basic auth is provided in the request
		if qUser, _, ok = r.BasicAuth(); !ok {
			next.ServeHTTP(w, r)
			return
		}

		// If authentication has been sent, check credentials

		err := a.Basic.authenticateRequest(r)

		if err != nil {
			middleware.ServeNextError(next, w, r, err)
			return
		}

		middleware.ServeNextAuthenticated(qUser, next, w, r)
	})
}
