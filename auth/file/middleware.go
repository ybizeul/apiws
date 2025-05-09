package file

import (
	"errors"
	"net/http"

	"github.com/ybizeul/apiws/auth/middleware"
	"github.com/ybizeul/apiws/internal/middleware/jwt"
)

type FileMiddleware struct {
	File *File

	jwtMiddleware jwt.JWTAuthMiddleware
}

// AuthMiddleware is the middleware for the File authentication
func (a FileMiddleware) AuthMiddleware(next http.Handler) http.Handler {

	next = a.jwtMiddleware.Middleware(next)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.File == nil {
			middleware.ServeNextError(next, w, r, errors.New("no authentication backend"))
			return
		}

		// If there is no credentials, skip middleware
		var qUser string
		var ok bool

		if qUser, _, ok = r.BasicAuth(); !ok {
			next.ServeHTTP(w, r)
			return
		}

		// If authentication has been sent, check credentials

		err := a.File.authenticateRequest(nil, r)

		if err != nil {
			if errors.Is(err, ErrMissingCredentials) {
				middleware.ServeNextAuthenticated("", next, w, r)
				return
			}
			if errors.Is(err, ErrBadCredentials) {
				middleware.ServeNextError(next, w, r, ErrBadCredentials)
				return
			}
			middleware.ServeNextError(next, w, r, err)
			return
		}

		middleware.ServeNextAuthenticated(qUser, next, w, r)
	})
}
