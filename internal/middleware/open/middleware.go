package open

import (
	"net/http"

	"github.com/ybizeul/apiws/auth/middleware"
)

type Middleware struct {
}

func (a Middleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.ServeNextAuthenticated("", next, w, r)
	})
}
