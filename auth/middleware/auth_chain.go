package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/ybizeul/apiws/auth"
)

// serveNextAuthenticated adds a passes w and r to next middleware after adding
// successful authentication context key/value
func ServeNextAuthenticated(user string, next http.Handler, w http.ResponseWriter, r *http.Request) {
	s, ok := auth.AuthForRequest(r)
	if !ok {
		s = auth.AuthStatus{}
	}
	if user != "" {
		s.User = user
	}
	s.Authenticated = true
	ctx := context.WithValue(r.Context(), auth.AuthStatusKey, s)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// serveNextError adds a passes w and r to next middleware after adding
// failed authentication context key/value
// any previously defined err is wrapped around err
func ServeNextError(next http.Handler, w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		err = errors.New("unknown error")
	}
	s, ok := auth.AuthForRequest(r)
	var c context.Context
	if ok {
		s.Error = errors.Join(s.Error, err)
		s.Authenticated = false
		s.User = ""
	} else {
		s = auth.AuthStatus{Error: err}
	}
	c = context.WithValue(r.Context(), auth.AuthStatusKey, s)
	next.ServeHTTP(w, r.WithContext(c))
}
