package auth

import (
	"net/http"
)

// Authentication must be implemented by the authentication backend
// If you want to implement your own authentication backend, you need to implement
// this interface.
type Authentication interface {
	// AuthMiddleware returns a middleware that will be used to authenticate the
	AuthMiddleware(next http.Handler) http.Handler
}

// CallbackHandler is an interface for authentications that need to
// handle a callback from an external service (like OIDC).
type CallbackHandler interface {
	// CallbackHandler returns handler associated to the pattern, of the form
	// "GET /path" or "POST /path".
	CallbackHandler(h http.Handler) (pattern string, handler http.Handler)
}

// CustomLoginHandler is an interface for authentications that needs to
// handle the login form.
type CustomLoginHandler interface {
	// LoginHandler returns handler h associated to "GET path" pattern.
	// If skipForm is true, the login form is not displayed and user redirected
	// to path
	LoginHandler() (path string, skipForm bool, h http.Handler)
}
