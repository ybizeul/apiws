package auth

import (
	"net/http"
)

type AuthStatusKeyType string

var AuthStatusKey AuthStatusKeyType = "AuthStatus"

// AuthStatus contains authentication information for the current context.
type AuthStatus struct {
	Authenticated bool   // Indicates if the user is authenticated
	User          string // The authenticated user
	Error         error  // Any error that occurred during authentication
}

// UserForRequest retrieves the authenticated user from the request context and
// returns it in username. present is true if authentication informations are
// found. A value of false indicates the request has not been processed by
// authentication middleware.
func UserForRequest(r *http.Request) (username string, present bool) {
	s, ok := AuthForRequest(r)
	if !ok {
		return "", false
	}
	return s.User, true
}

// AuthForRequest retrieves the authentication status from the request context.
func AuthForRequest(r *http.Request) (AuthStatus, bool) {
	s, ok := r.Context().Value(AuthStatusKey).(AuthStatus)
	if !ok {
		return AuthStatus{}, false
	}
	return s, true
}

// // ConfirmMiddleware is a middleware that checks if the user is authenticated.
// // It must always be called after any custom authentication middleware
// // you provide. ConfirmMiddleware is already called by standard authentication
// // backends.
// func ConfirmMiddleware(realm string, mw http.Handler) http.Handler {
// 	c := confirmAuthenticator{
// 		Realm: realm,
// 	}
// 	return c.Middleware(mw)
// }
