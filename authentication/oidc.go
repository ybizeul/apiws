package authentication

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	ProviderURL  string `yaml:"provider_url"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
}

type OIDC struct {
	Options OIDCConfig

	Provider *oidc.Provider
	Config   oauth2.Config
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func NewOIDC(o OIDCConfig) (*OIDC, error) {
	var err error
	result := &OIDC{
		Options: o,
	}

	result.Provider, err = oidc.NewProvider(context.Background(), result.Options.ProviderURL)
	if err != nil {
		return nil, err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	result.Config = oauth2.Config{
		ClientID:     result.Options.ClientID,
		ClientSecret: result.Options.ClientSecret,
		RedirectURL:  result.Options.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: result.Provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return result, nil
}

func (o *OIDC) AuthenticateRequest(w http.ResponseWriter, r *http.Request) error {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return err
	}

	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	if r.URL.Path == "/login" {
		http.Redirect(w, r, o.Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
		return ErrAuthenticationRedirect
	}

	return nil
}

func (o *OIDC) Callback(h http.Handler) (http.Handler, string) {
	f := func(w http.ResponseWriter, r *http.Request) {
		var verifier = o.Provider.Verifier(&oidc.Config{ClientID: o.Options.ClientID})

		// Verify state and errors.

		oauth2Token, err := o.Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			ServeNextError(h, errors.New("code verification failed"), w, r)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(err)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			ServeNextError(h, errors.New("token verification failed"), w, r)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			ServeNextError(h, errors.New("missing nonce"), w, r)
			//http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			ServeNextError(h, errors.New("nonce doesn't match"), w, r)
			//http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		// Extract custom claims
		var claims struct {
			Email           string `json:"email"`
			Username        string `json:"preferred_username"`
			Audience        any    `json:"aud"`
			AuthorizedParty string `json:"azp"`
			Nonce           string `json:"nonce"`
		}
		if err := idToken.Claims(&claims); err != nil {
			ServeNextError(h, err, w, r)
			return
		}

		// Validate audience
		switch claims.Audience.(type) {
		case string:
			if claims.Audience != o.Options.ClientID {
				ServeNextError(h, errors.New("User not authorized for application"), w, r)
				return
			}

		case []string:
			if !slices.Contains(claims.Audience.([]string), o.Options.ClientID) {
				ServeNextError(h, errors.New("User not authorized for application"), w, r)
				return
			}
		}

		if claims.Username != "" {
			ServeNextAuthenticated(claims.Username, h, w, r)
			return
		}

		h.ServeHTTP(w, r)
	}

	hf := http.HandlerFunc(f)

	url, err := url.Parse(o.Options.RedirectURL)
	if err != nil {
		slog.Error("Unable to parse redirect URL", "error", err)
		return nil, ""
	}

	return hf, url.RequestURI()
}

func ServeNextAuthenticated(user string, next http.Handler, w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), AuthStatusKey, AuthStatus{Authenticated: true, User: user})
	next.ServeHTTP(w, r.WithContext(ctx))
}
func ServeNextError(next http.Handler, err error, w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), AuthStatusKey, AuthStatus{Authenticated: false, User: "", Error: err})
	next.ServeHTTP(w, r.WithContext(ctx))
}
func (o *OIDC) ShowLoginForm() bool {
	return false
}
func (o *OIDC) LoginURL() string {
	return "/login"
}
