package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/ybizeul/apiws/auth/middleware"
	"golang.org/x/oauth2"
)

var (
	ErrAuthenticationRedirect = errors.New("redirect to authenticate")
	ErrNotAuthenticated       = errors.New("Not authenticated")
)

// OIDCConfig is the configuration for the OIDC backend.
type OIDCConfig struct {
	ProviderURL    string `yaml:"provider_url"`
	ClientID       string `yaml:"client_id"`
	ClientSecret   string `yaml:"client_secret"`
	RedirectURL    string `yaml:"redirect_url"`
	LogoutURL      string `yaml:"logout_url"`
	CookieSecure   bool   `yaml:"secure"`
	CookieAuthKey  string `yaml:"cookie_auth_key"`
	CookieCryptKey string `yaml:"cookie_crypt_key"`
	SessionName    string `yaml:"session_name"`
}

// OIDC is a backend for authentication using OpenID Connect.
type OIDC struct {
	OIDCMiddleware
	config   OIDCConfig
	provider *oidc.Provider

	oauth2Config *oauth2.Config

	store sessions.Store
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewOIDC creates a new OIDC backend based on parameters in
func NewOIDC(config OIDCConfig) (*OIDC, error) {
	var err error

	result := &OIDC{
		config: config,
	}

	// Create the OIDC provider
	result.provider, err = oidc.NewProvider(context.Background(), result.config.ProviderURL)
	if err != nil {
		return nil, err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	result.oauth2Config = &oauth2.Config{
		ClientID:     result.config.ClientID,
		ClientSecret: result.config.ClientSecret,
		RedirectURL:  result.config.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: result.provider.Endpoint(),

		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email"},
	}

	result.OIDCMiddleware = OIDCMiddleware{
		OIDC: result,
	}

	cAuthKey := config.CookieAuthKey
	if cAuthKey == "" {
		cAuthKey = string(securecookie.GenerateRandomKey(32))
	}

	cCryptKey := config.CookieCryptKey
	if cCryptKey == "" {
		cCryptKey = string(securecookie.GenerateRandomKey(32))
	}

	//result.store = sessions.NewFilesystemStore("sessions", []byte(cAuthKey), []byte(cCryptKey))
	store := sessions.NewCookieStore([]byte(cAuthKey), []byte(cCryptKey))
	cbURL, err := url.Parse(result.config.RedirectURL)
	if err != nil {
		slog.Error("Unable to parse redirect URL", "error", err)
		return nil, err
	}
	if cbURL.Scheme == "http" {
		store.Options = &sessions.Options{
			Secure: false,
		}
	}
	result.store = store
	gob.Register(oauth2.Token{})
	if result.config.SessionName == "" {
		result.config.SessionName = "apiws"
	}

	return result, nil
}

func (o *OIDC) authenticateRequest(w http.ResponseWriter, r *http.Request) error {
	session, err := o.session(w, r)
	if err != nil {
		return err
	}
	token, ok := session.Values["access_token"].(oauth2.Token)
	if ok {
		t := o.OIDC.oauth2Config.TokenSource(context.Background(), &token)
		newT, err := t.Token()
		if err != nil {
			slog.Error("Unable to get token", "error", err)
			return err
		}

		if newT.AccessToken != token.AccessToken {
			newT.AccessToken = "<REDACTED>"
			session.Values["access_token"] = newT
			_ = session.Save(r, w)
		}
	}

	if session.Values["username"] == nil || session.Values["username"] == "" {
		return ErrNotAuthenticated
	}

	return nil
}

func (o *OIDC) CallbackHandler(h http.Handler) (string, http.Handler) {
	r := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifier := o.provider.Verifier(&oidc.Config{ClientID: o.config.ClientID})

		code := r.URL.Query().Get("code")

		// Check nonce and state
		session, err := o.session(w, r)
		if err != nil {
			session.Options.MaxAge = -1
			_ = session.Save(r, w)
			middleware.ServeNextError(h, w, r, err)
			return
		}

		oauth2Token, err := o.oauth2Config.Exchange(context.Background(), code, oauth2.VerifierOption(session.Values["verifier"].(string)))
		if err != nil {
			middleware.ServeNextError(h, w, r, errors.New("code verification failed"))
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
			middleware.ServeNextError(h, w, r, errors.New("token verification failed"))
			return
		}

		nonce, ok := session.Values["nonce"].(string)
		if !ok || idToken.Nonce != nonce {
			middleware.ServeNextError(h, w, r, errors.New("missing nonce"))
			return
		}

		state, ok := session.Values["state"].(string)
		if !ok || state != r.URL.Query().Get("state") {
			middleware.ServeNextError(h, w, r, errors.New("missing state"))
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
			middleware.ServeNextError(h, w, r, err)
			return
		}

		// Validate audience
		switch claims.Audience.(type) {
		case string:
			if claims.Audience != o.config.ClientID {
				middleware.ServeNextError(h, w, r, errors.New("User not authorized for application"))
				return
			}

		case []string:
			if !slices.Contains(claims.Audience.([]string), o.config.ClientID) {
				middleware.ServeNextError(h, w, r, errors.New("User not authorized for application"))
				return
			}
		}

		if claims.Username != "" {
			session.Values["username"] = claims.Username
			oauth2Token.AccessToken = "<REDACTED>"
			session.Values["access_token"] = oauth2Token
			err = session.Save(r, w)
			if err != nil {
				middleware.ServeNextError(h, w, r, err)
				return
			}
			middleware.ServeNextAuthenticated(claims.Username, h, w, r)
			return
		}

		h.ServeHTTP(w, r)
	})

	url, err := url.Parse(o.config.RedirectURL)
	if err != nil {
		slog.Error("Unable to parse redirect URL", "error", err)
		return "", nil
	}

	return url.RequestURI(), r
}

func (o *OIDC) LoginHandler() (path string, skipForm bool, h http.Handler) {
	return "/login", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := randString(16)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session, err := o.session(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["state"] = state
		session.Values["nonce"] = nonce

		if session.Values["verifier"] == nil {
			session.Values["verifier"] = oauth2.GenerateVerifier()
		}
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		url := o.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(session.Values["verifier"].(string)), oidc.Nonce(nonce))

		http.Redirect(w, r, url, http.StatusFound)
	})
}

func (o *OIDC) session(w http.ResponseWriter, r *http.Request) (*sessions.Session, error) {
	session, err := o.store.Get(r, o.config.SessionName)
	if err != nil {
		w.Header().Set("Set-Cookie", o.config.SessionName+"=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/")
		http.Redirect(w, r, "/login", http.StatusFound)
		return nil, err
	}
	return session, nil
}
