package apiws

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"

	"github.com/ybizeul/apiws/auth"

	"github.com/ybizeul/apiws/internal/middleware/confirm"
	"github.com/ybizeul/apiws/internal/middleware/open"
	logger "github.com/ybizeul/apiws/middleware/log"
	"gopkg.in/square/go-jose.v2/json"
)

// APIWS is the main structure for the API Web Server.
type APIWS struct {
	// StaticUI is the file system containing the static web directory.
	staticUI fs.FS

	// HTTP port to listen on
	httpPort int

	// mux is the main ServeMux used by the API Web Server.
	mux *http.ServeMux

	// TemplateData is used to customized some templated parts of the web UI.
	templateData any

	// Authentication is the authentication backend
	auth auth.Authentication
}

// RouteOptions contains optional arguments when adding routes
type RouteOptions struct {
	anonymousOK bool

	// Disable logging for this route. Useful for routes that are often called
	// as part of the normal behaviour of the application and would pollute the
	// logs.
	DisableLogging bool
}

// New creates a new API Web Server. staticUI is the file system containing the
// web root directory and templateData contains data for templated values
// present in static web pages.
func New(staticUI fs.FS, templateData any) (*APIWS, error) {
	var f fs.FS = nil

	if staticUI != nil {
		d, err := fs.ReadDir(staticUI, ".")
		if err != nil {
			return nil, err
		}
		f, err = fs.Sub(staticUI, d[0].Name())
		if err != nil {
			return nil, err
		}
	}

	result := &APIWS{
		staticUI:     f,
		httpPort:     8080,
		templateData: templateData,
		mux:          http.NewServeMux(),
	}

	if result.staticUI != nil {
		staticFunc := func(w http.ResponseWriter, r *http.Request) {
			relPath := r.URL.Path[1:]
			_, err := fs.Stat(result.staticUI, relPath)
			if err != nil {
				// If the file does not exists, we will return index.html
				relPath = "index.html"
			}

			// Requested URI is an actual static file
			if path.Ext(relPath) == ".html" {
				// Apply template if that's a .html file
				tmpl, err := template.New(relPath).ParseFS(result.staticUI, relPath)
				if err != nil {
					slog.Error("unable to parse template", "error", err)
				}

				err = tmpl.Execute(w, result.templateData)
				if err != nil {
					slog.Error("unable to execute template", "error", err)
				}
			} else {
				// Otherwise, return raw file
				http.ServeFileFS(w, r, result.staticUI, relPath)
			}
		}
		result.AddPublicRoute("GET /{path...}", http.HandlerFunc(staticFunc))
	}

	return result, nil
}

// WithPort sets the HTTP port to listen on.
func (a *APIWS) WithPort(port int) *APIWS {
	a.httpPort = port
	return a
}

// WithAuthentication configures the authentication backend to use. Currently
// implemented authentication are [auth.Basic], [auth.File] and [auth.OIDC].
func (a *APIWS) WithAuthentication(b auth.Authentication) *APIWS {
	a.auth = b
	return a
}

// AddRoute adds a new route to the API Web Server. handler will be called when
// pattern matches the request. arg is an optional RouteOptions struct
func (a *APIWS) AddRoute(pattern string, handler http.Handler, arg ...*RouteOptions) {
	var options *RouteOptions

	if len(arg) > 0 && arg[0] != nil {
		options = arg[0]
	} else {
		options = &RouteOptions{}
	}

	o := open.Middleware{}

	b := confirm.ConfirmMiddleware("Hupload", handler)

	if options.anonymousOK {
		b = o.Middleware(b)
	}

	//	b = j.Middleware(b)
	if a.auth != nil {
		b = a.auth.AuthMiddleware(b)
	}

	disableLogger := arg != nil && options.DisableLogging

	if !disableLogger {
		b = logger.NewLogger(b)
	}

	a.mux.Handle(pattern, b)
}

// AddRoute adds a new route to the API Web Server. The route will not be
// passed to authentication, handler will be called when
// pattern matches the request. arg is an optional RouteOptions struct
func (a *APIWS) AddPublicRoute(pattern string, handler http.Handler, arg ...*RouteOptions) {
	var options *RouteOptions

	if len(arg) > 0 && arg[0] != nil {
		options = arg[0]
	} else {
		options = &RouteOptions{}
	}

	options.anonymousOK = true

	a.AddRoute(pattern, handler, options)
}

// Start starts the API Web Server.
func (a *APIWS) Start() {
	slog.Info(fmt.Sprintf("Starting web service on port %d", a.httpPort))

	skipForm := false
	loginPath := ""

	if customLoginHandler, ok := a.auth.(auth.CustomLoginHandler); ok {
		l, skip, h := customLoginHandler.LoginHandler()
		loginPath = l
		skipForm = skip

		a.AddPublicRoute("GET "+loginPath, h, nil)
	} else {
		loginPath = "/login"
		loginHandler := a.auth.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := auth.AuthForRequest(r)
			if ok && user.Authenticated {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/error?"+r.URL.RawQuery, http.StatusFound)
		}))
		a.AddPublicRoute("POST /login", loginHandler, nil)
	}

	logoutPath := "/logout"

	if l, ok := a.auth.(auth.CustomLogout); ok {
		logoutPath = l.LogoutURL()
	}

	a.AddPublicRoute("GET /auth", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := auth.UserForRequest(r)

		response := struct {
			User          string `json:"user"`
			LoginURL      string `json:"loginUrl,omitempty"`
			LogoutURL     string `json:"logoutUrl,omitempty"`
			SkipLoginForm bool   `json:"skipLoginForm"`
		}{user, loginPath, logoutPath, skipForm}

		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			slog.Error("unable to encode json", "error", err)
		}
	}))

	// Check if we have a callback function for this authentication
	if callback, ok := a.auth.(auth.CallbackHandler); ok {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, ok := auth.AuthForRequest(r)
			if ok && s.Authenticated {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			http.Redirect(w, r, "/error?"+r.URL.RawQuery, http.StatusFound)
		})
		if p, h := callback.CallbackHandler(handler); p != "" {
			a.AddPublicRoute("GET "+p, h)
		}
	}

	err := http.ListenAndServe(fmt.Sprintf(":%d", a.httpPort), a.mux)
	if err != nil {
		slog.Error("unable to start http server", slog.String("error", err.Error()))
	}
}

// ServeHTTP serves a request passed in w and r, and can be used for integration
// tests.
func (a *APIWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}
