package apiws

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"

	"github.com/ybizeul/apiws/authentication"
	"github.com/ybizeul/apiws/middleware/auth"
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
	// Public for integration tests
	mux *http.ServeMux

	// TemplateData is used to customized some templated parts of the web UI.
	templateData any

	// Authentication is the authentication backend
	Authentication authentication.Authentication
}

// New creates a new API Web Server. staticUI is the file system containing the
// web root directory and templateData contains data for teplated values
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
		result.mux.Handle("GET /{path...}", logger.NewLogger(http.HandlerFunc(staticFunc)))
	}

	result.AddRoute("GET /auth", nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := auth.AuthForRequest(r)
		response := struct {
			User          string `json:"user"`
			ShowLoginForm bool   `json:"showLoginForm"`
			LoginURL      string `json:"loginUrl"`
		}{
			User:          user,
			ShowLoginForm: result.Authentication.ShowLoginForm(),
			LoginURL:      result.Authentication.LoginURL(),
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			slog.Error("unable to encode json", "error", err)
		}
	}), RouteOptions{AnonymousOK: true})

	return result, nil
}

func (a *APIWS) WithPort(port int) *APIWS {
	a.httpPort = port
	return a
}

// SetAuthentication
func (a *APIWS) SetAuthentication(b authentication.Authentication) {
	a.Authentication = b
}

// AddRoute adds a new route to the API Web Server. pattern is the URL pattern
// to match. authenticators is a list of Authenticator to use to authenticate
// the request. handlerFunc is the function to call when the route is matched.
func (a *APIWS) AddRoute(pattern string, authenticator auth.AuthMiddleware, handler http.Handler, args ...RouteOptions) {
	j := auth.JWTAuthMiddleware{
		HMACSecret: os.Getenv("JWT_SECRET"),
	}
	c := auth.ConfirmAuthenticator{Realm: "Hupload"}
	o := auth.OpenAuthMiddleware{}

	b := c.Middleware(handler)

	if len(args) > 0 {
		if args[0].AnonymousOK {
			b = o.Middleware(b)
		}
	}

	b = j.Middleware(b)
	if authenticator != nil {
		b = authenticator.Middleware(b)
	}

	if len(args) == 0 || (len(args) > 0 && !args[0].DisableLogging) {
		b = logger.NewLogger(b)
	}

	a.mux.Handle(pattern, b)
}

func (a *APIWS) AddPublicRoute(pattern string, authenticator auth.AuthMiddleware, handler http.Handler, args ...RouteOptions) {
	options := RouteOptions{AnonymousOK: true}
	if len(args) > 0 && args[0].DisableLogging {
		options.DisableLogging = true
	}

	a.AddRoute(pattern, authenticator, handler, options)
}

// Start starts the API Web Server.
func (a *APIWS) Start() {
	slog.Info(fmt.Sprintf("Starting web service on port %d", a.httpPort))

	// Check if we have a callback function for this authentication
	if a.Authentication != nil {
		if _, p := a.Authentication.Callback(nil); p != "" {
			// If there is, define action to redirect to "/shares"
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s, ok := r.Context().Value(authentication.AuthStatusKey).(authentication.AuthStatus)
				if ok && s.Authenticated {
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}

				http.Redirect(w, r, "/error?"+r.URL.RawQuery, http.StatusFound)
			})

			m := auth.NewJWTAuthMiddleware(os.Getenv("JWT_SECRET"))

			h, p := a.Authentication.Callback(m.Middleware(handler))

			a.mux.Handle("GET "+p, h)
		}
	}
	err := http.ListenAndServe(fmt.Sprintf(":%d", a.httpPort), a.mux)
	if err != nil {
		slog.Error("unable to start http server", slog.String("error", err.Error()))
	}
}

func (a *APIWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}
