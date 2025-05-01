package apiws

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ybizeul/apiws/middleware/auth"
)

func writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIResult{Status: "error", Message: msg})
}

func writeSuccessJSON(w http.ResponseWriter, body any) {
	err := json.NewEncoder(w).Encode(body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func makeAPI(staticUI fs.FS, templateData any) *APIWS {
	api, err := New(staticUI, templateData)
	if err != nil {
		slog.Error("Error creating APIWS", slog.String("error", err.Error()))
	}

	if api == nil || api.mux == nil {
		slog.Error("New() returned nil")
	}

	return api
}
func TestSimpleAPI(t *testing.T) {
	api := makeAPI(nil, nil)

	api.AddPublicRoute("GET /", nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSuccessJSON(w, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	api.mux.ServeHTTP(w, req)

	if w.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Errorf("Unexpected response: %s", w.Body.String())
	}
}

type testAuth struct {
	Username string
	Password string
}

func (a *testAuth) AuthenticateRequest(w http.ResponseWriter, r *http.Request) error {
	username, password, ok := r.BasicAuth()
	if !ok {
		return errors.New("No basic auth")
	}
	if a.Username == username && a.Password == password {
		return nil
	}
	return errors.New("bad credentials")
}

func (o *testAuth) Callback(http.Handler) (http.Handler, string) {
	return nil, ""
}
func (o *testAuth) ShowLoginForm() bool {
	return false
}
func (o *testAuth) LoginURL() string {
	return "/"
}

func TestAuthAPI(t *testing.T) {
	authenticator := auth.BasicAuthMiddleware{
		Authentication: &testAuth{
			Username: "admin",
			Password: "password",
		},
	}

	api := makeAPI(nil, nil)

	api.AddRoute("GET /", authenticator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSuccessJSON(w, map[string]string{"status": "ok"})
	}))

	var (
		req *http.Request
		w   *httptest.ResponseRecorder
	)

	// Test with no authentication
	req = httptest.NewRequest("GET", "/", nil)

	w = httptest.NewRecorder()

	api.mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Unexpected response code: %d", w.Code)
	}

	// Test with authentication
	req = httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "password")

	w = httptest.NewRecorder()

	api.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Unexpected response code: %d", w.Code)
	}

	if w.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Errorf("Unexpected response: %s", w.Body.String())
	}
}

func TestTemplate(t *testing.T) {
	statucUI := os.DirFS("apiws_testdata")
	api := makeAPI(statucUI, struct{ Title string }{Title: "My Wonderful API"})

	var (
		req *http.Request
		w   *httptest.ResponseRecorder
	)

	// Test template on existing page
	req = httptest.NewRequest("GET", "/page.html", nil)

	w = httptest.NewRecorder()

	api.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Unexpected response code: %d", w.Code)
	}

	if w.Body.String() != "My Wonderful API" {
		t.Errorf("Unexpected response: %s", w.Body.String())
	}

	// Test template on non-existing page
	req = httptest.NewRequest("GET", "/random.html", nil)

	w = httptest.NewRecorder()

	api.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Unexpected response code: %d", w.Code)
	}

	if w.Body.String() != "index My Wonderful API" {
		t.Errorf("Unexpected response: %s", w.Body.String())
	}

	// Test template on non-html content
	req = httptest.NewRequest("GET", "/nothtml.txt", nil)

	w = httptest.NewRecorder()

	api.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Unexpected response code: %d", w.Code)
	}

	if w.Body.String() != "{{.Title}}" {
		t.Errorf("Unexpected response: %s", w.Body.String())
	}

}
