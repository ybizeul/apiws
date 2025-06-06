package apiws

import (
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ybizeul/apiws/auth/basic"
)

// func writeError(w http.ResponseWriter, code int, msg string) {
// 	w.WriteHeader(code)
// 	_ = json.NewEncoder(w).Encode(apiResult{Status: "error", Message: msg})
// }

// func writeSuccessJSON(w http.ResponseWriter, body any) {
// 	err := json.NewEncoder(w).Encode(body)
// 	if err != nil {
// 		writeError(w, http.StatusInternalServerError, err.Error())
// 	}
// }

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

	api.AddPublicRoute("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSuccessJSON(w, map[string]string{"status": "ok"})
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	api.mux.ServeHTTP(w, req)

	if w.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Errorf("Unexpected response: %s", w.Body.String())
	}
}

// type testAuth struct {
// 	Username string
// 	Password string
// }

// func (a *testAuth) AuthenticateRequest(w http.ResponseWriter, r *http.Request) error {
// 	username, password, ok := r.BasicAuth()
// 	if !ok {
// 		return errors.New("No basic auth")
// 	}
// 	if a.Username == username && a.Password == password {
// 		return nil
// 	}
// 	return errors.New("bad credentials")
// }

// func (o *testAuth) Callback(http.Handler) (http.Handler, string) {
// 	return nil, ""
// }
// func (o *testAuth) ShowLoginForm() bool {
// 	return false
// }
// func (o *testAuth) LoginURL() string {
// 	return "/"
// }

func TestBasicAPI(t *testing.T) {
	api := makeAPI(nil, nil)
	password := "password"
	basic := basic.NewBasic("admin", &password)
	api.WithAuthentication(basic)

	api.AddRoute("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSuccessJSON(w, map[string]string{"status": "ok"})
	}), nil)

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
	staticUI := os.DirFS("apiws_testdata")
	api := makeAPI(staticUI, struct{ Title string }{Title: "My Wonderful API"})

	var (
		req *http.Request
		w   *httptest.ResponseRecorder
	)

	tests := []struct {
		Path     string
		Expected string
	}{
		{
			Path:     "/page.html",
			Expected: "My Wonderful API",
		},
		{
			Path:     "/random.html",
			Expected: "index My Wonderful API",
		},
		{
			Path:     "/nothtml.txt",
			Expected: "{{.Title}}",
		},
		{
			Path:     "/randomPath",
			Expected: "index My Wonderful API",
		},
	}
	for _, test := range tests {
		// Test template on existing page
		req = httptest.NewRequest("GET", test.Path, nil)

		w = httptest.NewRecorder()

		api.mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Unexpected response code: %d (%s)", w.Code, test.Path)
		}

		if w.Body.String() != test.Expected {
			t.Errorf("Unexpected response: %s (expected %s)", w.Body.String(), test.Expected)
		}
	}

}
