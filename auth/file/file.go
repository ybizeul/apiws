package file

import (
	"errors"
	"net/http"
	"os"

	"github.com/ybizeul/apiws/internal/middleware/jwt"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

var (
	ErrMissingCredentials = errors.New("no credentials provided in request")
	ErrBadCredentials     = errors.New("bad username or password")
	ErrMissingUsersFile   = errors.New("missing users file")
)

type File struct {
	FileMiddleware
	FilePath string
}

type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// NewFile returns a new File authentication
func NewFile(filePath string) (*File, error) {
	r := File{
		FilePath: filePath,
	}

	r.FileMiddleware = FileMiddleware{
		File: &r,
	}

	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrMissingUsersFile
		}
		return nil, err
	}

	r.jwtMiddleware = jwt.JWTAuthMiddleware{
		HMACSecret: os.Getenv("JWT_SECRET"),
	}

	return &r, nil
}

func (a *File) authenticateRequest(w http.ResponseWriter, r *http.Request) error {
	username, password, ok := r.BasicAuth()
	if !ok {
		return ErrMissingCredentials
	}

	// Prepare struct to load users.yaml
	var users []User

	filePath := a.FilePath

	// Fail if we can't open the file
	pf, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer pf.Close()

	// Load users.yml
	err = yaml.NewDecoder(pf).Decode(&users)
	if err != nil {
		return err
	}

	// Check if user is in the list
	for _, u := range users {
		if u.Username == username {
			// Compare password hash
			err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
			if err == nil {
				return nil
			}
		}
	}

	return ErrBadCredentials
}
