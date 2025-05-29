package apiws

import (
	"github.com/ybizeul/apiws/auth/basic"
	"github.com/ybizeul/apiws/auth/file"
	"github.com/ybizeul/apiws/auth/oidc"
)

func NewBasic(username string, password *string) *basic.Basic {
	return basic.NewBasic(username, password)
}

func NewFile(filePath string) (*file.File, error) {
	return file.NewFile(filePath)
}

func NewOIDC(config oidc.OIDCConfig) (*oidc.OIDC, error) {
	return oidc.NewOIDC(config)
}
