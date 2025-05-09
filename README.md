## Introduction

APIWS is a package to simplify creation of web servers with static web pages, (typically SPAs) and a REST API.

It's the erfect wrapper to your React app where the frontend is a set of static
web page, and the backend is a go REST server.

## Features

- Embed your web frontend into Go binary
- Add public or authenticated handlers
- Authentication includes Basic username/password, Yaml file with password
hash, or OIDC

## Project(s) using APIWS

- [Hupload](https://github.com/ybizeul/hupload)

## Example

```go
//go:embed admin-ui
var uiFS embed.FS

func NewApp() (*App, error) {
    api, err := apiws.New(uiFS, c.Values)
    if err != nil {
        return nil, err
    }

    api.WithAuthentication(basic.NewBasic("admin","secret"))

	api.AddPublicRoute("GET /status", statusHandler)

	api.AddRoute("GET /api/v1/resources", resourcesHandler)
	api.AddRoute("GET /api/v1/resources/{resource}", resourceHandler)

    api.Start()
}
```
