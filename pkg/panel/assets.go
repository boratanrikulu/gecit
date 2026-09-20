package panel

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web
var webFS embed.FS

// assets serves the page from the binary. Nothing is fetched from a CDN: a
// privacy tool must not make the operator's browser talk to a third party, and
// the panel has to work on a machine whose DNS gecit is in the middle of
// rewiring.
func (s *Server) assets() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	return http.FileServerFS(sub)
}
