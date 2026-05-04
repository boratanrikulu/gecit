//go:build tools

// Anchors the gobee module in our module graph. The BPF source under
// bpf/src/ imports gobee/bpf, but that file has //go:build ignore so
// `go mod tidy` doesn't see it. The gobee transpiler resolves the
// import in this module's context, so the require has to be there.
package bpf

import (
	_ "github.com/boratanrikulu/gobee/bpf"
)
