package app

import "golang.org/x/sys/windows/svc"

const (
	serviceName        = "gecit"
	serviceDisplayName = "gecit DPI bypass"
	serviceDescription = "Injects fake TLS ClientHello packets to desynchronize DPI middleboxes, and resolves DNS over HTTPS."
)

// underServiceManager reports whether the SCM started this process rather than
// an operator at a console. It decides where logs go and who drives shutdown.
func underServiceManager() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}
