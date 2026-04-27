package dns

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const breadcrumbFile = "/tmp/gecit-dns-backup"

var savedDNS string
var savedService string

func StopMDNSResponder() {
	for i := 0; i < 10; i++ {
		exec.Command("killall", "mDNSResponder").CombinedOutput()
		time.Sleep(200 * time.Millisecond)

		conn, err := net.ListenPacket("udp", "127.0.0.1:53")
		if err == nil {
			conn.Close()
			return
		}
	}
}

func ResumeMDNSResponder() {
	exec.Command("killall", "-HUP", "mDNSResponder").CombinedOutput()
}

// NetworkServiceForInterface returns the macOS network service name
// for a given interface (e.g. "en5" -> "iPhone USB").
func NetworkServiceForInterface(iface string) string {
	if iface == "" {
		return ""
	}
	out, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Device: "+iface) && i > 0 {
			return strings.TrimPrefix(strings.TrimSpace(lines[i-1]), "Hardware Port: ")
		}
	}
	return ""
}

// DetectActiveService finds the network service for the active internet interface.
func DetectActiveService() string {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "Wi-Fi"
	}
	var iface string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			break
		}
	}
	if svc := NetworkServiceForInterface(iface); svc != "" {
		return svc
	}
	return "Wi-Fi"
}

func SetSystemDNS(networkService ...string) error {
	svc := DetectActiveService()
	if len(networkService) > 0 && networkService[0] != "" {
		svc = networkService[0]
	}
	savedService = svc

	if data, err := os.ReadFile(breadcrumbFile); err == nil {
		prev := strings.TrimSpace(string(data))
		if prev != "" && prev != "127.0.0.1" {
			parts := strings.Fields(prev)
			args := append([]string{"-setdnsservers", svc}, parts...)
			exec.Command("networksetup", args...).CombinedOutput()
		}
	}

	out, err := exec.Command("networksetup", "-getdnsservers", svc).CombinedOutput()
	if err == nil {
		savedDNS = strings.TrimSpace(string(out))
		content := savedDNS
		if strings.Contains(savedDNS, "aren't any") {
			content = "empty"
		}
		os.WriteFile(breadcrumbFile, []byte(content+"\n"+svc+"\n"), 0644)
	}

	out, err = exec.Command("networksetup", "-setdnsservers", svc, "127.0.0.1").CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func RestoreSystemDNS(networkService ...string) error {
	svc := savedService
	if svc == "" {
		svc = "Wi-Fi"
	}
	if len(networkService) > 0 && networkService[0] != "" {
		svc = networkService[0]
	}

	args := []string{"-setdnsservers", svc}
	if savedDNS != "" && !strings.Contains(savedDNS, "aren't any") {
		for _, server := range strings.Fields(savedDNS) {
			args = append(args, server)
		}
	} else {
		args = append(args, "empty")
	}

	exec.Command("networksetup", args...).CombinedOutput()
	ResumeMDNSResponder()
	os.Remove(breadcrumbFile)
	return nil
}
