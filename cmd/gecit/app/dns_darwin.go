package app

import gecitdns "github.com/boratanrikulu/gecit/pkg/dns"

func stopSystemDNS()      { gecitdns.StopMDNSResponder() }
func resumeSystemDNS()    { gecitdns.ResumeMDNSResponder() }
func dnsServiceInfo() string { return gecitdns.DetectActiveService() }
