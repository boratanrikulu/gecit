package seqtrack

// This function calculates the TTL for our own spoofed packets, based on the server's TTL which is present in the initial SYN-ACK packet.
// Some common operating system defaults are 64 for Linux/macOS, 128 for Windows, and 255 for some routers and Solaris.
// We assume the closest default >= serverTTL is the origin, then subtract one extra hop for the DPI box itself.
func CalculateFakeTTL(serverTTL uint8) uint8 {
	hops := GetOSDefaultTTL(serverTTL) - serverTTL
	if hops <= 1 {
		return 1
	}
	return hops - 1
}

func GetOSDefaultTTL(ttl uint8) uint8 {
	switch {
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default: // since uint8 guarantees <= 255...
		return 255
	}
}
