package fake

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
)

const (
	extServerName        = 0x0000
	extSupportedGroups   = 0x000a
	extECPointFormats    = 0x000b
	extSignatureAlgs     = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
	extPSKModes          = 0x002d
	extKeyShare          = 0x0033
)

// ClientHelloProfile describes a fake TLS fingerprint template.
type ClientHelloProfile struct {
	ServerName          string
	CipherSuites        []uint16
	SupportedGroups     []uint16
	SignatureAlgorithms []uint16
	SupportedVersions   []uint16
	ALPN                []string
	KeyShareGroup       uint16
	ExtensionOrder      []uint16
}

var clientHelloProfiles = []ClientHelloProfile{
	{
		ServerName: "www.google.com",
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303,
			0xc02b, 0xc02f, 0xcca9, 0xcca8,
			0xc02c, 0xc030, 0x009e, 0x009f,
		},
		SupportedGroups:     []uint16{0x001d, 0x0017, 0x0018},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		ALPN:                []string{"h2", "http/1.1"},
		KeyShareGroup:       0x001d,
		ExtensionOrder: []uint16{
			extServerName,
			extSupportedGroups,
			extECPointFormats,
			extSignatureAlgs,
			extALPN,
			extSupportedVersions,
			extPSKModes,
			extKeyShare,
		},
	},
	{
		ServerName: "www.cloudflare.com",
		CipherSuites: []uint16{
			0x1301, 0x1303, 0x1302,
			0xcca8, 0xcca9, 0xc02f, 0xc02b,
			0xc030, 0xc02c, 0x009f, 0x009e,
		},
		SupportedGroups:     []uint16{0x001d, 0x0017},
		SignatureAlgorithms: []uint16{0x0804, 0x0403, 0x0805, 0x0503, 0x0401, 0x0501},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		ALPN:                []string{"http/1.1", "h2"},
		KeyShareGroup:       0x001d,
		ExtensionOrder: []uint16{
			extServerName,
			extSupportedVersions,
			extSignatureAlgs,
			extSupportedGroups,
			extKeyShare,
			extALPN,
			extPSKModes,
			extECPointFormats,
		},
	},
	{
		ServerName: "www.microsoft.com",
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303,
			0xc02f, 0xc02b, 0xc030, 0xc02c,
			0x009f, 0x009e,
		},
		SupportedGroups:     []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		SignatureAlgorithms: []uint16{0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		ALPN:                []string{"h2", "http/1.1"},
		KeyShareGroup:       0x001d,
		ExtensionOrder: []uint16{
			extServerName,
			extSupportedGroups,
			extSignatureAlgs,
			extSupportedVersions,
			extKeyShare,
			extPSKModes,
			extALPN,
			extECPointFormats,
		},
	},
}

var clientHelloCounter atomic.Uint64

// tlsClientHelloDefault is the lazily-built deterministic payload for tests.
var tlsClientHelloDefault = buildClientHello(clientHelloProfiles[0], false, 1)

// TLSClientHello returns a deterministic default payload kept for tests and
// compatibility. The returned slice is a fresh copy, safe to mutate.
// Production code should use RandomTLSClientHello().
func TLSClientHello() []byte {
	out := make([]byte, len(tlsClientHelloDefault))
	copy(out, tlsClientHelloDefault)
	return out
}

// RandomTLSClientHello rotates through several fake fingerprints and varies the
// client random / session ID so each connection is less fingerprintable.
func RandomTLSClientHello() []byte {
	idx := int(clientHelloCounter.Add(1)-1) % len(clientHelloProfiles)
	return buildClientHello(clientHelloProfiles[idx], true, uint64(idx+1))
}

func buildClientHello(profile ClientHelloProfile, useCryptoRandom bool, seed uint64) []byte {
	clientRandom := make([]byte, 32)
	fillBytes(clientRandom, useCryptoRandom, seed^0x9e3779b97f4a7c15)

	sessionID := make([]byte, 32)
	fillBytes(sessionID, useCryptoRandom, seed^0xc2b2ae3d27d4eb4f)

	body := []byte{0x03, 0x03} // legacy_version = TLS 1.2
	body = append(body, clientRandom...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = appendUint16List(body, profile.CipherSuites)
	body = append(body, 0x01, 0x00) // compression methods: null only

	extensions := make([]byte, 0, 256)
	for _, extType := range profile.ExtensionOrder {
		switch extType {
		case extServerName:
			extensions = appendExtension(extensions, extType, serverNameExtension(profile.ServerName))
		case extSupportedGroups:
			extensions = appendExtension(extensions, extType, uint16Vector(profile.SupportedGroups))
		case extECPointFormats:
			extensions = appendExtension(extensions, extType, []byte{0x01, 0x00})
		case extSignatureAlgs:
			extensions = appendExtension(extensions, extType, uint16Vector(profile.SignatureAlgorithms))
		case extALPN:
			if len(profile.ALPN) > 0 {
				extensions = appendExtension(extensions, extType, alpnExtension(profile.ALPN))
			}
		case extSupportedVersions:
			extensions = appendExtension(extensions, extType, versionExtension(profile.SupportedVersions))
		case extPSKModes:
			extensions = appendExtension(extensions, extType, []byte{0x01, 0x01})
		case extKeyShare:
			keyShare := make([]byte, 32)
			fillBytes(keyShare, useCryptoRandom, seed^0x165667b19e3779f9)
			extensions = appendExtension(extensions, extType, keyShareExtension(profile.KeyShareGroup, keyShare))
		}
	}

	body = appendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{
		0x01, // ClientHello
		byte(len(body) >> 16),
		byte(len(body) >> 8),
		byte(len(body)),
	}
	handshake = append(handshake, body...)

	record := []byte{
		0x16,       // handshake
		0x03, 0x01, // TLS 1.0 record layer for compatibility
		byte(len(handshake) >> 8),
		byte(len(handshake)),
	}
	record = append(record, handshake...)
	return record
}

func fillBytes(dst []byte, useCryptoRandom bool, seed uint64) {
	if useCryptoRandom {
		if _, err := rand.Read(dst); err == nil {
			return
		}
	}

	var state uint64
	if seed == 0 {
		state = 1
	} else {
		state = seed
	}
	for i := range dst {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		dst[i] = byte(state)
	}
}

func appendUint16(dst []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(dst, buf[:]...)
}

func appendUint16List(dst []byte, values []uint16) []byte {
	dst = appendUint16(dst, uint16(len(values)*2))
	for _, v := range values {
		dst = appendUint16(dst, v)
	}
	return dst
}

func appendExtension(dst []byte, extType uint16, data []byte) []byte {
	dst = appendUint16(dst, extType)
	dst = appendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}

func uint16Vector(values []uint16) []byte {
	out := make([]byte, 0, 2+len(values)*2)
	out = appendUint16(out, uint16(len(values)*2))
	for _, v := range values {
		out = appendUint16(out, v)
	}
	return out
}

func serverNameExtension(serverName string) []byte {
	name := []byte(serverName)
	listLen := 1 + 2 + len(name)
	out := make([]byte, 0, 2+listLen)
	out = appendUint16(out, uint16(listLen))
	out = append(out, 0x00) // host_name
	out = appendUint16(out, uint16(len(name)))
	out = append(out, name...)
	return out
}

func alpnExtension(protocols []string) []byte {
	list := make([]byte, 0, 32)
	for _, proto := range protocols {
		list = append(list, byte(len(proto)))
		list = append(list, proto...)
	}

	out := make([]byte, 0, 2+len(list))
	out = appendUint16(out, uint16(len(list)))
	out = append(out, list...)
	return out
}

func versionExtension(versions []uint16) []byte {
	out := make([]byte, 0, 1+len(versions)*2)
	out = append(out, byte(len(versions)*2))
	for _, v := range versions {
		out = appendUint16(out, v)
	}
	return out
}

func keyShareExtension(group uint16, key []byte) []byte {
	entryLen := 2 + 2 + len(key)
	out := make([]byte, 0, 2+entryLen)
	out = appendUint16(out, uint16(entryLen))
	out = appendUint16(out, group)
	out = appendUint16(out, uint16(len(key)))
	out = append(out, key...)
	return out
}
