package fake

import "testing"

func FuzzParseSNI(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add(TLSClientHello)
	f.Add([]byte{0x16, 0x03, 0x03, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		sni := ParseSNI(data)
		if len(sni) > 65535 {
			t.Fatalf("SNI too long: %d", len(sni))
		}
	})
}
