package fake

import "testing"

func TestParseSNI_FromOurClientHello(t *testing.T) {
	sni := ParseSNI(TLSClientHello())
	if sni != "www.google.com" {
		t.Fatalf("got %q, want %q", sni, "www.google.com")
	}
}

func TestParseSNI_Empty(t *testing.T) {
	if sni := ParseSNI(nil); sni != "" {
		t.Fatalf("nil input: got %q", sni)
	}
	if sni := ParseSNI([]byte{0x16, 0x03}); sni != "" {
		t.Fatalf("short input: got %q", sni)
	}
}

func TestParseSNI_NotTLS(t *testing.T) {
	if sni := ParseSNI([]byte("GET / HTTP/1.1\r\n")); sni != "" {
		t.Fatalf("HTTP input: got %q", sni)
	}
}
