package fake

import (
	"bytes"
	"testing"
)

func TestTLSClientHello_RecordLayer(t *testing.T) {
	ch := TLSClientHello()

	if len(ch) < 5 {
		t.Fatalf("ClientHello too short: %d bytes", len(ch))
	}

	if ch[0] != 0x16 {
		t.Fatalf("record type: got 0x%02x, want 0x16 (Handshake)", ch[0])
	}

	if ch[1] != 0x03 || ch[2] != 0x01 {
		t.Fatalf("record version: got 0x%02x%02x, want 0x0301", ch[1], ch[2])
	}

	recordLen := int(ch[3])<<8 | int(ch[4])
	if recordLen != len(ch)-5 {
		t.Fatalf("record length: got %d, want %d", recordLen, len(ch)-5)
	}
}

func TestTLSClientHello_HandshakeType(t *testing.T) {
	ch := TLSClientHello()

	if ch[5] != 0x01 {
		t.Fatalf("handshake type: got 0x%02x, want 0x01 (ClientHello)", ch[5])
	}

	hsLen := int(ch[6])<<16 | int(ch[7])<<8 | int(ch[8])
	if hsLen != len(ch)-9 {
		t.Fatalf("handshake length: got %d, want %d", hsLen, len(ch)-9)
	}
}

func TestTLSClientHello_ClientVersion(t *testing.T) {
	ch := TLSClientHello()

	if ch[9] != 0x03 || ch[10] != 0x03 {
		t.Fatalf("client version: got 0x%02x%02x, want 0x0303 (TLS 1.2)", ch[9], ch[10])
	}
}

func TestTLSClientHello_SNI(t *testing.T) {
	ch := TLSClientHello()
	sni := []byte("www.google.com")

	if !bytes.Contains(ch, sni) {
		t.Fatal("ClientHello does not contain SNI \"www.google.com\"")
	}
}

func TestTLSClientHello_Deterministic(t *testing.T) {
	a := buildClientHello(clientHelloProfiles[0], false, 1)
	if !bytes.Equal(a, TLSClientHello()) {
		t.Fatal("TLSClientHello should stay deterministic")
	}
}

func TestTLSClientHello_ReturnsCopy(t *testing.T) {
	a := TLSClientHello()
	b := TLSClientHello()
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("TLSClientHello should not return empty payload")
	}
	a[0] ^= 0xff
	if a[0] == b[0] {
		t.Fatal("TLSClientHello results must not share backing memory")
	}
}

func TestRandomTLSClientHello_NotStatic(t *testing.T) {
	a := RandomTLSClientHello()
	b := RandomTLSClientHello()

	if bytes.Equal(a, b) {
		t.Fatal("randomized ClientHello should vary between calls")
	}
}

func TestRandomTLSClientHello_UsesMultipleProfiles(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < len(clientHelloProfiles)*2; i++ {
		sni := ParseSNI(RandomTLSClientHello())
		if sni == "" {
			t.Fatal("ParseSNI returned empty string for randomized ClientHello")
		}
		seen[sni] = true
	}

	if len(seen) < 2 {
		t.Fatalf("expected multiple fake fingerprints, saw %d", len(seen))
	}
}
