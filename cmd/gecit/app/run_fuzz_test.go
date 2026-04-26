package app

import "testing"

func FuzzToUint16Slice(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0xbb})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0x01, 0xbb})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 160 {
			data = data[:160]
		}
		ports := make([]int, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			port := int(data[i])<<8 | int(data[i+1])
			if data[i]&0x80 != 0 {
				port -= 70000
			}
			ports = append(ports, port)
		}

		got, err := toUint16Slice(ports)
		if err != nil {
			return
		}
		if len(got) == 0 || len(got) > maxTargetPorts {
			t.Fatalf("accepted invalid port count: %d", len(got))
		}
		seen := make(map[uint16]bool)
		for _, port := range got {
			if port == 0 {
				t.Fatal("accepted zero port")
			}
			if seen[port] {
				t.Fatalf("accepted duplicate port: %d", port)
			}
			seen[port] = true
		}
	})
}
