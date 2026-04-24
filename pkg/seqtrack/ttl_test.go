package seqtrack

import "testing"

func TestGetOSDefaultTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  uint8
		want uint8
	}{
		// linux/macOS bucket: [0, 64]
		{"zero", 0, 64},
		{"one", 1, 64},
		{"63", 63, 64},
		{"64_boundary", 64, 64},
		// windows bucket: (64, 128]
		{"65", 65, 128},
		{"127", 127, 128},
		{"128_boundary", 128, 128},
		// solaris/router bucket: (128, 255]
		{"129", 129, 255},
		{"254", 254, 255},
		{"255_max", 255, 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetOSDefaultTTL(tt.ttl)
			if got != tt.want {
				t.Errorf("GetOSDefaultTTL(%d) = %d, want %d", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestCalculateFakeTTL(t *testing.T) {
	// hops = GetOSDefaultTTL(s) - s --->> fakeTTL = hops - 1
	// when hops <= 1, the function clamps the value to 1 (minimum TTL to be seen by DPI).
	tests := []struct {
		name      string
		serverTTL uint8
		want      uint8
	}{
		// linux/macOS origin (default 64): hops = 64 - serverTTL
		{"linux_at_origin_64", 64, 1}, // hops=0, clamp -> 1
		{"linux_1hop_63", 63, 1},      // hops=1, clamp -> 1
		{"linux_2hops_62", 62, 1},     // hops=2, hops-1=1
		{"linux_3hops_61", 61, 2},     // hops=3, hops-1=2
		{"linux_4hops_60", 60, 3},     // hops=4, hops-1=3
		{"linux_many_hops_1", 1, 62},  // hops=63, hops-1=62

		// windows origin (default 128): hops = 128 - serverTTL
		{"windows_at_origin_128", 128, 1}, // hops=0, clamp -> 1
		{"windows_1hop_127", 127, 1},      // hops=1, clamp -> 1
		{"windows_2hops_126", 126, 1},     // hops=2, hops-1=1
		{"windows_8hops_120", 120, 7},     // hops=8, hops-1=7
		{"windows_many_hops_65", 65, 62},  // hops=63, hops-1=62

		// solaris/router origin (default 255): hops = 255 - serverTTL
		{"solaris_at_origin_255", 255, 1},   // hops=0, clamp -> 1
		{"solaris_1hop_254", 254, 1},        // hops=1, clamp -> 1
		{"solaris_2hops_253", 253, 1},       // hops=2, hops-1=1
		{"solaris_5hops_250", 250, 4},       // hops=5, hops-1=4
		{"solaris_many_hops_129", 129, 125}, // hops=126, hops-1=125
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateFakeTTL(tt.serverTTL)
			if got != tt.want {
				t.Errorf("CalculateFakeTTL(%d) = %d, want %d", tt.serverTTL, got, tt.want)
			}
		})
	}
}

// this verifies the safety invariant: a fake TTL of zero would be silently dropped by the kernel
// before leaving the NIC, so the function must always return at least 1.
func TestCalculateFakeTTL_NeverZero(t *testing.T) {
	for i := 0; i <= 255; i++ {
		got := CalculateFakeTTL(uint8(i))
		if got == 0 {
			t.Errorf("CalculateFakeTTL(%d) = 0: fake TTL must never be zero", i)
		}
	}
}

// this verifies the core assumption that the returned default is always >= the input TTL.
// CalculateFakeTTL relies on this to avoid uint8 underflow in the subtraction.
func TestGetOSDefaultTTL_AlwaysGTE(t *testing.T) {
	for i := 0; i <= 255; i++ {
		ttl := uint8(i)
		def := GetOSDefaultTTL(ttl)
		if def < ttl {
			t.Errorf("GetOSDefaultTTL(%d) = %d < input: would underflow in CalculateFakeTTL", ttl, def)
		}
	}
}
