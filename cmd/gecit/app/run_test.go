package app

import "testing"

func TestToUint16SliceRejectsInvalidPorts(t *testing.T) {
	for _, ports := range [][]int{
		{},
		{0},
		{-1},
		{70000},
		{443, 443},
	} {
		if _, err := toUint16Slice(ports); err == nil {
			t.Fatalf("toUint16Slice(%v) succeeded, want error", ports)
		}
	}
}

func TestToUint16SliceRejectsTooManyPorts(t *testing.T) {
	ports := make([]int, maxTargetPorts+1)
	for i := range ports {
		ports[i] = 1000 + i
	}
	if _, err := toUint16Slice(ports); err == nil {
		t.Fatal("too many ports succeeded, want error")
	}
}

func TestToUint16SliceValid(t *testing.T) {
	got, err := toUint16Slice([]int{443, 8443})
	if err != nil {
		t.Fatalf("toUint16Slice returned error: %v", err)
	}
	if len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("got %v, want [443 8443]", got)
	}
}
