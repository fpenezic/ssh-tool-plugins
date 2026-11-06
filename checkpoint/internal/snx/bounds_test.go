package snx

import "testing"

func TestGatewayNumbers(t *testing.T) {
	for in, want := range map[int64]int{443: 443, 65535: 65535, 0: 0, -1: 0, 65536: 0, 1 << 40: 0} {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%d) = %d (want %d)", in, got, want)
		}
	}
	for in, want := range map[int64]int{1: 1, -5: -5, 1 << 31: 0, -(1 << 31) - 1: 0} {
		if got := smallInt(in); got != want {
			t.Errorf("smallInt(%d) = %d (want %d)", in, got, want)
		}
	}
}
