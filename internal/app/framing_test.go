package app

import "testing"

func TestFragmentFramingNegotiation(t *testing.T) {
	for _, tc := range []struct {
		reply   string
		offered bool
		enabled bool
		fails   bool
	}{
		{"", false, false, false},
		{"", true, false, false},
		{framingValue, true, true, false},
		{framingValue, false, false, true},
		{"bogus", true, false, true},
	} {
		got, err := negotiatedFraming(tc.reply, tc.offered)
		if got != tc.enabled || (err != nil) != tc.fails {
			t.Fatalf("reply=%q offered=%t: enabled=%t err=%v", tc.reply, tc.offered, got, err)
		}
	}
	if !acceptFraming(framingValue) || acceptFraming("frag-v2") || acceptFraming("") {
		t.Fatal("server accepted unsupported framing version")
	}
}
