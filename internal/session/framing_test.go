package session

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
		{FramingValue, true, true, false},
		{FramingValue, false, false, true},
		{"bogus", true, false, true},
	} {
		got, err := NegotiatedFraming(tc.reply, tc.offered)
		if got != tc.enabled || (err != nil) != tc.fails {
			t.Fatalf("reply=%q offered=%t: enabled=%t err=%v", tc.reply, tc.offered, got, err)
		}
	}
	if !AcceptFraming(FramingValue) || AcceptFraming("frag-v2") || AcceptFraming("") {
		t.Fatal("server accepted unsupported framing version")
	}
}
