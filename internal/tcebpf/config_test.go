package tcebpf

import "testing"

func TestDefaultAndExplicitModes(t *testing.T) {
	auto, err := DefaultConfig().Normalize()
	if err != nil || !auto.Enabled() || auto.Mode != "auto" || auto.MSSClamp != "auto" || !auto.Stats || auto.Object != DefaultObject {
		t.Fatalf("default: %+v %v", auto, err)
	}
	for _, mode := range []string{"", "auto", "required"} {
		cfg, err := (Config{Mode: mode}).Normalize()
		want := mode
		if want == "" {
			want = "auto"
		}
		if err != nil || cfg.Mode != want || cfg.Object != "" || cfg.MSSClamp != "auto" {
			t.Fatalf("mode %q: %+v %v", mode, cfg, err)
		}
	}
	override, err := (Config{Object: "custom.o", MSSClamp: "auto"}).Normalize()
	if err != nil || override.Mode != "auto" || override.Object != "custom.o" {
		t.Fatalf("ELF override must not alter mode: %+v %v", override, err)
	}
	required, err := (Config{Object: "custom.o", Mode: "required"}).Normalize()
	if err != nil || required.Mode != "required" {
		t.Fatalf("explicit fail-closed TC mode: %+v %v", required, err)
	}
	off, err := (Config{Mode: "off", Object: "ignored.o", MSSClamp: "auto", Stats: true}).Normalize()
	if err != nil || off.Enabled() || off.Object != "" {
		t.Fatalf("off mode: %+v %v", off, err)
	}
	if _, err := (Config{Mode: "invalid"}).Normalize(); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestClampLimits(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		mtu     int
		v4, v6  uint16
		enabled uint32
	}{
		{"off", 1400, 0, 0, 0},
		{"auto", 1400, 1360, 1340, 1},
		{"", 1400, 1360, 1340, 1},
		{"1300", 1400, 1300, 1300, 1},
		{"1360", 1400, 1360, 1340, 1},
		{"auto", 1280, 1240, 1220, 1},
		{"auto", 1360, 1320, 1300, 1},
	} {
		got, err := EffectiveLimits(tc.mtu, tc.mode)
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		if got.MSS4 != tc.v4 || got.MSS6 != tc.v6 || got.Clamp != tc.enabled {
			t.Fatalf("%+v got %+v", tc, got)
		}
	}
}

func TestNormalizeValidatesClampWithoutExternalELF(t *testing.T) {
	for _, tc := range []Config{
		{MSSClamp: "abc"}, {MSSClamp: "-2"}, {MSSClamp: "65536"}, {MSSClamp: "250"},
		{Mode: "unsupported"},
	} {
		if _, err := tc.Normalize(); err == nil {
			t.Fatalf("invalid TC config accepted: %+v", tc)
		}
	}
	for _, tc := range []Config{
		{}, {Stats: true}, {MSSClamp: "auto"}, {MSSClamp: "1280"},
		{Object: "file.o", Stats: true}, {Mode: "required", MSSClamp: "auto"}, {Mode: "off"},
	} {
		if _, err := tc.Normalize(); err != nil {
			t.Fatalf("valid TC config rejected %+v: %v", tc, err)
		}
	}
}
