package logging

import (
	"log/slog"
	"reflect"
	"testing"
)

func TestLevels(t *testing.T) {
	cases := map[string]slog.Level{"DEBUG": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "ERROR": slog.LevelError}
	for name, want := range cases {
		got, err := ParseLevel(name)
		if err != nil || got != want {
			t.Fatalf("%s: %v, %v", name, got, err)
		}
	}
	if _, err := ParseLevel("trace"); err == nil {
		t.Fatal("accepted invalid level")
	}
}
func TestExtract(t *testing.T) {
	t.Setenv("MQVPN_LOG_LEVEL", "")
	t.Setenv("MQVPN_LOG_FORMAT", "")
	args, opts, err := Extract([]string{"--config", "/cfg.json", "--log-level=debug", "--log-format", "json"})
	if err != nil || opts.Level != slog.LevelDebug || opts.Format != "json" {
		t.Fatalf("%+v %v", opts, err)
	}
	if !reflect.DeepEqual(args, []string{"--config", "/cfg.json"}) {
		t.Fatal(args)
	}
	if _, _, err := Extract([]string{"--log-format", "xml"}); err == nil {
		t.Fatal("accepted invalid format")
	}
}
