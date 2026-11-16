package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
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

func TestComponentLoggerJSONFieldsAndLevel(t *testing.T) {
	var output bytes.Buffer
	logger := newComponentWithWriter(&output, Options{Level: slog.LevelWarn, Format: "json"}, "client").With("tun", "mq0")
	logger.InfoContext(context.Background(), "filtered")
	logger.WarnContext(context.Background(), "reconnecting", "attempt", 3)
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one filtered JSON record, got %q", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]any{
		"level": "WARN", "msg": "reconnecting", "component": "client", "tun": "mq0", "attempt": float64(3),
	} {
		if record[name] != want {
			t.Errorf("JSON field %q: got %v want %v", name, record[name], want)
		}
	}
}

func TestRequirePreservesCallerHandler(t *testing.T) {
	var output bytes.Buffer
	explicit := newComponentWithWriter(&output, Options{Level: slog.LevelWarn, Format: "json"}, "client")
	if got := Require(explicit); got != explicit {
		t.Fatal("configured logger was replaced")
	}
	Require(explicit).InfoContext(context.Background(), "filtered")
	Require(explicit).WarnContext(context.Background(), "owned logger")
	if strings.Contains(output.String(), "filtered") || !strings.Contains(output.String(), "owned logger") ||
		!strings.Contains(output.String(), "\"component\":\"client\"") {
		t.Fatalf("injected logger's level, handler or component was bypassed: %q", output.String())
	}
}

func TestRequireRejectsMissingLogger(t *testing.T) {
	defer func() {
		msg, ok := recover().(string)
		if !ok || !strings.Contains(msg, "nil logger") {
			t.Fatalf("nil logger must fail fast, not create a second handler: %v", msg)
		}
	}()
	Require(nil)
}
