package configfile

import (
	"strings"
	"testing"
)

type sample struct {
	Name string   `yaml:"name"`
	Routes []string `yaml:"routes"`
}

func TestYAMLOnlyRoundTrip(t *testing.T) {
	for _, path := range []string{"config.yaml", "config.yml"} {
		in := sample{Name: ":4433", Routes: []string{"192.168.20.0/24"}}
		b, err := Marshal(path, in)
		if err != nil { t.Fatal(err) }
		var got sample
		if err := Decode(path, b, &got); err != nil { t.Fatal(err) }
		if got.Name != in.Name || got.Routes[0] != in.Routes[0] { t.Fatalf("%+v", got) }
	}
}

func TestRejectLegacyJSONAndInvalidYAML(t *testing.T) {
	if err := Decode("server.json", []byte("name: x"), &sample{}); err == nil {
		t.Fatal("legacy JSON extension accepted")
	}
	if _, err := Marshal("server.json", sample{}); err == nil { t.Fatal("JSON output accepted") }
	for _, text := range []string{
		"",
		"name: x
unknown: forbidden
",
		"name: x
name: duplicate
",
		"name: first
---
name: second
",
		"name: [not-a-string]
",
	} {
		var got sample
		if err := Decode("server.yaml", []byte(text), &got); err == nil { t.Fatalf("accepted %q", text) }
	}
	out, err := Marshal("server.yaml", sample{Name: ":4433"})
	if err != nil || !strings.Contains(string(out), "4433") { t.Fatalf("%s: %v", out, err) }
}
