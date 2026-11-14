package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestServerHAReadinessValidatesLoopbackOnly(t *testing.T) {
	good := []string{"127.0.0.1:9090", "[::1]:9090"}
	for _, address := range good {
		cfg := ServerConfig{
			HA:        ServerHAConfig{ReadinessListen: address},
			Instances: []ServerInstance{sampleInstance("a", "vpn.example.test", "mq0")},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid local HA health listener %q rejected: %v", address, err)
		}
	}
	bad := []string{
		":9090", "0.0.0.0:9090", "[::]:9090",
		"localhost:9090", "192.0.2.1:9090", "127.0.0.1:0",
		"[::1]:65536", "[::1%lo]:9090", "127.0.0.1",
	}
	for _, address := range bad {
		cfg := ServerConfig{
			HA:        ServerHAConfig{ReadinessListen: address},
			Instances: []ServerInstance{sampleInstance("a", "vpn.example.test", "mq0")},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("unsafe/non-listening HA health %q accepted", address)
		}
	}
}

func TestServerHAReadinessRespondsOnlyWhenReady(t *testing.T) {
	var ready atomic.Bool
	handler := newServerHAHealthHandler(&ready)
	check := func(method, path string, want int) {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, nil)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != want {
			t.Fatalf("%s %s status %d, wanted %d", method, path, recorder.Code, want)
		}
		if value := recorder.Header().Get("Cache-Control"); value != "no-store" && want != http.StatusNotFound {
			t.Fatalf("missing no-store cache header on %s: %q", path, value)
		}
	}
	check("GET", "/livez", http.StatusOK)
	check("GET", "/readyz", http.StatusServiceUnavailable)
	check("POST", "/readyz", http.StatusMethodNotAllowed)
	ready.Store(true)
	check("GET", "/readyz", http.StatusOK)
	check("HEAD", "/readyz", http.StatusOK)
	check("GET", "/invalid", http.StatusNotFound)
	ready.Store(false)
	check("GET", "/readyz", http.StatusServiceUnavailable)
	check("GET", "/livez", http.StatusOK)
}

func TestServerHAReadinessLoopbackSocketLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := newServerManager(context.Background(), logger)
	defer m.close()
	m.readinessListen = "127.0.0.1:0" // runtime-only ephemeral port in test
	if err := m.startHealthListener(); err != nil {
		t.Fatal(err)
	}
	url := "http://" + m.healthListener.Addr().String() + "/readyz"
	client := &http.Client{}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unready socket status %d", resp.StatusCode)
	}
	m.ready.Store(true)
	resp, err = client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("ready socket status=%d body=%q error=%v", resp.StatusCode, body, err)
	}
}
